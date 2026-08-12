//! PR E6-m — Wave E proof: continuity wipe removes host secrets + facet fail-closed.
//!
//! Integration harness (THREATS.md C4 residual + C6 facet bleed; GRANTS.md S7).
//! Real LocalFabric session + mesh/v1 tower oneshot — not placeholders.
//!
//! Proves:
//! 1. Continuity materialize writes secrets under host `continuity/<pack_id>/`;
//!    wipe removes fields/pack secrets from host storage (no residual plaintext).
//! 2. Grant `identity_facet` / `location_allowlist` fail closed on empty or
//!    mismatched session context (`allows` / `allows_with` + session handshake).
//! 3. Guest session path integrates with facet constraints: constrained grant
//!    yields empty accepted caps under empty AllowContext (intentional fail-closed
//!    until Carrier presents active facet).

#[cfg(test)]
mod tests {
    use crate::mesh_api::{
        auth_challenge_preimage, mesh_v1_routes, AuthMethod, MeshApiState, MeshAuthStore,
    };
    use crate::session::Session;
    use axum::body::Body;
    use axum::http::{header, Request, StatusCode};
    use mymesh_core::{
        allows, allows_with, status_pack as continuity_status_pack, AllowContext, Capability,
        ContinuityHostStatus, DeviceId, DeviceLabel, DeviceRecord, DeviceStore, GrantStore,
        IdentityFacet, IssuedBy, MeshRole, MeshState, NodeFingerprint, Paths, RateLimitState,
        TrustState,
    };
    use mymesh_crypto::{Identity, MeshOwnerFile};
    use mymesh_net::{LocalFabric, Transport};
    use rand::rngs::OsRng;
    use rand::RngCore;
    use std::path::Path;
    use std::sync::Arc;
    use tower::ServiceExt;

    fn tmp_paths(tag: &str) -> Paths {
        let root = std::env::temp_dir().join(format!(
            "mymesh-e6-{}-{}-{}",
            tag,
            std::process::id(),
            chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0)
        ));
        let _ = std::fs::remove_dir_all(&root);
        let paths = Paths {
            config_dir: root.join("cfg"),
            data_dir: root.join("data"),
            cache_dir: root.join("cache"),
        };
        paths.ensure().unwrap();
        paths
    }

    fn mesh_app(paths: Paths, secret: [u8; 32], label: &str) -> axum::Router {
        mesh_v1_routes(MeshApiState {
            paths,
            rate_limits: Arc::new(RateLimitState::new()),
            secret,
            label: label.into(),
            auth: Arc::new(tokio::sync::Mutex::new(MeshAuthStore::default())),
        })
    }

    async fn json_body(resp: axum::response::Response) -> serde_json::Value {
        let bytes = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
            .await
            .unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }

    async fn mint_person_owner_token(
        app: &axum::Router,
        mesh_id: &str,
        signer: &Identity,
        person_id: &str,
    ) -> String {
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/mesh/v1/auth/challenge")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let ch = json_body(resp).await;
        let cid = ch["challenge_id"].as_str().unwrap().to_string();
        let nonce_b64 = ch["nonce"].as_str().unwrap();
        let nonce = {
            use base64::engine::general_purpose::URL_SAFE_NO_PAD;
            use base64::Engine;
            let v = URL_SAFE_NO_PAD.decode(nonce_b64.as_bytes()).unwrap();
            let mut n = [0u8; 32];
            n.copy_from_slice(&v);
            n
        };
        let pre = auth_challenge_preimage(&cid, &nonce, mesh_id, AuthMethod::PersonOwner);
        let sig = signer.sign(&pre);
        let body = serde_json::json!({
            "challenge_id": cid,
            "method": "person_owner",
            "person_id": person_id,
            "sig_hex": hex::encode(sig),
        });
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/mesh/v1/auth/session")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK, "mint person_owner");
        json_body(resp).await["session_token"]
            .as_str()
            .unwrap()
            .to_string()
    }

    fn upsert_member(
        store: &mut DeviceStore,
        id: DeviceId,
        label: &str,
        mesh_id: &str,
        caps: Vec<Capability>,
        role: MeshRole,
    ) {
        store
            .upsert(DeviceRecord {
                id,
                label: DeviceLabel::new(label),
                fingerprint: NodeFingerprint::from_device_id(&id).as_str().to_string(),
                capabilities: caps,
                trust: TrustState::Trusted,
                linked_at: chrono::Utc::now(),
                last_seen: None,
                endpoint_hint: None,
                mesh_id: Some(mesh_id.into()),
                aliases: vec![],
                groups: vec![],
                mesh_role: role,
            })
            .unwrap();
    }

    fn seal_for_host(host: &Identity, fields: &str, pack_id: &str) -> mymesh_crypto::SealedContinuity {
        let pk_hex = hex::encode(host.verifying_key_bytes());
        let did = host.device_id().to_string();
        mymesh_crypto::seal_continuity_pack(mymesh_crypto::SealContinuityInput {
            host_device_public_key_hex: &pk_hex,
            host_device_id_hex: &did,
            person_id: "01E6CONTPERSON0000000000000",
            facet_id: Some("personal"),
            label: "e6 hotel bag",
            fields_json: fields,
            fields_summary: vec!["profile".into(), "wifi".into()],
            pack_id: Some(pack_id),
        })
        .unwrap()
    }

    /// Walk `root` recursively; return relative paths whose raw bytes contain `needle`.
    fn paths_containing_bytes(root: &Path, needle: &[u8]) -> Vec<String> {
        let mut hits = Vec::new();
        if !root.exists() {
            return hits;
        }
        fn walk(dir: &Path, root: &Path, needle: &[u8], hits: &mut Vec<String>) {
            let Ok(rd) = std::fs::read_dir(dir) else {
                return;
            };
            for ent in rd.flatten() {
                let p = ent.path();
                if p.is_dir() {
                    walk(&p, root, needle, hits);
                } else if let Ok(bytes) = std::fs::read(&p) {
                    if bytes.windows(needle.len()).any(|w| w == needle) {
                        let rel = p
                            .strip_prefix(root)
                            .map(|r| r.display().to_string())
                            .unwrap_or_else(|_| p.display().to_string());
                        hits.push(rel);
                    }
                }
            }
        }
        walk(root, root, needle, &mut hits);
        hits
    }

    async fn session_accepted_caps(
        host_secret: [u8; 32],
        guest_secret: [u8; 32],
        host_paths: &Paths,
        guest_paths: &Paths,
        offered: Vec<Capability>,
    ) -> Vec<Capability> {
        let host_id = Identity::from_secret_bytes(host_secret).device_id();
        let guest_id = Identity::from_secret_bytes(guest_secret).device_id();
        let fabric = LocalFabric::new();
        let ep_h = fabric.endpoint(host_id);
        let ep_g = fabric.endpoint(guest_id);
        let grants_live = GrantStore::open(host_paths.grants_file()).unwrap();
        let store_g = DeviceStore::open(guest_paths.devices_file()).unwrap();
        let offered_h = offered.clone();
        let offered_g = offered;

        let host_fut = {
            let store_h = DeviceStore::open(host_paths.devices_file()).unwrap();
            async move {
                let id = Identity::from_secret_bytes(host_secret);
                let conn = ep_h.accept().await.unwrap();
                Session::handshake_acceptor_with_grants(
                    conn,
                    &id,
                    "host",
                    &store_h,
                    Some(&grants_live),
                    offered_h,
                )
                .await
            }
        };
        let guest_fut = async move {
            let id = Identity::from_secret_bytes(guest_secret);
            let conn = ep_g.connect(host_id).await.unwrap();
            Session::handshake_dialer_with_grants(
                conn,
                &id,
                "guest",
                &store_g,
                None,
                offered_g,
            )
            .await
        };
        let (host_sess, guest_sess) = tokio::join!(host_fut, guest_fut);
        let host_sess = host_sess.expect("host handshake");
        let _ = guest_sess.expect("guest handshake");
        let caps = host_sess.capabilities().to_vec();
        let _ = host_sess.close().await;
        caps
    }

    // ── 1. Continuity materialize → wipe removes secrets ───────────────────

    /// E6 proof: materialize writes host secrets; wipe removes them from storage.
    #[tokio::test]
    async fn continuity_materialize_wipe_removes_host_secrets() {
        let paths = tmp_paths("cont-wipe");
        let mut secret = [0u8; 32];
        OsRng.fill_bytes(&mut secret);
        secret[0] = 0xE6;
        let host = Identity::from_secret_bytes(secret);
        let mesh = MeshState::new_mesh();
        mesh.save(paths.mesh_file()).unwrap();

        let person = Identity::generate();
        let person_id = "01E6OWNER000000000000000000";
        MeshOwnerFile {
            mesh_id: mesh.mesh_id.clone(),
            person_id: person_id.into(),
            person_public_key_hex: hex::encode(person.verifying_key_bytes()),
            display_name: "E6 Owner".into(),
            claimed_at: chrono::Utc::now(),
            claim_ts_unix: chrono::Utc::now().timestamp(),
            claimed_from_device_id: None,
            mrk_fingerprint: "fp".into(),
            mrk_epoch: 0,
            claim_sig_hex: "00".repeat(64),
            backup_stored_at: None,
        }
        .save(paths.mesh_owner_file())
        .unwrap();

        // Unique plaintext markers that must not survive wipe on host storage.
        const SECRET_NAME: &str = "Ada-E6-Residual-Marker-7f3a";
        const SECRET_WIFI: &str = "wifi-pw-E6-DO-NOT-RETAIN-9c2b";
        let fields = format!(
            r#"{{"profile":{{"name":"{SECRET_NAME}"}},"wifi":{{"password":"{SECRET_WIFI}"}}}}"#
        );
        let pack_id = "01E6TESTPACK000000000000000";
        let sealed = seal_for_host(&host, &fields, pack_id);

        let app = mesh_app(paths.clone(), secret, "host");
        let token = mint_person_owner_token(&app, &mesh.mesh_id, &person, person_id).await;

        // Status absent before materialize.
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(format!("/mesh/v1/continuity/status?pack_id={pack_id}"))
                    .header(header::AUTHORIZATION, format!("Bearer {token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(json_body(resp).await["status"], "absent");

        // Materialize via mesh/v1.
        let body = serde_json::to_string(&sealed.pack).unwrap();
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/mesh/v1/continuity/materialize")
                    .header(header::AUTHORIZATION, format!("Bearer {token}"))
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK, "materialize");
        let mat = json_body(resp).await;
        assert_eq!(mat["status"], "present");
        assert_eq!(mat["pack_id"], pack_id);

        let pack_dir = paths.continuity_pack_dir(pack_id);
        let fields_path = pack_dir.join("fields.json");
        let pack_json_path = pack_dir.join("pack.json");
        let state_path = pack_dir.join("state.json");

        assert!(fields_path.exists(), "fields.json present after materialize");
        assert!(pack_json_path.exists(), "pack.json present after materialize");
        assert!(state_path.exists(), "state.json present after materialize");
        let fields_on_disk = std::fs::read(&fields_path).unwrap();
        assert_eq!(fields_on_disk, fields.as_bytes());
        assert!(
            !paths_containing_bytes(&paths.data_dir, SECRET_NAME.as_bytes()).is_empty(),
            "secret name must be on host storage while present"
        );
        assert!(
            !paths_containing_bytes(&paths.data_dir, SECRET_WIFI.as_bytes()).is_empty(),
            "wifi secret must be on host storage while present"
        );
        assert_eq!(
            continuity_status_pack(&paths, pack_id).unwrap(),
            ContinuityHostStatus::Present
        );

        // Bad wipe_token must not remove secrets (fail closed).
        let bad = serde_json::json!({
            "pack_id": pack_id,
            "wipe_token": "ff".repeat(32),
        });
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/mesh/v1/continuity/wipe")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(bad.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        assert!(fields_path.exists(), "bad wipe must leave fields.json");
        assert!(
            !paths_containing_bytes(&paths.data_dir, SECRET_NAME.as_bytes()).is_empty(),
            "bad wipe must not scrub secrets"
        );

        // Valid wipe_token (no session required).
        let wipe_body = serde_json::json!({
            "pack_id": pack_id,
            "wipe_token": sealed.wipe_token_hex(),
        });
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/mesh/v1/continuity/wipe")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(wipe_body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(json_body(resp).await["status"], "wiped");

        // Secrets gone from host storage.
        assert!(!fields_path.exists(), "wipe must unlink fields.json");
        assert!(!pack_json_path.exists(), "wipe must unlink pack.json");
        assert!(state_path.exists(), "wiped marker state.json remains");
        assert_eq!(
            continuity_status_pack(&paths, pack_id).unwrap(),
            ContinuityHostStatus::Wiped
        );

        let residual_name = paths_containing_bytes(&paths.data_dir, SECRET_NAME.as_bytes());
        let residual_wifi = paths_containing_bytes(&paths.data_dir, SECRET_WIFI.as_bytes());
        assert!(
            residual_name.is_empty(),
            "plaintext name must not remain under data_dir after wipe: {residual_name:?}"
        );
        assert!(
            residual_wifi.is_empty(),
            "wifi password must not remain under data_dir after wipe: {residual_wifi:?}"
        );
        // Also scan full temp root (config/cache) for belt-and-suspenders.
        let root = paths.data_dir.parent().unwrap();
        assert!(
            paths_containing_bytes(root, SECRET_NAME.as_bytes()).is_empty(),
            "secret must not leak outside continuity fields into host root"
        );
        assert!(
            paths_containing_bytes(root, SECRET_WIFI.as_bytes()).is_empty(),
            "wifi secret must not leak into host root"
        );

        // state.json must not embed fields payload.
        let state_raw = std::fs::read_to_string(&state_path).unwrap();
        assert!(!state_raw.contains(SECRET_NAME));
        assert!(!state_raw.contains(SECRET_WIFI));
        assert!(state_raw.contains("\"status\": \"wiped\"") || state_raw.contains("\"status\":\"wiped\""));

        // Status HTTP reports wiped.
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(format!("/mesh/v1/continuity/status?pack_id={pack_id}"))
                    .header(header::AUTHORIZATION, format!("Bearer {token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(json_body(resp).await["status"], "wiped");

        // Idempotent second wipe stays wiped / secrets still absent.
        let wipe_body = serde_json::json!({
            "pack_id": pack_id,
            "wipe_token": sealed.wipe_token_hex(),
        });
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/mesh/v1/continuity/wipe")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(wipe_body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert!(!fields_path.exists());
        assert!(
            paths_containing_bytes(&paths.data_dir, SECRET_NAME.as_bytes()).is_empty()
        );

        let _ = std::fs::remove_dir_all(paths.data_dir.parent().unwrap());
    }

    // ── 2–3. Facet / location fail-closed + guest session integration ──────

    fn setup_guest_pair(
        tag: &str,
    ) -> (
        Paths,
        Paths,
        [u8; 32],
        [u8; 32],
        DeviceId,
        DeviceId,
        String,
    ) {
        let host_paths = tmp_paths(&format!("{tag}-host"));
        let guest_paths = tmp_paths(&format!("{tag}-guest"));
        let mut host_secret = [0u8; 32];
        OsRng.fill_bytes(&mut host_secret);
        host_secret[0] = 0xE6;
        let mut guest_secret = [0u8; 32];
        OsRng.fill_bytes(&mut guest_secret);
        guest_secret[0] = 0xF2;
        // Distinguish secrets across tests via tag byte.
        host_secret[1] = tag.as_bytes().first().copied().unwrap_or(0);
        guest_secret[1] = tag.as_bytes().get(1).copied().unwrap_or(1);

        let host_id = Identity::from_secret_bytes(host_secret).device_id();
        let guest_id = Identity::from_secret_bytes(guest_secret).device_id();
        MeshState::new_mesh().save(host_paths.mesh_file()).unwrap();
        let mesh_id = MeshState::load(host_paths.mesh_file()).unwrap().mesh_id;

        {
            let mut store_h = DeviceStore::open(host_paths.devices_file()).unwrap();
            upsert_member(
                &mut store_h,
                guest_id,
                "guest",
                &mesh_id,
                vec![Capability::Terminal, Capability::Files],
                MeshRole::Guest,
            );
        }
        {
            let mut store_g = DeviceStore::open(guest_paths.devices_file()).unwrap();
            upsert_member(
                &mut store_g,
                host_id,
                "host",
                &mesh_id,
                Capability::all(),
                MeshRole::Guest,
            );
        }

        (
            host_paths,
            guest_paths,
            host_secret,
            guest_secret,
            host_id,
            guest_id,
            mesh_id,
        )
    }

    /// E6 proof: identity_facet on grant fails closed without matching context;
    /// session handshake (empty AllowContext) denies Terminal; matching allows_with ok.
    #[tokio::test]
    async fn guest_identity_facet_fail_closed_session_and_allows() {
        let (host_paths, guest_paths, host_secret, guest_secret, host_id, guest_id, mesh_id) =
            setup_guest_pair("facet");

        let mut grants = GrantStore::open(host_paths.grants_file()).unwrap();
        let mut g = grants
            .create_guest(
                mesh_id,
                guest_id,
                host_id,
                vec![Capability::Terminal],
                None,
                IssuedBy::device(&host_id),
            )
            .unwrap();
        g.constraints.identity_facet = Some(IdentityFacet::Work);
        grants.upsert(g).unwrap();

        let store_h = DeviceStore::open(host_paths.devices_file()).unwrap();
        let grants = GrantStore::open(host_paths.grants_file()).unwrap();

        // Empty context (session path) → deny
        assert!(
            !allows(
                &store_h,
                &grants,
                &host_id,
                &guest_id,
                &Capability::Terminal
            ),
            "identity_facet=work must fail closed without context"
        );
        assert!(!allows_with(
            &store_h,
            &grants,
            &host_id,
            &guest_id,
            &Capability::Terminal,
            &AllowContext::default(),
        ));
        // Wrong facet → deny
        assert!(!allows_with(
            &store_h,
            &grants,
            &host_id,
            &guest_id,
            &Capability::Terminal,
            &AllowContext::new().with_facet(IdentityFacet::Personal),
        ));
        // Matching facet → allow
        assert!(allows_with(
            &store_h,
            &grants,
            &host_id,
            &guest_id,
            &Capability::Terminal,
            &AllowContext::new().with_facet(IdentityFacet::Work),
        ));

        // Live session: acceptor uses empty AllowContext → Terminal not accepted.
        let caps = session_accepted_caps(
            host_secret,
            guest_secret,
            &host_paths,
            &guest_paths,
            vec![Capability::Terminal, Capability::Files],
        )
        .await;
        assert!(
            !caps.contains(&Capability::Terminal),
            "session must fail closed for facet-constrained grant: {caps:?}"
        );
        assert!(!caps.contains(&Capability::Files));

        let _ = std::fs::remove_dir_all(host_paths.data_dir.parent().unwrap());
        let _ = std::fs::remove_dir_all(guest_paths.data_dir.parent().unwrap());
    }

    /// E6 proof: location_allowlist fail-closed (missing/mismatch/empty list) + session.
    #[tokio::test]
    async fn guest_location_allowlist_fail_closed_session_and_allows() {
        let (host_paths, guest_paths, host_secret, guest_secret, host_id, guest_id, mesh_id) =
            setup_guest_pair("loc");

        let mut grants = GrantStore::open(host_paths.grants_file()).unwrap();
        let mut g = grants
            .create_guest(
                mesh_id.clone(),
                guest_id,
                host_id,
                vec![Capability::Terminal],
                None,
                IssuedBy::device(&host_id),
            )
            .unwrap();
        g.constraints.location_allowlist = Some(vec!["home".into(), "lab".into()]);
        grants.upsert(g).unwrap();

        let store_h = DeviceStore::open(host_paths.devices_file()).unwrap();
        let grants = GrantStore::open(host_paths.grants_file()).unwrap();

        assert!(!allows(
            &store_h,
            &grants,
            &host_id,
            &guest_id,
            &Capability::Terminal
        ));
        assert!(!allows_with(
            &store_h,
            &grants,
            &host_id,
            &guest_id,
            &Capability::Terminal,
            &AllowContext::new().with_location("hotel"),
        ));
        assert!(allows_with(
            &store_h,
            &grants,
            &host_id,
            &guest_id,
            &Capability::Terminal,
            &AllowContext::new().with_location("lab"),
        ));

        let caps = session_accepted_caps(
            host_secret,
            guest_secret,
            &host_paths,
            &guest_paths,
            vec![Capability::Terminal],
        )
        .await;
        assert!(
            !caps.contains(&Capability::Terminal),
            "location-constrained grant must fail closed on session: {caps:?}"
        );

        // Empty allowlist denies all locations.
        let mut grants = GrantStore::open(host_paths.grants_file()).unwrap();
        // Mutate existing grant to empty allowlist (denies all locations).
        let mut g = grants.list().into_iter().next().unwrap().clone();
        g.constraints.location_allowlist = Some(vec![]);
        g.constraints.identity_facet = None;
        grants.upsert(g).unwrap();
        let grants = GrantStore::open(host_paths.grants_file()).unwrap();
        assert!(!allows_with(
            &store_h,
            &grants,
            &host_id,
            &guest_id,
            &Capability::Terminal,
            &AllowContext::new().with_location("home"),
        ));

        let _ = mesh_id;
        let _ = std::fs::remove_dir_all(host_paths.data_dir.parent().unwrap());
        let _ = std::fs::remove_dir_all(guest_paths.data_dir.parent().unwrap());
    }

    /// E6 proof: unconstrained guest grant sessions Terminal; adding facet+location
    /// constraints then fails closed on the same guest/host pair.
    #[tokio::test]
    async fn guest_facet_location_constraints_integration() {
        let (host_paths, guest_paths, host_secret, guest_secret, host_id, guest_id, mesh_id) =
            setup_guest_pair("integ");

        // 1) Unconstrained grant → session accepts Terminal.
        {
            let mut grants = GrantStore::open(host_paths.grants_file()).unwrap();
            grants
                .create_guest(
                    mesh_id.clone(),
                    guest_id,
                    host_id,
                    vec![Capability::Terminal],
                    None,
                    IssuedBy::device(&host_id),
                )
                .unwrap();
        }
        let store_h = DeviceStore::open(host_paths.devices_file()).unwrap();
        let grants = GrantStore::open(host_paths.grants_file()).unwrap();
        assert!(allows(
            &store_h,
            &grants,
            &host_id,
            &guest_id,
            &Capability::Terminal
        ));

        let caps = session_accepted_caps(
            host_secret,
            guest_secret,
            &host_paths,
            &guest_paths,
            vec![Capability::Terminal, Capability::Files],
        )
        .await;
        assert!(
            caps.contains(&Capability::Terminal),
            "unconstrained grant must accept Terminal: {caps:?}"
        );
        assert!(!caps.contains(&Capability::Files));

        // 2) Tighten grant with both facet + location → fail closed until full context.
        {
            let mut grants = GrantStore::open(host_paths.grants_file()).unwrap();
            let mut g = grants.list().into_iter().next().unwrap().clone();
            g.constraints.identity_facet = Some(IdentityFacet::Personal);
            g.constraints.location_allowlist = Some(vec!["office".into()]);
            grants.upsert(g).unwrap();
        }
        let grants = GrantStore::open(host_paths.grants_file()).unwrap();
        assert!(
            !allows(
                &store_h,
                &grants,
                &host_id,
                &guest_id,
                &Capability::Terminal
            ),
            "constrained grant denies empty context"
        );
        // Partial context still denies.
        assert!(!allows_with(
            &store_h,
            &grants,
            &host_id,
            &guest_id,
            &Capability::Terminal,
            &AllowContext::new().with_facet(IdentityFacet::Personal),
        ));
        assert!(!allows_with(
            &store_h,
            &grants,
            &host_id,
            &guest_id,
            &Capability::Terminal,
            &AllowContext::new().with_location("office"),
        ));
        // Full match allows.
        assert!(allows_with(
            &store_h,
            &grants,
            &host_id,
            &guest_id,
            &Capability::Terminal,
            &AllowContext::new()
                .with_facet(IdentityFacet::Personal)
                .with_location("office"),
        ));

        // Session still empty-context → no Terminal.
        let caps = session_accepted_caps(
            host_secret,
            guest_secret,
            &host_paths,
            &guest_paths,
            vec![Capability::Terminal],
        )
        .await;
        assert!(
            !caps.contains(&Capability::Terminal),
            "after constraints, session must fail closed: {caps:?}"
        );

        let _ = std::fs::remove_dir_all(host_paths.data_dir.parent().unwrap());
        let _ = std::fs::remove_dir_all(guest_paths.data_dir.parent().unwrap());
    }
}
