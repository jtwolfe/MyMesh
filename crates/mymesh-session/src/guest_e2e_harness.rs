//! PR C6-m — Wave C proof: guest no roster + revoke e2e + topology authz.
//!
//! Integration harness (GUEST.md / GRANTS.md / S6 topology). No Android.
//! Uses LocalFabric + mesh/v1 tower oneshot (same patterns as join + mesh_api tests).
//!
//! Proves:
//! 1. Guest never receives full membership snapshot / topology household roster
//! 2. Grant revoke ends access (`allows` fails closed; session caps empty)
//! 3. Topology guest minimal + `grants_summary` authz (empty for guest; active-only for host)

#[cfg(test)]
mod tests {
    use crate::join::{
        handle_join_as_host_with_grants, run_join_as_guest, JoinHostOutcome,
    };
    use crate::mesh_api::{
        auth_challenge_preimage, mesh_v1_routes, AuthMethod, MeshApiState, MeshAuthStore,
    };
    use crate::mesh_sync::{
        apply_grant_revoke, build_grant_revoke, members_from_store, peer_may_mutate_grants,
        peer_receives_mesh_gossip, verify_grant_revoke,
    };
    use crate::session::Session;
    use axum::body::Body;
    use axum::http::{header, Request, StatusCode};
    use mymesh_core::{
        allows, ArmState, Capability, DeviceId, DeviceLabel, DeviceRecord, DeviceStore, GrantStore,
        IssuedBy, JoinDecision, JoinStore, MeshRole, MeshState, NodeFingerprint, Paths,
        RateLimitState, TrustState,
    };
    use mymesh_crypto::Identity;
    use mymesh_net::{LocalFabric, PeerConnection, Transport};
    use mymesh_protocol::{decode_msg, ControlMessage, Frame};
    use rand::rngs::OsRng;
    use rand::RngCore;
    use std::sync::{Arc, Mutex};
    use std::time::Duration;
    use tower::ServiceExt;

    fn tmp_paths(tag: &str) -> Paths {
        let root = std::env::temp_dir().join(format!(
            "mymesh-c6-{}-{}-{}",
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

    async fn mint_device_member_token(
        app: &axum::Router,
        mesh_id: &str,
        signer: &Identity,
        device_id: &DeviceId,
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
        let pre = auth_challenge_preimage(&cid, &nonce, mesh_id, AuthMethod::DeviceMember);
        let sig = signer.sign(&pre);
        let body = serde_json::json!({
            "challenge_id": cid,
            "method": "device_member",
            "device_id_hex": device_id.to_string(),
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
        assert_eq!(resp.status(), StatusCode::OK, "mint device_member");
        json_body(resp).await["session_token"]
            .as_str()
            .unwrap()
            .to_string()
    }

    async fn get_topology(app: &axum::Router, token: &str) -> serde_json::Value {
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/mesh/v1/topology")
                    .header(header::AUTHORIZATION, format!("Bearer {token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK, "topology");
        json_body(resp).await
    }

    /// Capture frames the host sends so we can assert no MembershipSnapshot.
    struct CaptureConn {
        inner: Box<dyn PeerConnection>,
        sent: Arc<Mutex<Vec<ControlMessage>>>,
    }

    #[async_trait::async_trait]
    impl PeerConnection for CaptureConn {
        fn peer_id(&self) -> DeviceId {
            self.inner.peer_id()
        }
        async fn send_frame(&self, frame: Frame) -> mymesh_core::Result<()> {
            if let Ok(msg) = decode_msg::<ControlMessage>(&frame.payload) {
                self.sent.lock().unwrap().push(msg);
            }
            self.inner.send_frame(frame).await
        }
        async fn recv_frame(&self) -> mymesh_core::Result<Frame> {
            self.inner.recv_frame().await
        }
        async fn close(&self) -> mymesh_core::Result<()> {
            self.inner.close().await
        }
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

    async fn accept_first_pending(join_dir: std::path::PathBuf) {
        let joins = JoinStore::open(&join_dir).unwrap();
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        loop {
            let pending = joins.list_pending().unwrap();
            if !pending.is_empty() {
                joins
                    .write_decision(&pending[0].device_id, JoinDecision::Accept)
                    .unwrap();
                break;
            }
            if tokio::time::Instant::now() > deadline {
                panic!("timeout waiting pending join");
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    /// C6 proof #1: guest join path never leaks household MembershipSnapshot / roster.
    #[tokio::test]
    async fn guest_join_never_receives_membership_snapshot_or_roster() {
        let paths_host = tmp_paths("join-host");
        let paths_guest = tmp_paths("join-guest");

        let mut host_secret = [0u8; 32];
        OsRng.fill_bytes(&mut host_secret);
        let mut guest_secret = [0u8; 32];
        OsRng.fill_bytes(&mut guest_secret);
        // Distinct fixed-ish secrets so DeviceIds are stable within the test process.
        host_secret[0] = 0xC6;
        guest_secret[0] = 0xD1;

        let id_host = Identity::from_secret_bytes(host_secret);
        let id_guest = Identity::from_secret_bytes(guest_secret);
        let host_id = id_host.device_id();
        let guest_id = id_guest.device_id();

        MeshState::new_mesh()
            .save(paths_host.mesh_file())
            .unwrap();
        let mesh = MeshState::load(paths_host.mesh_file()).unwrap();
        MeshState::new_mesh()
            .save(paths_guest.mesh_file())
            .unwrap();

        // Household members that must never appear on guest wire / store.
        let secret_a = DeviceId::from_bytes([0xAAu8; 32]);
        let secret_b = DeviceId::from_bytes([0xBBu8; 32]);
        {
            let mut store = DeviceStore::open(paths_host.devices_file()).unwrap();
            upsert_member(
                &mut store,
                secret_a,
                "household-a",
                &mesh.mesh_id,
                Capability::all(),
                MeshRole::Member,
            );
            upsert_member(
                &mut store,
                secret_b,
                "household-b",
                &mesh.mesh_id,
                Capability::all(),
                MeshRole::Member,
            );
        }

        let mut grants = GrantStore::open(paths_host.grants_file()).unwrap();
        let grant = grants
            .create_guest(
                mesh.mesh_id.clone(),
                guest_id,
                host_id,
                vec![Capability::Terminal, Capability::Files],
                None,
                IssuedBy::device(&host_id),
            )
            .unwrap();
        ArmState::arm_with_guest_grant(paths_host.arm_file(), 120, &grant.grant_id).unwrap();

        let fabric = LocalFabric::new();
        let ep_host = fabric.endpoint(host_id);
        let ep_guest = fabric.endpoint(guest_id);
        let sent = Arc::new(Mutex::new(Vec::new()));
        let sent_c = sent.clone();

        let devices_path = paths_host.devices_file();
        let grants_path = paths_host.grants_file();
        let arm_path = paths_host.arm_file();
        let join_dir = paths_host.join_dir();
        let mesh_path = paths_host.mesh_file();

        let host_fut = async move {
            let id = Identity::from_secret_bytes(host_secret);
            let conn = ep_host.accept().await.unwrap();
            let cap = CaptureConn {
                inner: conn,
                sent: sent_c,
            };
            handle_join_as_host_with_grants(
                Box::new(cap),
                &id,
                "host",
                &devices_path,
                &grants_path,
                &arm_path,
                &join_dir,
                &mesh_path,
                120,
                None,
            )
            .await
        };

        let guest_devices = paths_guest.devices_file();
        let guest_mesh = paths_guest.mesh_file();
        let guest_fut = async move {
            let id = Identity::from_secret_bytes(guest_secret);
            let mut store = DeviceStore::open(&guest_devices).unwrap();
            let conn = ep_guest.connect(host_id).await.unwrap();
            run_join_as_guest(
                conn,
                &id,
                "guest",
                &mut store,
                &guest_mesh,
                vec![Capability::Terminal, Capability::Files],
            )
            .await
            .map(|r| (r, store))
        };

        let accept_fut = accept_first_pending(paths_host.join_dir());
        let (host_res, guest_res, _) = tokio::join!(host_fut, guest_fut, accept_fut);
        assert_eq!(host_res.expect("host"), JoinHostOutcome::GuestAccepted);
        let (host_rec, store_g) = guest_res.expect("guest join");

        // Guest only knows object host as Guest bilateral.
        assert_eq!(host_rec.id, host_id);
        assert_eq!(host_rec.mesh_role, MeshRole::Guest);
        assert_eq!(store_g.list().len(), 1, "guest store must be host-only");
        assert!(!store_g.is_trusted(&secret_a));
        assert!(!store_g.is_trusted(&secret_b));

        let store_h = DeviceStore::open(paths_host.devices_file()).unwrap();
        let guest_rec = store_h.get(&guest_id).expect("guest on host");
        assert_eq!(guest_rec.mesh_role, MeshRole::Guest);
        assert!(guest_rec.capabilities.contains(&Capability::Terminal));

        // Wire: JoinAccept, never MembershipSnapshot.
        let msgs = sent.lock().unwrap().clone();
        assert!(
            msgs.iter()
                .any(|m| matches!(m, ControlMessage::JoinAccept { .. })),
            "expected JoinAccept: {msgs:?}"
        );
        assert!(
            !msgs
                .iter()
                .any(|m| matches!(m, ControlMessage::MembershipSnapshot { .. })),
            "guest must not receive MembershipSnapshot: {msgs:?}"
        );

        // Mesh-wide snapshot helpers exclude guests; guest peers get no gossip.
        let members = members_from_store(&store_h, host_id, "host");
        assert!(!members.iter().any(|m| m.id == guest_id));
        assert!(members.iter().any(|m| m.id == secret_a));
        assert!(!peer_receives_mesh_gossip(&store_h, &guest_id));
        assert!(!peer_may_mutate_grants(&store_h, &guest_id));

        let _ = std::fs::remove_dir_all(paths_host.data_dir.parent().unwrap());
        let _ = std::fs::remove_dir_all(paths_guest.data_dir.parent().unwrap());
    }

    /// C6 proof #2: active grant → session Terminal; revoke → allows fail-closed + empty caps.
    #[tokio::test]
    async fn guest_grant_revoke_session_allows_fail_closed() {
        let paths = tmp_paths("revoke-session");
        let mut host_secret = [0u8; 32];
        OsRng.fill_bytes(&mut host_secret);
        host_secret[0] = 0xC6;
        let mut guest_secret = [0u8; 32];
        OsRng.fill_bytes(&mut guest_secret);
        guest_secret[0] = 0xD2;

        let id_host = Identity::from_secret_bytes(host_secret);
        let id_guest = Identity::from_secret_bytes(guest_secret);
        let host_id = id_host.device_id();
        let guest_id = id_guest.device_id();

        MeshState::new_mesh().save(paths.mesh_file()).unwrap();
        let mesh = MeshState::load(paths.mesh_file()).unwrap();

        // Bilateral Trusted guest link (post-join state).
        {
            let mut store_h = DeviceStore::open(paths.devices_file()).unwrap();
            upsert_member(
                &mut store_h,
                guest_id,
                "guest",
                &mesh.mesh_id,
                vec![Capability::Terminal, Capability::Files],
                MeshRole::Guest,
            );
            // Household peer the guest must not session into.
            upsert_member(
                &mut store_h,
                DeviceId::from_bytes([0xEEu8; 32]),
                "other-member",
                &mesh.mesh_id,
                Capability::all(),
                MeshRole::Member,
            );
        }
        let guest_paths = tmp_paths("revoke-guest-store");
        {
            let mut store_g = DeviceStore::open(guest_paths.devices_file()).unwrap();
            upsert_member(
                &mut store_g,
                host_id,
                "host",
                &mesh.mesh_id,
                Capability::all(),
                MeshRole::Guest,
            );
        }

        let mut grants = GrantStore::open(paths.grants_file()).unwrap();
        let grant = grants
            .create_guest(
                mesh.mesh_id.clone(),
                guest_id,
                host_id,
                vec![Capability::Terminal],
                None,
                IssuedBy::device(&host_id),
            )
            .unwrap();
        let grant_id = grant.grant_id.clone();

        let store_h = DeviceStore::open(paths.devices_file()).unwrap();
        let grants = GrantStore::open(paths.grants_file()).unwrap();
        assert!(
            allows(
                &store_h,
                &grants,
                &host_id,
                &guest_id,
                &Capability::Terminal
            ),
            "active grant must allow Terminal"
        );
        assert!(
            !allows(&store_h, &grants, &host_id, &guest_id, &Capability::Files),
            "Files not on grant"
        );
        // Guest is not allowed on a non-object host even with device caps listed.
        let other = DeviceId::from_bytes([0xEEu8; 32]);
        assert!(!allows(
            &store_h,
            &grants,
            &other,
            &guest_id,
            &Capability::Terminal
        ));

        // Live session handshake accepts Terminal under active grant.
        let fabric = LocalFabric::new();
        let ep_h = fabric.endpoint(host_id);
        let ep_g = fabric.endpoint(guest_id);
        let store_g = DeviceStore::open(guest_paths.devices_file()).unwrap();
        let grants_live = GrantStore::open(paths.grants_file()).unwrap();

        let host_fut = {
            let store_h = DeviceStore::open(paths.devices_file()).unwrap();
            async move {
                let id = Identity::from_secret_bytes(host_secret);
                let conn = ep_h.accept().await.unwrap();
                Session::handshake_acceptor_with_grants(
                    conn,
                    &id,
                    "host",
                    &store_h,
                    Some(&grants_live),
                    vec![Capability::Terminal, Capability::Files],
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
                vec![Capability::Terminal, Capability::Files],
            )
            .await
        };
        let (host_sess, guest_sess) = tokio::join!(host_fut, guest_fut);
        let host_sess = host_sess.expect("host handshake with grant");
        let guest_sess = guest_sess.expect("guest handshake");
        assert!(
            host_sess.capabilities().contains(&Capability::Terminal),
            "host must accept Terminal under active grant: {:?}",
            host_sess.capabilities()
        );
        assert!(!host_sess.capabilities().contains(&Capability::Files));
        // Dialer keeps offered list; enforcement is acceptor-side.
        assert!(guest_sess.capabilities().contains(&Capability::Terminal));
        let _ = host_sess.close().await;
        let _ = guest_sess.close().await;

        // Wire GrantRevoke + apply (same path mesh_sync uses after gossip).
        let identity = Identity::from_secret_bytes(host_secret);
        let grants_for_msg = GrantStore::open(paths.grants_file()).unwrap();
        let grant_ref = grants_for_msg.get(&grant_id).unwrap().clone();
        let msg = build_grant_revoke(&identity, &mesh.mesh_id, &grant_ref);
        match &msg {
            ControlMessage::GrantRevoke {
                mesh_id,
                grant_id: gid,
                subject_device_id,
                object_device_id,
                by_id,
                ts,
                signature,
            } => {
                verify_grant_revoke(
                    mesh_id,
                    gid,
                    subject_device_id,
                    object_device_id,
                    by_id,
                    *ts,
                    signature,
                )
                .expect("GrantRevoke signature");
            }
            other => panic!("expected GrantRevoke, got {other:?}"),
        }
        let mut grants_mut = GrantStore::open(paths.grants_file()).unwrap();
        let applied = apply_grant_revoke(&mut grants_mut, &grant_id).unwrap();
        assert!(applied.revoked_at.is_some());

        // allows fails closed immediately after revoke.
        let grants = GrantStore::open(paths.grants_file()).unwrap();
        assert!(
            !allows(
                &store_h,
                &grants,
                &host_id,
                &guest_id,
                &Capability::Terminal
            ),
            "revoked grant must deny Terminal"
        );

        // New session handshake: Terminal not accepted (empty / no Terminal).
        let fabric = LocalFabric::new();
        let ep_h = fabric.endpoint(host_id);
        let ep_g = fabric.endpoint(guest_id);
        let grants_live = GrantStore::open(paths.grants_file()).unwrap();
        let store_g = DeviceStore::open(guest_paths.devices_file()).unwrap();

        let host_fut = {
            let store_h = DeviceStore::open(paths.devices_file()).unwrap();
            async move {
                let id = Identity::from_secret_bytes(host_secret);
                let conn = ep_h.accept().await.unwrap();
                Session::handshake_acceptor_with_grants(
                    conn,
                    &id,
                    "host",
                    &store_h,
                    Some(&grants_live),
                    vec![Capability::Terminal, Capability::Files],
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
                vec![Capability::Terminal, Capability::Files],
            )
            .await
        };
        let (host_sess, guest_sess) = tokio::join!(host_fut, guest_fut);
        let host_sess = host_sess.expect("handshake still completes");
        let guest_sess = guest_sess.expect("guest dialer");
        assert!(
            !host_sess.capabilities().contains(&Capability::Terminal),
            "post-revoke host must not accept Terminal: {:?}",
            host_sess.capabilities()
        );
        assert!(
            host_sess.capabilities().is_empty(),
            "post-revoke accepted caps empty: {:?}",
            host_sess.capabilities()
        );
        let _ = host_sess.close().await;
        let _ = guest_sess.close().await;

        // Idempotent re-revoke via HTTP path (host device_member).
        let app = mesh_app(paths.clone(), host_secret, "host");
        let token = mint_device_member_token(&app, &mesh.mesh_id, &id_host, &host_id).await;
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/mesh/v1/grants/{grant_id}/revoke"))
                    .header(header::AUTHORIZATION, format!("Bearer {token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert!(json_body(resp).await["revoked_at"].as_str().is_some());

        let _ = std::fs::remove_dir_all(paths.data_dir.parent().unwrap());
        let _ = std::fs::remove_dir_all(guest_paths.data_dir.parent().unwrap());
    }

    /// C6 proof #3: topology guest minimal + grants_summary authz around create/revoke.
    #[tokio::test]
    async fn topology_guest_minimal_grants_summary_authz_and_revoke() {
        let paths = tmp_paths("topo-authz");
        let mut host_secret = [0u8; 32];
        OsRng.fill_bytes(&mut host_secret);
        host_secret[0] = 0xC6;
        let mut guest_secret = [0u8; 32];
        OsRng.fill_bytes(&mut guest_secret);
        guest_secret[0] = 0xD3;
        let mut peer_secret = [0u8; 32];
        OsRng.fill_bytes(&mut peer_secret);
        peer_secret[0] = 0xE1;

        let id_host = Identity::from_secret_bytes(host_secret);
        let id_guest = Identity::from_secret_bytes(guest_secret);
        let id_peer = Identity::from_secret_bytes(peer_secret);
        let host_id = id_host.device_id();
        let guest_id = id_guest.device_id();
        let peer_id = id_peer.device_id();

        MeshState::new_mesh().save(paths.mesh_file()).unwrap();
        let mesh = MeshState::load(paths.mesh_file()).unwrap();

        {
            let mut store = DeviceStore::open(paths.devices_file()).unwrap();
            // Full household peers guest must not see.
            for (i, byte) in [0x11u8, 0x22, 0x33].into_iter().enumerate() {
                upsert_member(
                    &mut store,
                    DeviceId::from_bytes([byte; 32]),
                    &format!("household-{i}"),
                    &mesh.mesh_id,
                    Capability::all(),
                    MeshRole::Member,
                );
            }
            upsert_member(
                &mut store,
                peer_id,
                "member-no-admin",
                &mesh.mesh_id,
                Capability::default_grant(),
                MeshRole::Member,
            );
            upsert_member(
                &mut store,
                guest_id,
                "guest-phone",
                &mesh.mesh_id,
                vec![Capability::Terminal],
                MeshRole::Guest,
            );
        }

        let mut grants = GrantStore::open(paths.grants_file()).unwrap();
        let g_host = grants
            .create_guest(
                mesh.mesh_id.clone(),
                guest_id,
                host_id,
                vec![Capability::Terminal],
                None,
                IssuedBy::device(&host_id),
            )
            .unwrap();
        // Second grant where non-admin peer is object (own for that peer).
        let foreign_guest = Identity::from_secret_bytes({
            let mut s = [0u8; 32];
            OsRng.fill_bytes(&mut s);
            s[0] = 0xF0;
            s
        });
        let g_peer = grants
            .create_guest(
                mesh.mesh_id.clone(),
                foreign_guest.device_id(),
                peer_id,
                vec![Capability::Files],
                None,
                IssuedBy::device(&host_id),
            )
            .unwrap();

        let app = mesh_app(paths.clone(), host_secret, "host");

        // --- Guest topology: minimal, empty grants_summary, no household ---
        let guest_tok =
            mint_device_member_token(&app, &mesh.mesh_id, &id_guest, &guest_id).await;
        // Scope pin at session mint.
        {
            // Re-mint to inspect session body scope (token mint helper discards body).
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
            let ch = json_body(resp).await;
            let cid = ch["challenge_id"].as_str().unwrap().to_string();
            let nonce = {
                use base64::engine::general_purpose::URL_SAFE_NO_PAD;
                use base64::Engine;
                let v = URL_SAFE_NO_PAD
                    .decode(ch["nonce"].as_str().unwrap().as_bytes())
                    .unwrap();
                let mut n = [0u8; 32];
                n.copy_from_slice(&v);
                n
            };
            let pre =
                auth_challenge_preimage(&cid, &nonce, &mesh.mesh_id, AuthMethod::DeviceMember);
            let body = serde_json::json!({
                "challenge_id": cid,
                "method": "device_member",
                "device_id_hex": guest_id.to_string(),
                "sig_hex": hex::encode(id_guest.sign(&pre)),
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
            assert_eq!(resp.status(), StatusCode::OK);
            assert_eq!(json_body(resp).await["scope"], "minimal");
        }

        let topo_g = get_topology(&app, &guest_tok).await;
        assert_eq!(topo_g["auth_mode"], "device_member");
        let members = topo_g["members"].as_array().unwrap();
        let ids: Vec<String> = members
            .iter()
            .map(|m| m["device_id_hex"].as_str().unwrap().to_string())
            .collect();
        assert!(ids.contains(&guest_id.to_string()));
        assert!(ids.contains(&host_id.to_string()));
        assert_eq!(
            members.len(),
            2,
            "guest topology = self + object host only, got {ids:?}"
        );
        for byte in [0x11u8, 0x22, 0x33] {
            assert!(
                !ids.contains(&DeviceId::from_bytes([byte; 32]).to_string()),
                "guest must not see household"
            );
        }
        assert!(!ids.contains(&peer_id.to_string()));
        assert!(topo_g["grants_summary"].as_array().unwrap().is_empty());

        // --- Host topology: full members (no guest row), grants_summary active ---
        let host_tok = mint_device_member_token(&app, &mesh.mesh_id, &id_host, &host_id).await;
        let topo_h = get_topology(&app, &host_tok).await;
        let h_members = topo_h["members"].as_array().unwrap();
        let h_ids: Vec<String> = h_members
            .iter()
            .map(|m| m["device_id_hex"].as_str().unwrap().to_string())
            .collect();
        assert!(h_ids.contains(&host_id.to_string()));
        assert!(h_ids.contains(&peer_id.to_string()));
        assert!(
            !h_ids.contains(&guest_id.to_string()),
            "guests excluded from full member roster"
        );
        let summary = topo_h["grants_summary"].as_array().unwrap();
        assert_eq!(summary.len(), 2, "host sees all active grants");
        let summary_ids: Vec<&str> = summary
            .iter()
            .map(|g| g["grant_id"].as_str().unwrap())
            .collect();
        assert!(summary_ids.contains(&g_host.grant_id.as_str()));
        assert!(summary_ids.contains(&g_peer.grant_id.as_str()));

        // --- Non-admin member: only own subject/object grants ---
        let peer_tok = mint_device_member_token(&app, &mesh.mesh_id, &id_peer, &peer_id).await;
        let topo_p = get_topology(&app, &peer_tok).await;
        let p_summary = topo_p["grants_summary"].as_array().unwrap();
        assert_eq!(p_summary.len(), 1);
        assert_eq!(p_summary[0]["grant_id"], g_peer.grant_id);
        assert_ne!(p_summary[0]["grant_id"], g_host.grant_id);

        // --- HTTP revoke g_host → disappears from host summary; guest still minimal ---
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/mesh/v1/grants/{}/revoke", g_host.grant_id))
                    .header(header::AUTHORIZATION, format!("Bearer {host_tok}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let topo_h2 = get_topology(&app, &host_tok).await;
        let summary2 = topo_h2["grants_summary"].as_array().unwrap();
        assert_eq!(summary2.len(), 1, "revoked grant excluded from summary");
        assert_eq!(summary2[0]["grant_id"], g_peer.grant_id);

        // Guest still cannot full-read (scope pin + live guest).
        let topo_g2 = get_topology(&app, &guest_tok).await;
        let ids2: Vec<String> = topo_g2["members"]
            .as_array()
            .unwrap()
            .iter()
            .map(|m| m["device_id_hex"].as_str().unwrap().to_string())
            .collect();
        for byte in [0x11u8, 0x22, 0x33] {
            assert!(!ids2.contains(&DeviceId::from_bytes([byte; 32]).to_string()));
        }
        assert!(topo_g2["grants_summary"].as_array().unwrap().is_empty());

        // Guest mutate grants forbidden.
        let body = serde_json::json!({
            "subject_device_id_hex": guest_id.to_string(),
            "capabilities": ["terminal"],
        });
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/mesh/v1/grants")
                    .header(header::AUTHORIZATION, format!("Bearer {guest_tok}"))
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        let err = json_body(resp).await;
        assert!(
            err["code"] == "guest_forbidden" || err["code"] == "admin_required",
            "guest grant mutate denied: {err}"
        );

        let _ = std::fs::remove_dir_all(paths.data_dir.parent().unwrap());
    }

    /// Full Wave C exit path: guest join → session ok → topology minimal → revoke → access denied.
    #[tokio::test]
    async fn guest_lifecycle_join_session_topology_revoke_e2e() {
        let paths_host = tmp_paths("life-host");
        let paths_guest = tmp_paths("life-guest");

        let mut host_secret = [0u8; 32];
        OsRng.fill_bytes(&mut host_secret);
        host_secret[0] = 0xC6;
        let mut guest_secret = [0u8; 32];
        OsRng.fill_bytes(&mut guest_secret);
        guest_secret[0] = 0xD4;

        let id_host = Identity::from_secret_bytes(host_secret);
        let id_guest = Identity::from_secret_bytes(guest_secret);
        let host_id = id_host.device_id();
        let guest_id = id_guest.device_id();

        MeshState::new_mesh()
            .save(paths_host.mesh_file())
            .unwrap();
        let mesh = MeshState::load(paths_host.mesh_file()).unwrap();
        MeshState::new_mesh()
            .save(paths_guest.mesh_file())
            .unwrap();

        let secret_member = DeviceId::from_bytes([0x5Eu8; 32]);
        {
            let mut store = DeviceStore::open(paths_host.devices_file()).unwrap();
            upsert_member(
                &mut store,
                secret_member,
                "secret-member",
                &mesh.mesh_id,
                Capability::all(),
                MeshRole::Member,
            );
        }

        let mut grants = GrantStore::open(paths_host.grants_file()).unwrap();
        let grant = grants
            .create_guest(
                mesh.mesh_id.clone(),
                guest_id,
                host_id,
                vec![Capability::Terminal],
                None,
                IssuedBy::device(&host_id),
            )
            .unwrap();
        let grant_id = grant.grant_id.clone();
        ArmState::arm_with_guest_grant(paths_host.arm_file(), 120, &grant_id).unwrap();

        // --- Join guest ---
        let fabric = LocalFabric::new();
        let ep_host = fabric.endpoint(host_id);
        let ep_guest = fabric.endpoint(guest_id);
        let sent = Arc::new(Mutex::new(Vec::new()));
        let sent_c = sent.clone();

        let devices_path = paths_host.devices_file();
        let grants_path = paths_host.grants_file();
        let arm_path = paths_host.arm_file();
        let join_dir = paths_host.join_dir();
        let mesh_path = paths_host.mesh_file();

        let host_fut = async move {
            let id = Identity::from_secret_bytes(host_secret);
            let conn = ep_host.accept().await.unwrap();
            handle_join_as_host_with_grants(
                Box::new(CaptureConn {
                    inner: conn,
                    sent: sent_c,
                }),
                &id,
                "host",
                &devices_path,
                &grants_path,
                &arm_path,
                &join_dir,
                &mesh_path,
                120,
                None,
            )
            .await
        };
        let guest_devices = paths_guest.devices_file();
        let guest_mesh = paths_guest.mesh_file();
        let guest_fut = async move {
            let id = Identity::from_secret_bytes(guest_secret);
            let mut store = DeviceStore::open(&guest_devices).unwrap();
            let conn = ep_guest.connect(host_id).await.unwrap();
            run_join_as_guest(
                conn,
                &id,
                "guest",
                &mut store,
                &guest_mesh,
                vec![Capability::Terminal],
            )
            .await
            .map(|r| (r, store))
        };
        let accept_fut = accept_first_pending(paths_host.join_dir());
        let (host_res, guest_res, _) = tokio::join!(host_fut, guest_fut, accept_fut);
        assert_eq!(host_res.unwrap(), JoinHostOutcome::GuestAccepted);
        let (_host_rec, store_g) = guest_res.unwrap();
        assert!(!store_g.is_trusted(&secret_member));
        assert!(
            !sent
                .lock()
                .unwrap()
                .iter()
                .any(|m| matches!(m, ControlMessage::MembershipSnapshot { .. }))
        );

        // --- Session under grant ---
        let fabric = LocalFabric::new();
        let ep_h = fabric.endpoint(host_id);
        let ep_g = fabric.endpoint(guest_id);
        let grants_live = GrantStore::open(paths_host.grants_file()).unwrap();
        let store_h = DeviceStore::open(paths_host.devices_file()).unwrap();
        let store_g = DeviceStore::open(paths_guest.devices_file()).unwrap();
        assert!(allows(
            &store_h,
            &grants_live,
            &host_id,
            &guest_id,
            &Capability::Terminal
        ));

        let host_fut = {
            let store_h = DeviceStore::open(paths_host.devices_file()).unwrap();
            async move {
                let id = Identity::from_secret_bytes(host_secret);
                let conn = ep_h.accept().await.unwrap();
                Session::handshake_acceptor_with_grants(
                    conn,
                    &id,
                    "host",
                    &store_h,
                    Some(&grants_live),
                    vec![Capability::Terminal],
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
                vec![Capability::Terminal],
            )
            .await
        };
        let (hs, gs) = tokio::join!(host_fut, guest_fut);
        let hs = hs.unwrap();
        assert!(hs.capabilities().contains(&Capability::Terminal));
        let _ = hs.close().await;
        let _ = gs.unwrap().close().await;

        // --- Topology authz ---
        let app = mesh_app(paths_host.clone(), host_secret, "host");
        let guest_tok =
            mint_device_member_token(&app, &mesh.mesh_id, &id_guest, &guest_id).await;
        let topo_g = get_topology(&app, &guest_tok).await;
        let g_ids: Vec<String> = topo_g["members"]
            .as_array()
            .unwrap()
            .iter()
            .map(|m| m["device_id_hex"].as_str().unwrap().to_string())
            .collect();
        assert!(!g_ids.contains(&secret_member.to_string()));
        assert!(topo_g["grants_summary"].as_array().unwrap().is_empty());

        let host_tok = mint_device_member_token(&app, &mesh.mesh_id, &id_host, &host_id).await;
        let topo_h = get_topology(&app, &host_tok).await;
        assert!(topo_h["grants_summary"]
            .as_array()
            .unwrap()
            .iter()
            .any(|g| g["grant_id"] == grant_id));
        assert!(!topo_h["members"]
            .as_array()
            .unwrap()
            .iter()
            .any(|m| m["device_id_hex"] == guest_id.to_string()));

        // --- Revoke via mesh/v1 ---
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/mesh/v1/grants/{grant_id}/revoke"))
                    .header(header::AUTHORIZATION, format!("Bearer {host_tok}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let grants = GrantStore::open(paths_host.grants_file()).unwrap();
        let store_h = DeviceStore::open(paths_host.devices_file()).unwrap();
        assert!(!allows(
            &store_h,
            &grants,
            &host_id,
            &guest_id,
            &Capability::Terminal
        ));

        // Session post-revoke: no Terminal.
        let fabric = LocalFabric::new();
        let ep_h = fabric.endpoint(host_id);
        let ep_g = fabric.endpoint(guest_id);
        let grants_live = GrantStore::open(paths_host.grants_file()).unwrap();
        let store_g = DeviceStore::open(paths_guest.devices_file()).unwrap();
        let host_fut = {
            let store_h = DeviceStore::open(paths_host.devices_file()).unwrap();
            async move {
                let id = Identity::from_secret_bytes(host_secret);
                let conn = ep_h.accept().await.unwrap();
                Session::handshake_acceptor_with_grants(
                    conn,
                    &id,
                    "host",
                    &store_h,
                    Some(&grants_live),
                    vec![Capability::Terminal],
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
                vec![Capability::Terminal],
            )
            .await
        };
        let (hs, gs) = tokio::join!(host_fut, guest_fut);
        let hs = hs.unwrap();
        assert!(
            !hs.capabilities().contains(&Capability::Terminal),
            "post-revoke fail closed: {:?}",
            hs.capabilities()
        );
        let _ = hs.close().await;
        let _ = gs.unwrap().close().await;

        // Host topology summary no longer lists the grant.
        let topo_h2 = get_topology(&app, &host_tok).await;
        assert!(topo_h2["grants_summary"].as_array().unwrap().is_empty());
        // Guest still minimal (no household).
        let topo_g2 = get_topology(&app, &guest_tok).await;
        let g_ids2: Vec<String> = topo_g2["members"]
            .as_array()
            .unwrap()
            .iter()
            .map(|m| m["device_id_hex"].as_str().unwrap().to_string())
            .collect();
        assert!(!g_ids2.contains(&secret_member.to_string()));

        let _ = std::fs::remove_dir_all(paths_host.data_dir.parent().unwrap());
        let _ = std::fs::remove_dir_all(paths_guest.data_dir.parent().unwrap());
    }
}
