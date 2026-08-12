//! PR A7 — two-agent harness: dual arm → join → confirm accept → both Trusted.
//!
//! No Android / no carrier HTTP. Uses LocalFabric (same-process peer transport)
//! so CI can gate the Wave A confirm-on-machine path without real iroh endpoints.
//!
//! Flow (PAIR-V2.md dual-scan + confirm):
//! 1. Resident A: arm join window + `PairSessionStore::arm_new` (pair dual)
//! 2. Agent A accepts on LocalFabric
//! 3. Joiner B dials + `run_join_as_guest` (pair dual --join)
//! 4. Test helper computes accept confirm code (phone-local HMAC stand-in)
//! 5. `apply_pair_confirm` on A (CLI confirm)
//! 6. Host join loop `take_decision` → JoinAccept + membership
//! 7. Both DeviceStores show mutual TrustState::Trusted

#[cfg(test)]
mod tests {
    use crate::{handle_join_as_host, run_join_as_guest, Agent};
    use mymesh_core::{
        apply_pair_confirm, compute_confirm_codes, ArmState, Capability, Config, DeviceStore,
        JoinStore, MeshState, PairEndpointClass, PairPhase, PairSessionStore, Paths, TrustState,
    };
    use mymesh_crypto::Identity;
    use mymesh_net::{LocalFabric, Transport};
    use std::path::PathBuf;
    use std::time::Duration;

    fn tmp_paths(tag: &str) -> Paths {
        let root = std::env::temp_dir().join(format!(
            "mymesh-a7-{}-{}-{}",
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
        // sandbox root under temp so Agent::from_paths PathSandbox is isolated
        std::fs::create_dir_all(root.join("sandbox")).unwrap();
        paths
    }

    fn test_config(label: &str, sandbox: PathBuf) -> Config {
        Config {
            device_label: label.into(),
            sandbox_root: Some(sandbox),
            magic: mymesh_core::MagicConfig {
                enabled: false,
                ..Default::default()
            },
            limits: mymesh_core::Limits {
                arm_timeout_secs: 120,
                ..Default::default()
            },
            ..Config::default()
        }
    }

    /// Full dual-scan + confirm-on-machine path over LocalFabric.
    #[tokio::test]
    async fn two_agent_dual_confirm_accept_both_trusted() {
        let paths_a = tmp_paths("resident");
        let paths_b = tmp_paths("joiner");
        let sandbox_a = paths_a.data_dir.parent().unwrap().join("sandbox");
        let sandbox_b = paths_b.data_dir.parent().unwrap().join("sandbox");

        let id_a = Identity::generate();
        let id_b = Identity::generate();
        let cfg_a = test_config("agent-a", sandbox_a);
        let cfg_b = test_config("agent-b", sandbox_b);

        // Resident mesh + arm (pair dual)
        MeshState::new_mesh()
            .save(paths_a.mesh_file())
            .expect("mesh A");
        ArmState::arm(paths_a.arm_file(), 120).expect("arm");
        let pair_store = PairSessionStore::open(paths_a.pair_sessions_dir()).expect("pair store");
        let mesh = MeshState::load(paths_a.mesh_file()).unwrap();
        let armed = pair_store
            .arm_new(
                mesh.mesh_id.clone(),
                id_a.device_id(),
                120,
                PairEndpointClass::Confirm,
            )
            .expect("arm_new");
        assert_eq!(armed.session.phase, PairPhase::Armed);
        assert_eq!(armed.session.nonce.len(), 16);
        assert_eq!(armed.token_raw.len(), 32);

        // Host agent accept loop on LocalFabric
        let fabric = LocalFabric::new();
        let agent = Agent::from_paths(&id_a, &paths_a, cfg_a).expect("agent A");
        let ep_a = fabric.endpoint(id_a.device_id());
        let agent_task = tokio::spawn(async move {
            let _ = agent.run(&ep_a).await;
        });

        // Give accept loop a moment to register
        tokio::time::sleep(Duration::from_millis(20)).await;

        // Joiner dials + JoinRequest (must be spawned — futures are lazy)
        let join_task = {
            let ep_b = fabric.endpoint(id_b.device_id());
            let secret_b = id_b.to_secret_bytes();
            let peer_a = id_a.device_id();
            let label = cfg_b.device_label.clone();
            let mesh_path = paths_b.mesh_file();
            let devices_b = paths_b.devices_file();
            tokio::spawn(async move {
                let id_b = Identity::from_secret_bytes(secret_b);
                let mut store_b = DeviceStore::open(devices_b).expect("store B");
                let conn = ep_b.connect(peer_a).await.expect("connect to A");
                run_join_as_guest(
                    conn,
                    &id_b,
                    &label,
                    &mut store_b,
                    &mesh_path,
                    Capability::all(),
                )
                .await
                .map(|rec| (rec, store_b))
            })
        };

        // Wait for pending JoinRequest on A (bind happens in handle_join_as_host)
        let joins = JoinStore::open(paths_a.join_dir()).expect("join store");
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        loop {
            let pending = joins.list_pending().expect("list pending");
            if !pending.is_empty() {
                assert_eq!(pending.len(), 1);
                assert_eq!(pending[0].device_id, id_b.device_id());
                break;
            }
            if tokio::time::Instant::now() > deadline {
                panic!("timeout waiting for pending join on resident");
            }
            tokio::time::sleep(Duration::from_millis(30)).await;
        }

        // Session should be bound (or still armed if bind races; confirm handles both)
        let sess = pair_store
            .load(&armed.session.sid)
            .expect("load sess")
            .expect("sess exists");
        assert!(
            matches!(sess.phase, PairPhase::Bound | PairPhase::Armed),
            "expected armed|bound, got {}",
            sess.phase.as_str()
        );

        // Phone stand-in: compute accept confirm code from token + nonce + identities
        let codes = compute_confirm_codes(
            &armed.token_raw,
            &armed.session.sid,
            &id_b.device_id().to_string(),
            &id_a.device_id().to_string(),
            &armed.session.nonce,
        );
        assert!(
            codes.accept.contains('-'),
            "display form 4-4: {}",
            codes.accept
        );

        // CLI: mymesh pair confirm <code>
        let applied = apply_pair_confirm(
            &pair_store,
            &joins,
            &codes.accept,
            Some(&armed.session.sid),
            None,
        )
        .expect("apply_pair_confirm accept");
        assert!(matches!(
            applied.decision,
            mymesh_core::JoinDecision::Accept
        ));
        assert_eq!(applied.joiner, id_b.device_id());
        assert_eq!(applied.session.phase, PairPhase::Decided);
        assert!(applied.session.confirm_consumed);

        // Join completes: B gets JoinAccept + membership; A upserts Trusted
        let (host_rec, store_b) = tokio::time::timeout(Duration::from_secs(10), join_task)
            .await
            .expect("join timed out")
            .expect("join task join")
            .expect("join guest failed");
        assert_eq!(host_rec.id, id_a.device_id());
        assert_eq!(host_rec.trust, TrustState::Trusted);
        assert!(
            store_b.is_trusted(&id_a.device_id()),
            "joiner DeviceStore must trust resident"
        );

        // Host DeviceStore: joiner Trusted
        // (host loop may still be flushing; poll briefly)
        let host_deadline = tokio::time::Instant::now() + Duration::from_secs(3);
        loop {
            let store_a = DeviceStore::open(paths_a.devices_file()).expect("store A");
            if store_a.is_trusted(&id_b.device_id()) {
                break;
            }
            if tokio::time::Instant::now() > host_deadline {
                panic!("host DeviceStore never marked joiner Trusted");
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }

        agent_task.abort();
        let _ = agent_task.await;

        // cleanup
        let _ = std::fs::remove_dir_all(paths_a.data_dir.parent().unwrap());
        let _ = std::fs::remove_dir_all(paths_b.data_dir.parent().unwrap());
    }

    /// Deny confirm code → joiner not Trusted; join fails closed.
    #[tokio::test]
    async fn two_agent_dual_confirm_deny_not_trusted() {
        let paths_a = tmp_paths("deny-a");
        let paths_b = tmp_paths("deny-b");
        let sandbox_a = paths_a.data_dir.parent().unwrap().join("sandbox");
        let sandbox_b = paths_b.data_dir.parent().unwrap().join("sandbox");

        let id_a = Identity::generate();
        let id_b = Identity::generate();
        let cfg_a = test_config("agent-a", sandbox_a);
        let cfg_b = test_config("agent-b", sandbox_b);

        MeshState::new_mesh().save(paths_a.mesh_file()).unwrap();
        ArmState::arm(paths_a.arm_file(), 120).unwrap();
        let pair_store = PairSessionStore::open(paths_a.pair_sessions_dir()).unwrap();
        let mesh = MeshState::load(paths_a.mesh_file()).unwrap();
        let armed = pair_store
            .arm_new(
                mesh.mesh_id,
                id_a.device_id(),
                120,
                PairEndpointClass::Confirm,
            )
            .unwrap();

        let fabric = LocalFabric::new();
        let agent = Agent::from_paths(&id_a, &paths_a, cfg_a).unwrap();
        let ep_a = fabric.endpoint(id_a.device_id());
        let agent_task = tokio::spawn(async move {
            let _ = agent.run(&ep_a).await;
        });
        tokio::time::sleep(Duration::from_millis(20)).await;

        let join_task = {
            let ep_b = fabric.endpoint(id_b.device_id());
            let secret_b = id_b.to_secret_bytes();
            let peer_a = id_a.device_id();
            let label = cfg_b.device_label.clone();
            let mesh_path = paths_b.mesh_file();
            let devices_b = paths_b.devices_file();
            tokio::spawn(async move {
                let id_b = Identity::from_secret_bytes(secret_b);
                let mut store_b = DeviceStore::open(devices_b).unwrap();
                let conn = ep_b.connect(peer_a).await.unwrap();
                run_join_as_guest(
                    conn,
                    &id_b,
                    &label,
                    &mut store_b,
                    &mesh_path,
                    Capability::all(),
                )
                .await
            })
        };

        let joins = JoinStore::open(paths_a.join_dir()).unwrap();
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        while joins.list_pending().unwrap().is_empty() {
            if tokio::time::Instant::now() > deadline {
                panic!("no pending");
            }
            tokio::time::sleep(Duration::from_millis(30)).await;
        }

        let codes = compute_confirm_codes(
            &armed.token_raw,
            &armed.session.sid,
            &id_b.device_id().to_string(),
            &id_a.device_id().to_string(),
            &armed.session.nonce,
        );
        let applied = apply_pair_confirm(
            &pair_store,
            &joins,
            &codes.deny,
            Some(&armed.session.sid),
            None,
        )
        .unwrap();
        assert!(matches!(
            applied.decision,
            mymesh_core::JoinDecision::Deny { .. }
        ));

        let join_err = tokio::time::timeout(Duration::from_secs(10), join_task)
            .await
            .expect("timeout")
            .expect("join task")
            .expect_err("deny must fail join");
        let msg = join_err.to_string();
        assert!(
            msg.to_lowercase().contains("denied")
                || msg.contains("PermissionDenied")
                || msg.to_lowercase().contains("deny"),
            "unexpected err: {msg}"
        );

        let store_a = DeviceStore::open(paths_a.devices_file()).unwrap();
        assert!(
            !store_a.is_trusted(&id_b.device_id()),
            "deny must not Trust joiner on host"
        );
        let store_b = DeviceStore::open(paths_b.devices_file()).unwrap();
        assert!(
            !store_b.is_trusted(&id_a.device_id()),
            "deny must not Trust host on joiner"
        );

        agent_task.abort();
        let _ = agent_task.await;
        let _ = std::fs::remove_dir_all(paths_a.data_dir.parent().unwrap());
        let _ = std::fs::remove_dir_all(paths_b.data_dir.parent().unwrap());
    }

    /// Direct call path without Agent::run — host handle_join_as_host + guest,
    /// confirms the same JoinStore / PairSession coupling as the agent loop.
    #[tokio::test]
    async fn two_agent_direct_handle_join_confirm_trusted() {
        let paths_a = tmp_paths("direct-a");
        let paths_b = tmp_paths("direct-b");
        let sandbox_b = paths_b.data_dir.parent().unwrap().join("sandbox");
        let _ = sandbox_b;

        let id_a = Identity::generate();
        let id_b = Identity::generate();

        MeshState::new_mesh().save(paths_a.mesh_file()).unwrap();
        ArmState::arm(paths_a.arm_file(), 120).unwrap();
        let pair_store = PairSessionStore::open(paths_a.pair_sessions_dir()).unwrap();
        let mesh = MeshState::load(paths_a.mesh_file()).unwrap();
        let armed = pair_store
            .arm_new(
                mesh.mesh_id,
                id_a.device_id(),
                120,
                PairEndpointClass::Confirm,
            )
            .unwrap();

        let fabric = LocalFabric::new();
        let ep_a = fabric.endpoint(id_a.device_id());
        let ep_b = fabric.endpoint(id_b.device_id());
        let secret_a = id_a.to_secret_bytes();
        let secret_b = id_b.to_secret_bytes();
        let peer_a = id_a.device_id();
        let peer_b = id_b.device_id();

        let host_fut = {
            let paths_a = paths_a.clone();
            async move {
                let id_a = Identity::from_secret_bytes(secret_a);
                let conn = ep_a.accept().await.unwrap();
                handle_join_as_host(
                    conn,
                    &id_a,
                    "agent-a",
                    &paths_a.devices_file(),
                    &paths_a.arm_file(),
                    &paths_a.join_dir(),
                    &paths_a.mesh_file(),
                    120,
                    Some(&paths_a.pair_sessions_dir()),
                )
                .await
            }
        };

        let mut store_b = DeviceStore::open(paths_b.devices_file()).unwrap();
        let guest_fut = {
            let mesh_path = paths_b.mesh_file();
            async move {
                let id_b = Identity::from_secret_bytes(secret_b);
                let conn = ep_b.connect(peer_a).await.unwrap();
                run_join_as_guest(
                    conn,
                    &id_b,
                    "agent-b",
                    &mut store_b,
                    &mesh_path,
                    Capability::all(),
                )
                .await
                .map(|r| (r, store_b))
            }
        };

        // Drive confirm after pending appears (parallel with host/guest)
        let confirm_fut = {
            let pair_store = PairSessionStore::open(paths_a.pair_sessions_dir()).unwrap();
            let joins = JoinStore::open(paths_a.join_dir()).unwrap();
            let token = armed.token_raw;
            let sid = armed.session.sid.clone();
            let nonce = armed.session.nonce;
            async move {
                let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
                loop {
                    if !joins.list_pending().unwrap().is_empty() {
                        break;
                    }
                    if tokio::time::Instant::now() > deadline {
                        panic!("pending timeout");
                    }
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
                let codes = compute_confirm_codes(
                    &token,
                    &sid,
                    &peer_b.to_string(),
                    &peer_a.to_string(),
                    &nonce,
                );
                apply_pair_confirm(&pair_store, &joins, &codes.accept, Some(&sid), None)
                    .expect("confirm")
            }
        };

        let (host_res, guest_res, _confirm_res) = tokio::join!(host_fut, guest_fut, confirm_fut);
        let outcome = host_res.expect("host join");
        assert_eq!(outcome, crate::JoinHostOutcome::MemberAccepted);
        let (host_rec, store_b) = guest_res.expect("guest join");
        assert_eq!(host_rec.trust, TrustState::Trusted);
        assert!(store_b.is_trusted(&peer_a));

        let store_a = DeviceStore::open(paths_a.devices_file()).unwrap();
        assert!(
            store_a.is_trusted(&peer_b),
            "host must Trust joiner after confirm accept"
        );

        let sess = pair_store.load(&armed.session.sid).unwrap().unwrap();
        assert_eq!(sess.phase, PairPhase::Decided);
        assert!(sess.confirm_consumed);

        let _ = std::fs::remove_dir_all(paths_a.data_dir.parent().unwrap());
        let _ = std::fs::remove_dir_all(paths_b.data_dir.parent().unwrap());
    }
}
