extern crate rocket;

mod cli;

use clap::Parser;
use cli::{
    AccountCommands, ClaimCommands, Cli, Commands, DomainCommands, PinCommands, RelationCommands,
    UserCommands,
};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

#[rocket::main]
async fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("warn")).init();

    let cli = Cli::parse();

    match cli.command {
        Commands::Serve => {
            log::info!("Starting linkkeys server...");

            let db_pool = linkkeys::db::create_pool();
            let ready_flag = Arc::new(AtomicBool::new(false));

            {
                let pool = db_pool.clone();
                let flag = ready_flag.clone();
                thread::spawn(move || {
                    // Schema migrations (diesel-tracked), then startup TRANSFORMS:
                    // idempotent data ops that must run at least once, in order.
                    // Transforms that were applied to every deployment from main
                    // (legacy-claim re-sign, profile backfill, admin split) have
                    // been removed; new transforms join the ordered list below.
                    linkkeys::db::run_migrations_with_locking(&pool);
                    run_startup_transforms(&pool);
                    // Signal readiness only after every startup DB write is done,
                    // so the TCP server's domain-key read can't contend on the
                    // SQLite lock (which previously failed its TLS setup).
                    flag.store(true, Ordering::SeqCst);
                    log::info!("Startup complete, server ready");
                });
            }

            {
                let flag = ready_flag.clone();
                let pool = db_pool.clone();
                let tcp_net = linkkeys::net::Net::production();
                thread::spawn(move || {
                    // Wait until startup DB writes finish before constructing the
                    // server: TcpServer::new reads domain keys for its TLS config,
                    // which would otherwise contend on the SQLite lock held by the
                    // migration/backfill thread, erroring out of new() (the bound
                    // listener is dropped) so the port never serves.
                    while !flag.load(Ordering::SeqCst) {
                        thread::sleep(Duration::from_millis(100));
                    }
                    match linkkeys::tcp::TcpServer::new(flag, pool, tcp_net) {
                        Ok(server) => server.run(),
                        Err(e) => log::error!("Failed to start TCP server: {}", e),
                    }
                });
            }

            linkkeys::web::launch_rocket(db_pool, ready_flag).await;
        }

        Commands::Domain(DomainCommands::Init) => domain_init(),
        Commands::Domain(DomainCommands::DnsCheck) => domain_dns_check().await,
        Commands::Domain(DomainCommands::ListKeys) => domain_list_keys(),
        Commands::Domain(DomainCommands::RevokeKey { key_id }) => domain_revoke_key(&key_id),
        Commands::User(UserCommands::Create {
            username,
            display_name,
            password,
            api_key,
            admin,
            relation,
        }) => {
            user_create(
                &username,
                &display_name,
                password.as_deref(),
                api_key,
                admin,
                &relation,
            );
        }
        Commands::User(UserCommands::List { local, server }) => {
            if local {
                user_list_local(server.as_deref())
            } else {
                user_list(server.as_deref())
            }
        }
        Commands::User(UserCommands::Update {
            user_id,
            display_name,
            server,
        }) => user_update(&user_id, display_name.as_deref(), server.as_deref()),
        Commands::User(UserCommands::Deactivate { user_id, server }) => {
            user_deactivate(&user_id, server.as_deref())
        }
        Commands::User(UserCommands::DeactivateLocal { user }) => user_deactivate_local(&user),
        Commands::User(UserCommands::ResetPassword { user_id, server }) => {
            user_reset_password(&user_id, server.as_deref())
        }
        Commands::User(UserCommands::ResetPasswordLocal {
            user,
            password,
            generate,
        }) => user_reset_password_local(&user, password.as_deref(), generate),
        Commands::User(UserCommands::PurgeLocal {
            user,
            force,
            force_admin,
            reason,
        }) => user_purge_local(&user, force, force_admin, &reason),
        Commands::Claim(ClaimCommands::Set {
            user_id,
            claim_type,
            claim_value,
            expires,
        }) => {
            claim_set(&user_id, &claim_type, &claim_value, expires.as_deref());
        }
        Commands::Claim(ClaimCommands::Remove { claim_id, server }) => {
            claim_remove(&claim_id, server.as_deref())
        }
        Commands::Relation(cmd) => handle_relation_command(cmd),
        Commands::Account(cmd) => handle_account_command(cmd),
        Commands::Pins(cmd) => handle_pins_command(cmd).await,
        Commands::Backup {
            out,
            rotate,
            embed_passphrase,
        } => backup_run(out.as_deref(), rotate, embed_passphrase),
        Commands::Restore {
            in_file,
            key,
            force,
        } => restore_run(in_file.as_deref(), key.as_deref(), force),
    }
}

/// Create an encrypted backup and write it to `--out` (or stdout). The backup
/// key is printed to stderr only when it was just generated or rotated.
fn backup_run(out: Option<&str>, rotate: bool, include_passphrase: bool) {
    let passphrase = get_passphrase();
    let db_pool = pool_with_migrations();

    let result = linkkeys::backup::create_backup(
        &db_pool,
        &passphrase,
        linkkeys::backup::BackupOptions {
            rotate,
            include_passphrase,
        },
    )
    .unwrap_or_else(|e| {
        eprintln!("Backup failed: {e}");
        std::process::exit(1);
    });

    match out {
        Some(path) => {
            std::fs::write(path, &result.ciphertext).unwrap_or_else(|e| {
                eprintln!("Failed to write {path}: {e}");
                std::process::exit(1);
            });
            eprintln!(
                "Backup written to {path} ({} bytes) for domain {}",
                result.ciphertext.len(),
                result.domain
            );
        }
        None => {
            use std::io::Write;
            std::io::stdout()
                .write_all(&result.ciphertext)
                .unwrap_or_else(|e| {
                    eprintln!("Failed to write backup to stdout: {e}");
                    std::process::exit(1);
                });
        }
    }

    if let Some(key) = result.new_key {
        eprintln!();
        eprintln!("==================== BACKUP KEY (SAVE THIS NOW) ====================");
        eprintln!("{}", linkkeys::backup::key_to_hex(&key));
        eprintln!("This is the ONLY way to decrypt your backups. Store it offline");
        eprintln!("(password manager / safe deposit box). It will not be shown again.");
        eprintln!("===================================================================");
    }
}

/// Restore the database from an encrypted backup artifact.
fn restore_run(in_file: Option<&str>, key: Option<&str>, force: bool) {
    let db_pool = pool_with_migrations();

    let key_hex = key
        .map(|s| s.to_string())
        .or_else(|| std::env::var("LINKKEYS_BACKUP_KEY").ok())
        .unwrap_or_else(|| {
            eprintln!("Error: provide --key <hex> or set LINKKEYS_BACKUP_KEY");
            std::process::exit(1);
        });
    let key = linkkeys::backup::key_from_hex(&key_hex).unwrap_or_else(|e| {
        eprintln!("Invalid backup key: {e}");
        std::process::exit(1);
    });

    let bytes = match in_file {
        Some(path) => std::fs::read(path).unwrap_or_else(|e| {
            eprintln!("Failed to read {path}: {e}");
            std::process::exit(1);
        }),
        None => {
            use std::io::Read;
            let mut buf = Vec::new();
            std::io::stdin().read_to_end(&mut buf).unwrap_or_else(|e| {
                eprintln!("Failed to read backup from stdin: {e}");
                std::process::exit(1);
            });
            buf
        }
    };

    let result = linkkeys::backup::restore_backup(
        &db_pool,
        &bytes,
        linkkeys::backup::RestoreOptions { key, force },
    )
    .unwrap_or_else(|e| {
        eprintln!("Restore failed: {e}");
        std::process::exit(1);
    });

    println!("Restored domain: {}", result.domain);
    println!(
        "Recovered signing fingerprints ({}):",
        result.fingerprints.len()
    );
    for fp in &result.fingerprints {
        println!("  {fp}");
    }

    if let Some(bundle_pass) = &result.passphrase_in_bundle {
        match std::env::var("DOMAIN_KEY_PASSPHRASE") {
            Ok(env_pass) if &env_pass == bundle_pass => {}
            Ok(_) => eprintln!(
                "WARNING: the DOMAIN_KEY_PASSPHRASE in this environment does NOT match the \
                 backup's. The restored domain keys will not decrypt until the server runs \
                 with the original passphrase."
            ),
            Err(_) => eprintln!(
                "NOTE: run the server with the DOMAIN_KEY_PASSPHRASE from when this backup was \
                 taken so the restored domain keys decrypt."
            ),
        }
    }

    println!("Restore complete. Confirm the fingerprints above match your _linkkeys DNS record.");
}

/// Run startup TRANSFORMS in order. A transform is an idempotent data operation
/// that must run at least once; unlike a schema migration (diesel-tracked) it is
/// safe to re-run every boot. Each is best-effort: a failure is logged but never
/// aborts the boot. The list is the single source of order.
///
/// (Transforms that had been applied to every deployment from main — legacy
/// claim re-signing, profile backfill, admin split — were removed once universal.)
fn run_startup_transforms(pool: &linkkeys::db::DbPool) {
    match pool.seed_default_policies() {
        Ok(n) if n > 0 => log::info!("Seeded {} default claim-type polic(ies)", n),
        Ok(_) => {}
        Err(e) => log::error!("Policy seed transform failed: {}", e),
    }
}

fn get_passphrase() -> String {
    std::env::var("DOMAIN_KEY_PASSPHRASE").unwrap_or_else(|_| {
        eprintln!("Error: DOMAIN_KEY_PASSPHRASE environment variable is required");
        std::process::exit(1);
    })
}

fn pool_with_migrations() -> linkkeys::db::DbPool {
    let pool = linkkeys::db::create_pool();
    linkkeys::db::run_migrations_with_locking(&pool);
    pool
}

fn store_auth_credential(
    db_pool: &linkkeys::db::DbPool,
    user_id: &str,
    credential_type: &str,
    credential_hash: &str,
) {
    match db_pool {
        #[cfg(feature = "postgres")]
        linkkeys::db::DbPool::Postgres(pool) => {
            let mut conn = pool.get().expect("Failed to get connection");
            let uid: uuid::Uuid = user_id.parse().expect("Invalid user UUID");
            linkkeys::db::auth_credentials::pg::create(
                &mut conn,
                uid,
                credential_type,
                credential_hash,
            )
            .expect("Failed to store auth credential");
        }
        #[cfg(feature = "sqlite")]
        linkkeys::db::DbPool::Sqlite(pool) => {
            let mut conn = pool.get().expect("Failed to get connection");
            linkkeys::db::auth_credentials::sqlite::create(
                &mut conn,
                user_id,
                credential_type,
                credential_hash,
            )
            .expect("Failed to store auth credential");
        }
    }
}

struct GeneratedKey {
    id: String,
    fingerprint: String,
}

fn generate_and_store_keypairs<F>(
    db_pool: &linkkeys::db::DbPool,
    passphrase: &str,
    staggered_years: &[i64],
    store_fn: F,
) where
    F: Fn(
        &linkkeys::db::DbPool,
        &[u8],
        &[u8],
        &str,
        chrono::DateTime<chrono::Utc>,
    ) -> Result<GeneratedKey, String>,
{
    for &years in staggered_years {
        let (verifying_key, signing_key) = liblinkkeys::crypto::generate_ed25519_keypair();
        let pk_bytes = verifying_key.as_bytes().to_vec();
        let sk_bytes = signing_key.to_bytes();
        let encrypted = liblinkkeys::crypto::encrypt_private_key(&sk_bytes, passphrase.as_bytes())
            .expect("Failed to encrypt private key");
        let fp = liblinkkeys::crypto::fingerprint(&pk_bytes);
        let expires = chrono::Utc::now() + chrono::Duration::days(365 * years);

        match store_fn(db_pool, &pk_bytes, &encrypted, &fp, expires) {
            Ok(key) => println!(
                "  Key {}: fingerprint={} expires={}yr",
                key.id, key.fingerprint, years
            ),
            Err(e) => {
                eprintln!("Failed to store key: {}", e);
                std::process::exit(1);
            }
        }
    }
}

/// Initialize a domain's keys. Idempotent and strictly additive: it generates
/// only the key *sets* that are entirely absent and never touches keys that
/// already exist. Re-running it on a domain created before split
/// signing/encryption keys backfills the missing encryption key without minting
/// new signing keys (which would be absent from DNS `fp=` and break pinning).
///
/// Safety: the decision is made from the full key list. If that lookup *fails*
/// we abort rather than generate — "I couldn't find the keys" must never become
/// "there are no keys, so make new ones" and clobber a working domain.
fn domain_init() {
    let passphrase = get_passphrase();
    let db_pool = pool_with_migrations();

    let existing = db_pool.list_all_domain_keys().unwrap_or_else(|e| {
        eprintln!("Failed to read existing domain keys: {e}");
        eprintln!("Refusing to generate keys when the current state is unknown.");
        std::process::exit(1);
    });
    let has_signing = existing.iter().any(|k| k.key_usage == "sign");
    let has_encryption = existing.iter().any(|k| k.key_usage == "encrypt");

    if has_signing {
        println!(
            "Signing keys already present ({} found); leaving them untouched.",
            existing.iter().filter(|k| k.key_usage == "sign").count()
        );
    } else {
        generate_signing_keys(&db_pool, &passphrase);
    }

    if has_encryption {
        println!("Encryption key already present; leaving it untouched.");
    } else {
        generate_and_store_encryption_key(&db_pool, &passphrase);
    }

    println!("Domain init complete.");
}

/// List the domain's keys (DB-direct) so an admin can find a key id to revoke.
fn domain_list_keys() {
    let db_pool = pool_with_migrations();
    let keys = db_pool.list_all_domain_keys().unwrap_or_else(|e| {
        eprintln!("Failed to read domain keys: {e}");
        std::process::exit(1);
    });
    if keys.is_empty() {
        println!("No domain keys. Run `linkkeys domain init`.");
        return;
    }
    println!("{:<38} {:<8} {:<10} FINGERPRINT", "ID", "USAGE", "STATUS");
    for k in &keys {
        let status = if k.revoked_at.is_some() {
            "revoked"
        } else {
            "active"
        };
        println!(
            "{:<38} {:<8} {:<10} {}",
            k.id, k.key_usage, status, k.fingerprint
        );
    }
}

/// Revoke a domain key by id (SEC-08). Idempotent; prints the resulting status
/// and, when at least two sibling signing keys remain, produces a sibling-signed
/// revocation certificate (the authenticated, in-band revocation proof) and
/// records it in the audit log.
fn domain_revoke_key(key_id: &str) {
    let db_pool = pool_with_migrations();
    let revoked = match db_pool.revoke_domain_key(key_id) {
        Ok(k) => k,
        Err(diesel::result::Error::NotFound) => {
            eprintln!("No domain key with id {key_id}.");
            std::process::exit(1);
        }
        Err(e) => {
            eprintln!("Failed to revoke key: {e}");
            std::process::exit(1);
        }
    };
    println!(
        "Revoked domain key {} (revoked_at={}).",
        revoked.id,
        revoked.revoked_at.as_deref().unwrap_or("<none>")
    );
    println!(
        "Next: remove this key's fingerprint ({}) from the domain's _linkkeys DNS TXT record so peers drop it on their next recheck.",
        revoked.fingerprint
    );

    // Produce the sibling-signed revocation certificate from the remaining active
    // signing keys (the target is now excluded from list_active_domain_keys).
    domain_emit_revocation_cert(&db_pool, &revoked);

    // TODO(proactive re-attestation): track the attestations WE have signed for
    // other domains (which claims, signed with which key, deposited where). On
    // revoking a key, go to each such domain and re-issue those attestations with
    // a replacement key — same subject/value/expiry, a NEW attested_at. Since the
    // two surviving keys already vouch and can prove the replacement, the peer can
    // swap the old claim for the new one seamlessly (everyone keeps their DMV-
    // style attestations without a re-verification round-trip). Needs an
    // outbound-attestation ledger + a re-attest op.
}

/// Build a sibling-signed revocation certificate for `revoked` from the domain's
/// other active signing keys and record it in the audit log. Best-effort: a
/// domain with fewer than two remaining sibling signing keys can't reach quorum,
/// which is logged as guidance, not an error.
fn domain_emit_revocation_cert(
    db_pool: &linkkeys::db::DbPool,
    revoked: &linkkeys::db::models::DomainKey,
) {
    use liblinkkeys::claims::ClaimSigner;
    use liblinkkeys::revocation::{
        build_revocation_certificate, RevocationSpec, REVOCATION_QUORUM,
    };

    let passphrase = get_passphrase();
    let active = db_pool.list_active_domain_keys().unwrap_or_default();
    let signer_keys: Vec<_> = active
        .into_iter()
        .filter(|k| k.key_usage == "sign" && k.id != revoked.id)
        .collect();
    let active_signers =
        linkkeys::claim_signing::active_signers(&signer_keys, passphrase.as_bytes())
            .unwrap_or_default();
    if active_signers.len() < REVOCATION_QUORUM {
        eprintln!(
            "Note: only {} sibling signing key(s) remain; need {} to co-sign a revocation certificate. \
             Revocation is recorded locally and enforced via DNS removal.",
            active_signers.len(),
            REVOCATION_QUORUM
        );
        let _ = db_pool.write_audit(
            "domain_key.revoked",
            Some(&revoked.id),
            Some("cli"),
            Some("no certificate (insufficient sibling keys)"),
        );
        return;
    }

    let domain = linkkeys::conversions::get_domain_name();
    let revoked_at = revoked.revoked_at.clone().unwrap_or_default();
    let signers: Vec<ClaimSigner> = active_signers
        .iter()
        .map(|s| ClaimSigner {
            domain: &domain,
            key_id: &s.key_id,
            algorithm: s.algorithm,
            private_key_bytes: &s.private_key,
        })
        .collect();
    let spec = RevocationSpec {
        target_key_id: &revoked.id,
        target_fingerprint: &revoked.fingerprint,
        revoked_at: &revoked_at,
    };
    match build_revocation_certificate(&spec, &signers) {
        Ok(cert) => {
            let summary = format!(
                "sibling-signed revocation certificate: {} signatures over key {} (fp {})",
                cert.signatures.len(),
                cert.target_key_id,
                cert.target_fingerprint
            );
            // The on-wire (CSIL CBOR) certificate — the portable, verifiable proof
            // a peer can check against this domain's published key set.
            let cbor = liblinkkeys::generated::encode_revocation_certificate(&cert);
            let hex = cbor
                .iter()
                .fold(String::with_capacity(cbor.len() * 2), |mut s, b| {
                    use std::fmt::Write;
                    let _ = write!(s, "{b:02x}");
                    s
                });
            println!("Produced {summary}.");
            println!("Revocation certificate (CBOR hex, publish to peers):\n{hex}");

            // Persist it so peers can pull it via DomainKeys/get-revocations.
            if let Ok(when) = chrono::DateTime::parse_from_rfc3339(&revoked_at) {
                if let Err(e) = db_pool.insert_issued_revocation(
                    &revoked.id,
                    &revoked.fingerprint,
                    when.with_timezone(&chrono::Utc),
                    &cbor,
                ) {
                    eprintln!("Warning: failed to store issued revocation: {e}");
                }
            }

            let _ = db_pool.write_audit(
                "domain_key.revoked",
                Some(&revoked.id),
                Some("cli"),
                Some(&summary),
            );
        }
        Err(e) => eprintln!("Could not build revocation certificate: {e}"),
    }
}

/// Handle `linkkeys pins ...` (SEC-01 TOFU pin management). `recheck` is
/// cron-friendly and exits non-zero if any domain is in a mismatch state.
async fn handle_pins_command(cmd: PinCommands) {
    let db_pool = pool_with_migrations();
    match cmd {
        PinCommands::List => {
            let pins = db_pool.list_domain_pins().unwrap_or_else(|e| {
                eprintln!("Failed to read pins: {e}");
                std::process::exit(1);
            });
            if pins.is_empty() {
                println!("No pinned domains yet.");
                return;
            }
            println!("{:<30} {:<28} FINGERPRINTS", "DOMAIN", "LAST CHECKED");
            for p in &pins {
                println!(
                    "{:<30} {:<28} {}",
                    p.domain, p.last_checked_at, p.fingerprints
                );
            }
        }
        PinCommands::Recheck { domain } => {
            let net = linkkeys::net::Net::production();
            let results = match domain {
                Some(d) => {
                    let r = linkkeys::services::pins::recheck_domain(&db_pool, &net, &d).await;
                    vec![(d, r)]
                }
                None => linkkeys::services::pins::recheck_all(&db_pool, &net).await,
            };
            if results.is_empty() {
                println!("No pinned domains to recheck.");
                return;
            }
            let mut mismatch = false;
            for (d, r) in &results {
                match r {
                    Ok(outcome) => {
                        println!("{d}: {outcome:?}");
                        if matches!(outcome, linkkeys::services::pins::PinOutcome::Mismatch) {
                            mismatch = true;
                        }
                    }
                    Err(e) => {
                        eprintln!("{d}: ERROR {e}");
                    }
                }
            }
            if mismatch {
                // Non-zero so cron/monitoring surfaces the mismatch for a human.
                std::process::exit(2);
            }
        }
    }
}

/// Generate the domain's three staggered-expiry Ed25519 signing keypairs.
fn generate_signing_keys(db_pool: &linkkeys::db::DbPool, passphrase: &str) {
    println!("Generating 3 domain keypairs...");
    generate_and_store_keypairs(
        db_pool,
        passphrase,
        &[2, 3, 4],
        |pool, pk, enc, fp, exp| match pool {
            #[cfg(feature = "postgres")]
            linkkeys::db::DbPool::Postgres(p) => {
                let mut conn = p.get().map_err(|e| e.to_string())?;
                linkkeys::db::domain_keys::pg::create(&mut conn, pk, enc, fp, "ed25519", exp)
                    .map(|k| GeneratedKey {
                        id: k.id,
                        fingerprint: k.fingerprint,
                    })
                    .map_err(|e| e.to_string())
            }
            #[cfg(feature = "sqlite")]
            linkkeys::db::DbPool::Sqlite(p) => {
                let mut conn = p.get().map_err(|e| e.to_string())?;
                linkkeys::db::domain_keys::sqlite::create(
                    &mut conn,
                    pk,
                    enc,
                    fp,
                    "ed25519",
                    &exp.to_rfc3339(),
                )
                .map(|k| GeneratedKey {
                    id: k.id,
                    fingerprint: k.fingerprint,
                })
                .map_err(|e| e.to_string())
            }
        },
    );
}

/// Generate the domain's X25519 encryption key (sealed-box recipient), vouched
/// for by one of the signing keys (the signing key signs the encryption key's
/// fingerprint + expiry). Encryption keys are NOT published in DNS — verifiers
/// trust them via this vouch chained to a DNS-pinned signing key.
fn generate_and_store_encryption_key(db_pool: &linkkeys::db::DbPool, passphrase: &str) {
    use chrono::Timelike;

    let signing_keys = db_pool.list_active_domain_keys().unwrap_or_else(|e| {
        eprintln!("Failed to list signing keys: {}", e);
        std::process::exit(1);
    });
    let signer = signing_keys
        .iter()
        .find(|k| k.key_usage == "sign")
        .unwrap_or_else(|| {
            eprintln!("No signing key available to vouch for the encryption key");
            std::process::exit(1);
        });
    let signer_sk = liblinkkeys::crypto::decrypt_private_key(
        &signer.private_key_encrypted,
        passphrase.as_bytes(),
    )
    .unwrap_or_else(|e| {
        eprintln!("Failed to decrypt signing key: {}", e);
        std::process::exit(1);
    });
    let signer_alg = liblinkkeys::crypto::SigningAlgorithm::parse_str(&signer.algorithm)
        .unwrap_or_else(|| {
            eprintln!("Unsupported signing algorithm: {}", signer.algorithm);
            std::process::exit(1);
        });

    let (enc_pub, enc_priv) = liblinkkeys::crypto::generate_x25519_keypair();
    let enc_fp = liblinkkeys::crypto::fingerprint(&enc_pub);
    let enc_priv_encrypted =
        liblinkkeys::crypto::encrypt_private_key(&enc_priv, passphrase.as_bytes())
            .expect("Failed to encrypt encryption private key");
    // Whole-second expiry so the signed value round-trips byte-identically
    // through pg timestamptz / sqlite text (the vouch signs this exact string).
    let expires = (chrono::Utc::now() + chrono::Duration::days(365 * 2))
        .with_nanosecond(0)
        .unwrap();
    let expires_str = expires.to_rfc3339();

    let vouch = liblinkkeys::dns::sign_key_vouch(&enc_fp, &expires_str, signer_alg, &signer_sk)
        .expect("Failed to sign encryption-key vouch");

    let result = match db_pool {
        #[cfg(feature = "postgres")]
        linkkeys::db::DbPool::Postgres(p) => {
            let mut conn = p.get().expect("Failed to get connection");
            linkkeys::db::domain_keys::pg::create_encryption_key(
                &mut conn,
                &enc_pub,
                &enc_priv_encrypted,
                &enc_fp,
                &signer.id,
                &vouch,
                expires,
            )
            .map(|k| k.id)
            .map_err(|e| e.to_string())
        }
        #[cfg(feature = "sqlite")]
        linkkeys::db::DbPool::Sqlite(p) => {
            let mut conn = p.get().expect("Failed to get connection");
            linkkeys::db::domain_keys::sqlite::create_encryption_key(
                &mut conn,
                &enc_pub,
                &enc_priv_encrypted,
                &enc_fp,
                &signer.id,
                &vouch,
                &expires_str,
            )
            .map(|k| k.id)
            .map_err(|e| e.to_string())
        }
    };
    match result {
        Ok(id) => println!(
            "  Encryption key {}: fingerprint={} (vouched by {})",
            id, enc_fp, signer.id
        ),
        Err(e) => {
            eprintln!("Failed to store encryption key: {}", e);
            std::process::exit(1);
        }
    }
}

fn user_create(
    username: &str,
    display_name: &str,
    password: Option<&str>,
    api_key: bool,
    admin: bool,
    relations: &[String],
) {
    // Validate requested relations up front so we fail before creating a user
    // (and its keypairs) we'd then have to reason about half-provisioned.
    for r in relations {
        if !linkkeys::services::authorization::is_grantable_relation(r) {
            eprintln!(
                "Unknown relation '{}'. Valid relations: {}",
                r,
                linkkeys::services::authorization::GRANTABLE_RELATIONS.join(", ")
            );
            std::process::exit(1);
        }
    }
    let passphrase = get_passphrase();
    let db_pool = pool_with_migrations();

    let user = match &db_pool {
        #[cfg(feature = "postgres")]
        linkkeys::db::DbPool::Postgres(pool) => {
            let mut conn = pool.get().expect("Failed to get connection");
            linkkeys::db::users::pg::create(&mut conn, username, display_name)
        }
        #[cfg(feature = "sqlite")]
        linkkeys::db::DbPool::Sqlite(pool) => {
            let mut conn = pool.get().expect("Failed to get connection");
            linkkeys::db::users::sqlite::create(&mut conn, username, display_name)
        }
    }
    .unwrap_or_else(|e| {
        eprintln!("Failed to create user: {}", e);
        std::process::exit(1);
    });

    println!("User created: id={}", user.id);

    // Store auth credential
    if api_key {
        let (key, hash) = linkkeys::services::auth::generate_api_key(&user.id);
        store_auth_credential(
            &db_pool,
            &user.id,
            linkkeys::services::auth::CREDENTIAL_TYPE_API_KEY,
            &hash,
        );
        println!("API key: {}", key);
        println!("(save this — it will not be shown again)");
    } else {
        let password = match password {
            Some(p) => p.to_string(),
            None => {
                eprint!("Enter password: ");
                let mut input = String::new();
                std::io::stdin()
                    .read_line(&mut input)
                    .expect("Failed to read password");
                input.trim().to_string()
            }
        };

        if password.is_empty() {
            eprintln!("Error: password cannot be empty");
            std::process::exit(1);
        }

        let hash = bcrypt::hash(&password, 12).expect("Failed to hash password");
        store_auth_credential(
            &db_pool,
            &user.id,
            linkkeys::services::auth::CREDENTIAL_TYPE_PASSWORD,
            &hash,
        );
    }

    let user_id_for_store = user.id.clone();
    generate_and_store_keypairs(
        &db_pool,
        &passphrase,
        &[2, 3, 4],
        |pool, pk, enc, fp, exp| match pool {
            #[cfg(feature = "postgres")]
            linkkeys::db::DbPool::Postgres(p) => {
                let mut conn = p.get().map_err(|e| e.to_string())?;
                let uid: uuid::Uuid = user_id_for_store
                    .parse()
                    .map_err(|e: uuid::Error| e.to_string())?;
                linkkeys::db::user_keys::pg::create(&mut conn, uid, pk, enc, fp, "ed25519", exp)
                    .map(|k| GeneratedKey {
                        id: k.id,
                        fingerprint: k.fingerprint,
                    })
                    .map_err(|e| e.to_string())
            }
            #[cfg(feature = "sqlite")]
            linkkeys::db::DbPool::Sqlite(p) => {
                let mut conn = p.get().map_err(|e| e.to_string())?;
                linkkeys::db::user_keys::sqlite::create(
                    &mut conn,
                    &user_id_for_store,
                    pk,
                    enc,
                    fp,
                    "ed25519",
                    &exp.to_rfc3339(),
                )
                .map(|k| GeneratedKey {
                    id: k.id,
                    fingerprint: k.fingerprint,
                })
                .map_err(|e| e.to_string())
            }
        },
    );

    // Grant --admin (kept for compatibility) plus any explicit --relation values.
    // De-duplicated so `--admin --relation admin` doesn't hit the unique index.
    let mut to_grant: Vec<&str> = Vec::new();
    if admin {
        to_grant.push("admin");
    }
    for r in relations {
        if !to_grant.contains(&r.as_str()) {
            to_grant.push(r.as_str());
        }
    }
    for relation in to_grant {
        grant_relation_local(&db_pool, &user.id, relation);
    }
}

/// Grant `relation` to `user_id` on the current domain, DB-direct and idempotent.
/// Shared by `user create --relation/--admin` and `relation grant-local`; the
/// caller is responsible for validating the relation name first (both do).
fn grant_relation_local(db_pool: &linkkeys::db::DbPool, user_id: &str, relation: &str) {
    let domain = linkkeys::conversions::get_domain_name();
    match db_pool.grant_relation_idempotent("user", user_id, relation, "domain", &domain) {
        Ok(true) => println!(
            "Relation granted: {} -> {} on domain {}",
            user_id, relation, domain
        ),
        Ok(false) => println!(
            "Relation already present: {} -> {} on domain {}",
            user_id, relation, domain
        ),
        Err(e) => {
            eprintln!("Failed to grant relation '{}': {}", relation, e);
            std::process::exit(1);
        }
    }
}

/// Resolve a user by username (preferred) or UUID, for DB-direct CLI paths.
fn resolve_local_user_id(db_pool: &linkkeys::db::DbPool, ident: &str) -> String {
    if let Ok(u) = db_pool.find_user_by_username(ident) {
        return u.id;
    }
    if let Ok(u) = db_pool.find_user_by_id(ident) {
        return u.id;
    }
    eprintln!(
        "No user found matching '{}' (tried username, then UUID)",
        ident
    );
    std::process::exit(1);
}

fn is_protected_admin_account(
    db_pool: &linkkeys::db::DbPool,
    user: &linkkeys::db::models::User,
) -> bool {
    let domain = linkkeys::conversions::get_domain_name();
    match db_pool.is_protected_admin_user(&user.id, &domain) {
        Ok(protected) => protected,
        Err(e) => {
            eprintln!("Failed to inspect protected-admin status: {}", e);
            std::process::exit(1);
        }
    }
}

fn generated_password() -> String {
    use rand::distributions::{Alphanumeric, DistString};
    Alphanumeric.sample_string(&mut rand::thread_rng(), 32)
}

fn read_password_from_stdin(prompt: &str) -> String {
    eprint!("{prompt}");
    let mut password = String::new();
    std::io::stdin()
        .read_line(&mut password)
        .expect("Failed to read password");
    password.trim().to_string()
}

fn user_list_local(server: Option<&str>) {
    if server.is_some() {
        eprintln!("Error: --local cannot be combined with --server");
        std::process::exit(1);
    }
    let db_pool = pool_with_migrations();
    let users = db_pool.list_all_users().unwrap_or_else(|e| {
        eprintln!("Failed to list users: {}", e);
        std::process::exit(1);
    });

    for user in &users {
        let mut status = Vec::new();
        if !user.is_active {
            status.push("deactivated");
        }
        if user.is_admin_account {
            status.push("admin-account");
        }
        if user.purged_at.is_some() {
            status.push("purged");
        }
        let status = if status.is_empty() {
            String::new()
        } else {
            format!(" [{}]", status.join(", "))
        };
        println!(
            "  {} {} ({}){}",
            user.id, user.username, user.display_name, status
        );
    }
    println!("{} user(s)", users.len());
}

fn user_deactivate_local(user_ident: &str) {
    let db_pool = pool_with_migrations();
    let user_id = resolve_local_user_id(&db_pool, user_ident);
    let user = db_pool.find_user_by_id(&user_id).unwrap_or_else(|e| {
        eprintln!("Failed to load user: {}", e);
        std::process::exit(1);
    });
    if user.purged_at.is_some() {
        eprintln!("User is already purged: {} {}", user.id, user.username);
        std::process::exit(1);
    }

    let req = liblinkkeys::generated::types::DeactivateUserRequest {
        user_id: user_id.clone(),
    };
    let resp = linkkeys::services::admin::deactivate_user(&db_pool, req).unwrap_or_else(|e| {
        eprintln!("Failed to deactivate user: {}", e.message);
        std::process::exit(1);
    });
    let _ = db_pool.write_audit(
        "user.deactivated.local",
        Some(&user_id),
        Some("local-cli"),
        Some("credentials revoked"),
    );
    println!("User deactivated: {} {}", resp.user.id, resp.user.username);
}

fn user_reset_password_local(user_ident: &str, password: Option<&str>, generate: bool) {
    if generate && password.is_some() {
        eprintln!("Error: use either --password or --generate, not both");
        std::process::exit(1);
    }
    let db_pool = pool_with_migrations();
    let user_id = resolve_local_user_id(&db_pool, user_ident);
    let new_password = if generate {
        generated_password()
    } else {
        password
            .map(ToString::to_string)
            .unwrap_or_else(|| read_password_from_stdin("Enter new password: "))
    };
    if new_password.is_empty() {
        eprintln!("Error: password cannot be empty");
        std::process::exit(1);
    }

    let req = liblinkkeys::generated::types::ResetPasswordRequest {
        user_id: user_id.clone(),
        new_password: new_password.clone(),
    };
    let resp = linkkeys::services::admin::reset_password(&db_pool, req).unwrap_or_else(|e| {
        eprintln!("Failed to reset password: {}", e.message);
        std::process::exit(1);
    });
    if !resp.success {
        eprintln!("Password reset failed.");
        std::process::exit(1);
    }

    let _ = db_pool.write_audit(
        "user.password_reset.local",
        Some(&user_id),
        Some("local-cli"),
        Some(if generate {
            "generated"
        } else {
            "operator-provided"
        }),
    );
    println!("Password reset successfully.");
    if generate {
        println!("Generated password: {}", new_password);
        println!("(save this — it will not be shown again)");
    }
}

fn user_purge_local(user_ident: &str, force: bool, force_admin: bool, reason: &str) {
    if !force {
        eprintln!("Error: purge-local is irreversible; pass --force to confirm");
        std::process::exit(1);
    }
    if reason.trim().is_empty() {
        eprintln!("Error: --reason cannot be empty");
        std::process::exit(1);
    }

    let db_pool = pool_with_migrations();
    let user_id = resolve_local_user_id(&db_pool, user_ident);
    let user = db_pool.find_user_by_id(&user_id).unwrap_or_else(|e| {
        eprintln!("Failed to load user: {}", e);
        std::process::exit(1);
    });
    if user.purged_at.is_some() {
        eprintln!("User is already purged: {} {}", user.id, user.username);
        std::process::exit(1);
    }
    if is_protected_admin_account(&db_pool, &user) && !force_admin {
        eprintln!(
            "Refusing to purge protected admin account {} {}; pass --force-admin to override",
            user.id, user.username
        );
        std::process::exit(1);
    }

    let summary = db_pool
        .purge_user_tombstone(&user_id, Some(reason.trim()))
        .unwrap_or_else(|e| {
            eprintln!("Failed to purge user: {}", e);
            std::process::exit(1);
        });
    let detail = format!(
        "username={} credentials_revoked={} keys_revoked={} claims_revoked={} relations_removed={} profiles_deleted={} consent_grants_deleted={} release_prefs_deleted={} email_verifications_deleted={} reviews_resolved={} reason={}",
        user.username,
        summary.credentials_revoked,
        summary.keys_revoked,
        summary.claims_revoked,
        summary.relations_removed,
        summary.profiles_deleted,
        summary.consent_grants_deleted,
        summary.release_prefs_deleted,
        summary.email_verifications_deleted,
        summary.reviews_resolved,
        reason.trim()
    );
    let _ = db_pool.write_audit(
        "user.purged.local",
        Some(&summary.user.id),
        Some("local-cli"),
        Some(&detail),
    );

    println!(
        "User purged to tombstone: {} {}",
        summary.user.id, summary.user.username
    );
    println!(
        "Revoked: {} credential(s), {} key(s), {} claim(s); removed {} relation(s)",
        summary.credentials_revoked,
        summary.keys_revoked,
        summary.claims_revoked,
        summary.relations_removed
    );
}

// --- TCP-based command handlers ---

/// Encode `req` with the CSIL codec, send it over TCP to the given service/op,
/// and decode the response — exiting with a message on any transport or decode
/// error. Centralizes the uniform CLI error handling for the typed admin/account
/// calls.
fn tcp_call<Req, Resp>(
    addr: &str,
    service: &str,
    op: &str,
    req: &Req,
    api_key: &str,
    encode: impl Fn(&Req) -> Vec<u8>,
    decode: impl Fn(&[u8]) -> Result<Resp, liblinkkeys::generated::codec::CsilCborError>,
) -> Resp {
    let resp_bytes = cli::tcp_client::send_request(addr, service, op, encode(req), Some(api_key))
        .unwrap_or_else(|e| {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        });
    decode(&resp_bytes).unwrap_or_else(|e| {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    })
}

fn user_list(server: Option<&str>) {
    let addr = cli::tcp_client::get_server_addr(server);
    let key = cli::tcp_client::get_api_key();
    let req = liblinkkeys::generated::types::ListUsersRequest {
        offset: None,
        limit: None,
    };

    let resp = tcp_call(
        &addr,
        "Admin",
        "list-users",
        &req,
        &key,
        liblinkkeys::generated::encode_list_users_request,
        liblinkkeys::generated::decode_list_users_response,
    );

    for user in &resp.users {
        let status = if user.is_active { "" } else { " [deactivated]" };
        println!(
            "  {} {} ({}){}",
            user.id, user.username, user.display_name, status
        );
    }
    println!("{} user(s)", resp.users.len());
}

fn user_update(user_id: &str, display_name: Option<&str>, server: Option<&str>) {
    let addr = cli::tcp_client::get_server_addr(server);
    let key = cli::tcp_client::get_api_key();
    let req = liblinkkeys::generated::types::UpdateUserRequest {
        user_id: user_id.to_string(),
        display_name: display_name.map(|s| s.to_string()),
    };

    let resp = tcp_call(
        &addr,
        "Admin",
        "update-user",
        &req,
        &key,
        liblinkkeys::generated::encode_update_user_request,
        liblinkkeys::generated::decode_update_user_response,
    );

    println!(
        "User updated: {} {} ({})",
        resp.user.id, resp.user.username, resp.user.display_name
    );
}

fn user_deactivate(user_id: &str, server: Option<&str>) {
    let addr = cli::tcp_client::get_server_addr(server);
    let key = cli::tcp_client::get_api_key();
    let req = liblinkkeys::generated::types::DeactivateUserRequest {
        user_id: user_id.to_string(),
    };

    let resp = tcp_call(
        &addr,
        "Admin",
        "deactivate-user",
        &req,
        &key,
        liblinkkeys::generated::encode_deactivate_user_request,
        liblinkkeys::generated::decode_deactivate_user_response,
    );

    println!("User deactivated: {} {}", resp.user.id, resp.user.username);
}

fn user_reset_password(user_id: &str, server: Option<&str>) {
    let addr = cli::tcp_client::get_server_addr(server);
    let key = cli::tcp_client::get_api_key();

    eprint!("Enter new password: ");
    let mut password = String::new();
    std::io::stdin()
        .read_line(&mut password)
        .expect("Failed to read password");
    let password = password.trim().to_string();
    if password.is_empty() {
        eprintln!("Error: password cannot be empty");
        std::process::exit(1);
    }

    let req = liblinkkeys::generated::types::ResetPasswordRequest {
        user_id: user_id.to_string(),
        new_password: password,
    };

    let resp = tcp_call(
        &addr,
        "Admin",
        "reset-password",
        &req,
        &key,
        liblinkkeys::generated::encode_reset_password_request,
        liblinkkeys::generated::decode_reset_password_response,
    );

    if resp.success {
        println!("Password reset successfully.");
    } else {
        eprintln!("Password reset failed.");
        std::process::exit(1);
    }
}

fn claim_remove(claim_id: &str, server: Option<&str>) {
    let addr = cli::tcp_client::get_server_addr(server);
    let key = cli::tcp_client::get_api_key();
    let req = liblinkkeys::generated::types::RemoveClaimRequest {
        claim_id: claim_id.to_string(),
    };

    let resp = tcp_call(
        &addr,
        "Admin",
        "remove-claim",
        &req,
        &key,
        liblinkkeys::generated::encode_remove_claim_request,
        liblinkkeys::generated::decode_remove_claim_response,
    );

    if resp.success {
        println!("Claim removed.");
    } else {
        eprintln!("Claim removal failed.");
        std::process::exit(1);
    }
}

fn handle_relation_command(cmd: RelationCommands) {
    match cmd {
        RelationCommands::GrantLocal { user, relation } => {
            if !linkkeys::services::authorization::is_grantable_relation(&relation) {
                eprintln!(
                    "Unknown relation '{}'. Valid relations: {}",
                    relation,
                    linkkeys::services::authorization::GRANTABLE_RELATIONS.join(", ")
                );
                std::process::exit(1);
            }
            let db_pool = pool_with_migrations();
            let user_id = resolve_local_user_id(&db_pool, &user);
            grant_relation_local(&db_pool, &user_id, &relation);
        }
        RelationCommands::Grant {
            subject_type,
            subject_id,
            relation,
            object_type,
            object_id,
            server,
        } => {
            let addr = cli::tcp_client::get_server_addr(server.as_deref());
            let key = cli::tcp_client::get_api_key();
            let req = liblinkkeys::generated::types::GrantRelationRequest {
                subject_type,
                subject_id,
                relation,
                object_type,
                object_id,
            };

            let resp = tcp_call(
                &addr,
                "Admin",
                "grant-relation",
                &req,
                &key,
                liblinkkeys::generated::encode_grant_relation_request,
                liblinkkeys::generated::decode_grant_relation_response,
            );

            let r = &resp.relation;
            println!(
                "Relation granted: id={} ({} {} -> {} {} {})",
                r.id, r.subject_type, r.subject_id, r.relation, r.object_type, r.object_id
            );
        }
        RelationCommands::Remove {
            relation_id,
            server,
        } => {
            let addr = cli::tcp_client::get_server_addr(server.as_deref());
            let key = cli::tcp_client::get_api_key();
            let req = liblinkkeys::generated::types::RemoveRelationRequest {
                relation_id: relation_id.to_string(),
            };

            let resp = tcp_call(
                &addr,
                "Admin",
                "remove-relation",
                &req,
                &key,
                liblinkkeys::generated::encode_remove_relation_request,
                liblinkkeys::generated::decode_remove_relation_response,
            );

            if resp.success {
                println!("Relation removed.");
            } else {
                eprintln!("Relation removal failed.");
                std::process::exit(1);
            }
        }
        RelationCommands::List {
            subject_type,
            subject_id,
            object_type,
            object_id,
            server,
        } => {
            let addr = cli::tcp_client::get_server_addr(server.as_deref());
            let key = cli::tcp_client::get_api_key();
            let req = liblinkkeys::generated::types::ListRelationsRequest {
                subject_type,
                subject_id,
                object_type,
                object_id,
            };

            let resp = tcp_call(
                &addr,
                "Admin",
                "list-relations",
                &req,
                &key,
                liblinkkeys::generated::encode_list_relations_request,
                liblinkkeys::generated::decode_list_relations_response,
            );

            for r in &resp.relations {
                let removed = r
                    .removed_at
                    .as_ref()
                    .map(|t| format!(" [removed {}]", t))
                    .unwrap_or_default();
                println!(
                    "  {} ({} {} -> {} {} {}){}",
                    r.id,
                    r.subject_type,
                    r.subject_id,
                    r.relation,
                    r.object_type,
                    r.object_id,
                    removed
                );
            }
            println!("{} relation(s)", resp.relations.len());
        }
        RelationCommands::Check {
            user_id,
            relation,
            object_type,
            object_id,
            server,
        } => {
            let addr = cli::tcp_client::get_server_addr(server.as_deref());
            let key = cli::tcp_client::get_api_key();
            let req = liblinkkeys::generated::types::CheckPermissionRequest {
                user_id: user_id.clone(),
                relation: relation.clone(),
                object_type: object_type.clone(),
                object_id: object_id.clone(),
            };

            let resp = tcp_call(
                &addr,
                "Admin",
                "check-permission",
                &req,
                &key,
                liblinkkeys::generated::encode_check_permission_request,
                liblinkkeys::generated::decode_check_permission_response,
            );

            if resp.allowed {
                println!(
                    "ALLOWED: user {} has {} on {} {}",
                    user_id, relation, object_type, object_id
                );
            } else {
                println!(
                    "DENIED: user {} does not have {} on {} {}",
                    user_id, relation, object_type, object_id
                );
            }
        }
    }
}

fn handle_account_command(cmd: AccountCommands) {
    match cmd {
        AccountCommands::ChangePassword { server } => {
            let addr = cli::tcp_client::get_server_addr(server.as_deref());
            let key = cli::tcp_client::get_api_key();

            eprint!("Enter new password: ");
            let mut password = String::new();
            std::io::stdin()
                .read_line(&mut password)
                .expect("Failed to read password");
            let password = password.trim().to_string();
            if password.is_empty() {
                eprintln!("Error: password cannot be empty");
                std::process::exit(1);
            }

            let req = liblinkkeys::generated::types::ChangePasswordRequest {
                new_password: password,
            };

            let resp = tcp_call(
                &addr,
                "Account",
                "change-password",
                &req,
                &key,
                liblinkkeys::generated::encode_change_password_request,
                liblinkkeys::generated::decode_change_password_response,
            );

            if resp.success {
                println!("Password changed successfully.");
            } else {
                eprintln!("Password change failed.");
                std::process::exit(1);
            }
        }
        AccountCommands::MyInfo { server } => {
            let addr = cli::tcp_client::get_server_addr(server.as_deref());
            let key = cli::tcp_client::get_api_key();

            // GetMyInfo has no request fields, send an empty request.
            let req = liblinkkeys::generated::types::EmptyRequest {};

            let resp = tcp_call(
                &addr,
                "Account",
                "get-my-info",
                &req,
                &key,
                liblinkkeys::generated::encode_empty_request,
                liblinkkeys::generated::decode_get_my_info_response,
            );

            println!(
                "User: {} {} ({})",
                resp.user.id, resp.user.username, resp.user.display_name
            );
            if !resp.relations.is_empty() {
                println!("Relations:");
                for r in &resp.relations {
                    println!(
                        "  {} ({} {} -> {} {} {})",
                        r.id, r.subject_type, r.subject_id, r.relation, r.object_type, r.object_id
                    );
                }
            }
            if !resp.claims.is_empty() {
                println!("Claims:");
                for c in &resp.claims {
                    let value = String::from_utf8(c.claim_value.clone())
                        .unwrap_or_else(|_| format!("<{} bytes>", c.claim_value.len()));
                    println!("  {} {}={}", c.claim_id, c.claim_type, value);
                }
            }
        }
    }
}

fn claim_set(user_id: &str, claim_type: &str, claim_value: &str, expires: Option<&str>) {
    let passphrase = get_passphrase();
    let db_pool = pool_with_migrations();

    let domain_keys = db_pool.list_active_domain_keys().unwrap_or_else(|e| {
        eprintln!("Failed to list domain keys: {}", e);
        std::process::exit(1);
    });

    // Sign with every active domain key (>=3 by design) for a quorum of signatures.
    let signers = linkkeys::claim_signing::active_signers(&domain_keys, passphrase.as_bytes())
        .unwrap_or_else(|e| {
            eprintln!("Failed to prepare signing keys: {}", e);
            std::process::exit(1);
        });

    use chrono::Timelike;
    let expires_chrono = expires.map(|s| {
        chrono::DateTime::parse_from_rfc3339(s)
            .unwrap_or_else(|e| {
                eprintln!("Invalid --expires timestamp: {}", e);
                std::process::exit(1);
            })
            .with_timezone(&chrono::Utc)
            // Whole-second normalization so the signed expires_at round-trips
            // byte-identically through pg timestamptz / sqlite text (matches set_claim).
            .with_nanosecond(0)
            .unwrap()
    });

    let claim_value_bytes = claim_value.as_bytes();
    let claim_id = uuid::Uuid::now_v7().to_string();
    let expires_str = expires_chrono.as_ref().map(|e| e.to_rfc3339());
    let attested_chrono = chrono::Utc::now().with_nanosecond(0).unwrap();
    let attested_str = attested_chrono.to_rfc3339();
    let subject_domain = linkkeys::conversions::get_domain_name();
    let claim = linkkeys::claim_signing::sign_with_active(
        &liblinkkeys::claims::ClaimSpec {
            claim_id: &claim_id,
            claim_type,
            claim_value: claim_value_bytes,
            user_id,
            subject_domain: &subject_domain,
            expires_at: expires_str.as_deref(),
            attested_at: &attested_str,
        },
        &signers,
    )
    .unwrap_or_else(|e| {
        eprintln!("Failed to sign claim: {}", e);
        std::process::exit(1);
    });

    match db_pool.create_claim(
        &claim_id,
        user_id,
        claim_type,
        claim_value_bytes,
        &claim.signatures,
        expires_chrono,
        attested_chrono,
    ) {
        Ok(stored) => println!(
            "Claim set: id={} type={} signatures={}",
            stored.id,
            stored.claim_type,
            stored.signatures.len()
        ),
        Err(e) => {
            eprintln!("Failed to store claim: {}", e);
            std::process::exit(1);
        }
    }
}

async fn domain_dns_check() {
    use hickory_resolver::TokioAsyncResolver;
    use linkkeys::conversions::get_domain_name;

    let domain_name = get_domain_name();
    let db_pool = pool_with_migrations();

    // Get current domain keys for expected fingerprints
    let domain_keys = db_pool.list_active_domain_keys().unwrap_or_else(|e| {
        eprintln!("Failed to list domain keys: {}", e);
        std::process::exit(1);
    });

    // Only SIGNING keys are published in DNS. Encryption keys are trusted via a
    // signing-key vouch carried in the key-fetch, not via DNS fingerprints.
    let fingerprints: Vec<String> = domain_keys
        .iter()
        .filter(|k| k.key_usage == "sign")
        .map(|k| k.fingerprint.clone())
        .collect();

    // Build the expected endpoint values for the `_linkkeys_apis` record.
    // API_HOSTNAME overrides DOMAIN_NAME for the HTTPS URL (when the API is on a
    // subdomain). PUBLIC_PORT overrides HTTPS_PORT for URL construction (when
    // behind a gateway/LB). TCP_HOSTNAME / TCP_PORT locate the protocol service;
    // the TCP port is omitted from the advert when it is the spec default.
    let api_hostname = std::env::var("API_HOSTNAME").unwrap_or_else(|_| domain_name.clone());
    let public_port: u16 = std::env::var("PUBLIC_PORT")
        .or_else(|_| std::env::var("HTTPS_PORT"))
        .unwrap_or_else(|_| "8443".to_string())
        .parse()
        .unwrap_or(8443);
    let https_value = if public_port == 443 {
        api_hostname.clone()
    } else {
        format!("{}:{}", api_hostname, public_port)
    };

    let tcp_hostname = std::env::var("TCP_HOSTNAME").unwrap_or_else(|_| domain_name.clone());
    let tcp_port: u16 = std::env::var("TCP_PORT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(liblinkkeys::dns::DEFAULT_TCP_PORT);
    let tcp_value = if tcp_port == liblinkkeys::dns::DEFAULT_TCP_PORT {
        tcp_hostname.clone()
    } else {
        format!("{}:{}", tcp_hostname, tcp_port)
    };

    let apis_name = liblinkkeys::dns::linkkeys_apis_dns_name(&domain_name);
    let trust_name = liblinkkeys::dns::linkkeys_dns_name(&domain_name);

    println!("Domain: {}", domain_name);
    println!();

    // Show expected records.
    let expected_trust = liblinkkeys::dns::build_linkkeys_txt(&fingerprints);
    let expected_apis =
        liblinkkeys::dns::build_linkkeys_apis_txt(Some(&tcp_value), Some(&https_value));
    println!("Expected TXT records:");
    println!("  {} TXT \"{}\"", trust_name, expected_trust);
    println!("  {} TXT \"{}\"", apis_name, expected_apis);
    let warn_if_long = |label: &str, txt: &str| {
        if liblinkkeys::dns::txt_exceeds_single_string(txt) {
            println!(
                "  WARNING: the {} record is {} bytes, over the {}-byte single-string DNS TXT \
                 limit; it must be split into multiple strings, which some resolvers handle \
                 poorly. Consider shorter hostnames, default ports, or fewer keys.",
                label,
                txt.len(),
                liblinkkeys::dns::MAX_TXT_STRING_LEN
            );
        }
    };
    warn_if_long("_linkkeys", &expected_trust);
    warn_if_long("_linkkeys_apis", &expected_apis);
    println!();

    let resolver = TokioAsyncResolver::tokio_from_system_conf().unwrap_or_else(|e| {
        eprintln!("  Failed to create DNS resolver: {}", e);
        std::process::exit(1);
    });

    // -- Check the _linkkeys trust-anchor record (fingerprints) --
    println!("DNS lookup: {}", trust_name);
    match resolver.txt_lookup(&trust_name).await {
        Ok(response) => {
            let mut found = false;
            for record in response.iter() {
                let txt_str = record.to_string();
                if let Ok(parsed) = liblinkkeys::dns::parse_linkkeys_txt(&txt_str) {
                    found = true;
                    println!("  TXT: \"{}\"", txt_str);
                    println!("    Fingerprints in DNS: {}", parsed.fingerprints.len());
                    for fp in &parsed.fingerprints {
                        let status = if fingerprints.contains(fp) {
                            "OK"
                        } else {
                            "NOT IN DB"
                        };
                        println!("      {} [{}]", fp, status);
                    }
                    let missing: Vec<&String> = fingerprints
                        .iter()
                        .filter(|fp| !parsed.fingerprints.contains(fp))
                        .collect();
                    if !missing.is_empty() {
                        println!("    Missing from DNS ({}):", missing.len());
                        for fp in missing {
                            println!("      {}", fp);
                        }
                    }
                }
            }
            if !found {
                println!("  No valid _linkkeys record found. Add the expected record above.");
            }
        }
        Err(e) => println!(
            "  No TXT records found: {} (add the expected record above)",
            e
        ),
    }
    println!();

    // -- Check the _linkkeys_apis endpoint record (tcp/https) --
    println!("DNS lookup: {}", apis_name);
    match resolver.txt_lookup(&apis_name).await {
        Ok(response) => {
            let mut found = false;
            for record in response.iter() {
                let txt_str = record.to_string();
                if let Ok(parsed) = liblinkkeys::dns::parse_linkkeys_apis_txt(&txt_str) {
                    found = true;
                    println!("  TXT: \"{}\"", txt_str);
                    println!("    tcp:   {}", parsed.tcp.as_deref().unwrap_or("(none)"));
                    println!(
                        "    https: {}",
                        parsed.https_base.as_deref().unwrap_or("(none)")
                    );
                }
            }
            if !found {
                println!("  No valid _linkkeys_apis record found. Add the expected record above.");
            }
        }
        Err(e) => println!(
            "  No TXT records found: {} (add the expected record above)",
            e
        ),
    }

    println!();
    println!("Active domain keys: {}", domain_keys.len());
    for dk in &domain_keys {
        println!(
            "  {} fingerprint={} expires={}",
            dk.id, dk.fingerprint, dk.expires_at
        );
    }
}
