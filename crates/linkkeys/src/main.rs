extern crate rocket;

mod cli;
mod dns;
mod tcp;

use clap::Parser;
use cli::{
    AccountCommands, Cli, ClaimCommands, Commands, DomainCommands, RelationCommands, UserCommands,
};
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::thread;

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
                    linkkeys::db::run_migrations_with_locking(&pool, flag);
                    resign_legacy_claims_on_startup(&pool);
                });
            }

            {
                let flag = ready_flag.clone();
                let pool = db_pool.clone();
                thread::spawn(move || match tcp::TcpServer::new(flag, pool) {
                    Ok(server) => server.run(),
                    Err(e) => log::error!("Failed to start TCP server: {}", e),
                });
            }

            linkkeys::web::launch_rocket(db_pool, ready_flag).await;
        }

        Commands::Domain(DomainCommands::Init) => domain_init(),
        Commands::Domain(DomainCommands::DnsCheck) => domain_dns_check().await,
        Commands::User(UserCommands::Create {
            username,
            display_name,
            password,
            api_key,
            admin,
        }) => {
            user_create(&username, &display_name, password.as_deref(), api_key, admin);
        }
        Commands::User(UserCommands::List { server }) => user_list(server.as_deref()),
        Commands::User(UserCommands::Update {
            user_id,
            display_name,
            server,
        }) => user_update(&user_id, display_name.as_deref(), server.as_deref()),
        Commands::User(UserCommands::Deactivate { user_id, server }) => {
            user_deactivate(&user_id, server.as_deref())
        }
        Commands::User(UserCommands::ResetPassword { user_id, server }) => {
            user_reset_password(&user_id, server.as_deref())
        }
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
    }
}

/// TEMPORARY (added 2026-06-14, pre-alpha): re-sign claims that the
/// claim_signatures migration left unsigned.
///
/// That migration dropped the old single-signature columns without porting their
/// (now domain-unbound, payload-incompatible) values, so pre-existing claims have
/// no signatures until re-signed with the domain's active keys. Idempotent:
/// claims that already carry signatures are skipped, so this is a no-op on every
/// boot after the first. Failures here are logged but never fatal — a server with
/// no domain keys or passphrase (e.g. RP-only) simply skips. Remove once all
/// deployments have moved past pre-alpha.
fn resign_legacy_claims_on_startup(pool: &linkkeys::db::DbPool) {
    let claims = match pool.list_claims_missing_signatures() {
        Ok(c) => c,
        Err(e) => {
            log::error!("re-sign backfill: failed to list unsigned claims: {}", e);
            return;
        }
    };
    if claims.is_empty() {
        return;
    }

    let passphrase = match std::env::var("DOMAIN_KEY_PASSPHRASE") {
        Ok(p) => p,
        Err(_) => {
            log::warn!(
                "re-sign backfill: {} claim(s) need re-signing but DOMAIN_KEY_PASSPHRASE \
                 is not set; skipping",
                claims.len()
            );
            return;
        }
    };

    let domain_keys = match pool.list_active_domain_keys() {
        Ok(k) => k,
        Err(e) => {
            log::error!("re-sign backfill: failed to list domain keys: {}", e);
            return;
        }
    };
    let signers = match linkkeys::claim_signing::active_signers(&domain_keys, passphrase.as_bytes())
    {
        Ok(s) => s,
        Err(e) => {
            log::warn!("re-sign backfill: cannot sign ({}); skipping", e);
            return;
        }
    };

    let mut resigned = 0usize;
    for c in &claims {
        let spec = liblinkkeys::claims::ClaimSpec {
            claim_id: &c.id,
            claim_type: &c.claim_type,
            claim_value: &c.claim_value,
            user_id: &c.user_id,
            expires_at: c.expires_at.as_deref(),
        };
        let signed = match linkkeys::claim_signing::sign_with_active(&spec, &signers) {
            Ok(s) => s,
            Err(e) => {
                log::error!("re-sign backfill: failed to sign claim {}: {}", c.id, e);
                continue;
            }
        };
        if let Err(e) = pool.replace_claim_signatures(&c.id, &signed.signatures) {
            log::error!("re-sign backfill: failed to store signatures for {}: {}", c.id, e);
            continue;
        }
        resigned += 1;
    }
    log::info!("re-sign backfill: re-signed {} legacy claim(s)", resigned);
}

fn get_passphrase() -> String {
    std::env::var("DOMAIN_KEY_PASSPHRASE").unwrap_or_else(|_| {
        eprintln!("Error: DOMAIN_KEY_PASSPHRASE environment variable is required");
        std::process::exit(1);
    })
}

fn pool_with_migrations() -> linkkeys::db::DbPool {
    let pool = linkkeys::db::create_pool();
    let flag = Arc::new(AtomicBool::new(false));
    linkkeys::db::run_migrations_with_locking(&pool, flag);
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

/// Generate the domain's three staggered-expiry Ed25519 signing keypairs.
fn generate_signing_keys(db_pool: &linkkeys::db::DbPool, passphrase: &str) {
    println!("Generating 3 domain keypairs...");
    generate_and_store_keypairs(db_pool, passphrase, &[2, 3, 4], |pool, pk, enc, fp, exp| {
        match pool {
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
        }
    });
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
    let signer_sk =
        liblinkkeys::crypto::decrypt_private_key(&signer.private_key_encrypted, passphrase.as_bytes())
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

    let vouch =
        liblinkkeys::dns::sign_key_vouch(&enc_fp, &expires_str, signer_alg, &signer_sk)
            .expect("Failed to sign encryption-key vouch");

    let result = match db_pool {
        #[cfg(feature = "postgres")]
        linkkeys::db::DbPool::Postgres(p) => {
            let mut conn = p.get().expect("Failed to get connection");
            linkkeys::db::domain_keys::pg::create_encryption_key(
                &mut conn, &enc_pub, &enc_priv_encrypted, &enc_fp, &signer.id, &vouch, expires,
            )
            .map(|k| k.id)
            .map_err(|e| e.to_string())
        }
        #[cfg(feature = "sqlite")]
        linkkeys::db::DbPool::Sqlite(p) => {
            let mut conn = p.get().expect("Failed to get connection");
            linkkeys::db::domain_keys::sqlite::create_encryption_key(
                &mut conn, &enc_pub, &enc_priv_encrypted, &enc_fp, &signer.id, &vouch, &expires_str,
            )
            .map(|k| k.id)
            .map_err(|e| e.to_string())
        }
    };
    match result {
        Ok(id) => println!("  Encryption key {}: fingerprint={} (vouched by {})", id, enc_fp, signer.id),
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
) {
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

    if admin {
        let domain = linkkeys::conversions::get_domain_name();
        match db_pool.create_relation("user", &user.id, "admin", "domain", &domain) {
            Ok(rel) => println!("Admin relation granted: id={}", rel.id),
            Err(e) => {
                eprintln!("Failed to grant admin relation: {}", e);
                std::process::exit(1);
            }
        }
    }
}

// --- TCP-based command handlers ---

fn user_list(server: Option<&str>) {
    let addr = cli::tcp_client::get_server_addr(server);
    let key = cli::tcp_client::get_api_key();
    let req = liblinkkeys::generated::types::ListUsersRequest {
        offset: None,
        limit: None,
    };

    let resp: liblinkkeys::generated::types::ListUsersResponse =
        cli::tcp_client::send_request(&addr, "Admin", "list-users", &req, Some(&key))
            .unwrap_or_else(|e| {
                eprintln!("Error: {}", e);
                std::process::exit(1);
            });

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

    let resp: liblinkkeys::generated::types::UpdateUserResponse =
        cli::tcp_client::send_request(&addr, "Admin", "update-user", &req, Some(&key))
            .unwrap_or_else(|e| {
                eprintln!("Error: {}", e);
                std::process::exit(1);
            });

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

    let resp: liblinkkeys::generated::types::DeactivateUserResponse =
        cli::tcp_client::send_request(&addr, "Admin", "deactivate-user", &req, Some(&key))
            .unwrap_or_else(|e| {
                eprintln!("Error: {}", e);
                std::process::exit(1);
            });

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

    let resp: liblinkkeys::generated::types::ResetPasswordResponse =
        cli::tcp_client::send_request(&addr, "Admin", "reset-password", &req, Some(&key))
            .unwrap_or_else(|e| {
                eprintln!("Error: {}", e);
                std::process::exit(1);
            });

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

    let resp: liblinkkeys::generated::types::RemoveClaimResponse =
        cli::tcp_client::send_request(&addr, "Admin", "remove-claim", &req, Some(&key))
            .unwrap_or_else(|e| {
                eprintln!("Error: {}", e);
                std::process::exit(1);
            });

    if resp.success {
        println!("Claim removed.");
    } else {
        eprintln!("Claim removal failed.");
        std::process::exit(1);
    }
}

fn handle_relation_command(cmd: RelationCommands) {
    match cmd {
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

            let resp: liblinkkeys::generated::types::GrantRelationResponse =
                cli::tcp_client::send_request(&addr, "Admin", "grant-relation", &req, Some(&key))
                    .unwrap_or_else(|e| {
                        eprintln!("Error: {}", e);
                        std::process::exit(1);
                    });

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

            let resp: liblinkkeys::generated::types::RemoveRelationResponse =
                cli::tcp_client::send_request(&addr, "Admin", "remove-relation", &req, Some(&key))
                    .unwrap_or_else(|e| {
                        eprintln!("Error: {}", e);
                        std::process::exit(1);
                    });

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

            let resp: liblinkkeys::generated::types::ListRelationsResponse =
                cli::tcp_client::send_request(&addr, "Admin", "list-relations", &req, Some(&key))
                    .unwrap_or_else(|e| {
                        eprintln!("Error: {}", e);
                        std::process::exit(1);
                    });

            for r in &resp.relations {
                let removed = r
                    .removed_at
                    .as_ref()
                    .map(|t| format!(" [removed {}]", t))
                    .unwrap_or_default();
                println!(
                    "  {} ({} {} -> {} {} {}){}",
                    r.id, r.subject_type, r.subject_id, r.relation, r.object_type, r.object_id,
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

            let resp: liblinkkeys::generated::types::CheckPermissionResponse =
                cli::tcp_client::send_request(
                    &addr,
                    "Admin",
                    "check-permission",
                    &req,
                    Some(&key),
                )
                .unwrap_or_else(|e| {
                    eprintln!("Error: {}", e);
                    std::process::exit(1);
                });

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

            let resp: liblinkkeys::generated::types::ChangePasswordResponse =
                cli::tcp_client::send_request(&addr, "Account", "change-password", &req, Some(&key))
                    .unwrap_or_else(|e| {
                        eprintln!("Error: {}", e);
                        std::process::exit(1);
                    });

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

            // GetMyInfo has no request fields, send an empty map
            let req = std::collections::HashMap::<String, String>::new();

            let resp: liblinkkeys::generated::types::GetMyInfoResponse =
                cli::tcp_client::send_request(&addr, "Account", "get-my-info", &req, Some(&key))
                    .unwrap_or_else(|e| {
                        eprintln!("Error: {}", e);
                        std::process::exit(1);
                    });

            println!("User: {} {} ({})", resp.user.id, resp.user.username, resp.user.display_name);
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
    let claim = linkkeys::claim_signing::sign_with_active(
        &liblinkkeys::claims::ClaimSpec {
            claim_id: &claim_id,
            claim_type,
            claim_value: claim_value_bytes,
            user_id,
            expires_at: expires_str.as_deref(),
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
                        let status = if fingerprints.contains(fp) { "OK" } else { "NOT IN DB" };
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
        Err(e) => println!("  No TXT records found: {} (add the expected record above)", e),
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
                    println!("    https: {}", parsed.https_base.as_deref().unwrap_or("(none)"));
                }
            }
            if !found {
                println!("  No valid _linkkeys_apis record found. Add the expected record above.");
            }
        }
        Err(e) => println!("  No TXT records found: {} (add the expected record above)", e),
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
