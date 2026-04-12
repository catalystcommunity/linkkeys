extern crate rocket;

mod cli;
mod dns;
mod tcp;
mod web;

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

            web::launch_rocket(db_pool, ready_flag).await;
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

fn generate_and_store_keypairs(
    db_pool: &linkkeys::db::DbPool,
    passphrase: &str,
    staggered_years: &[i64],
    store_fn: &dyn Fn(
        &linkkeys::db::DbPool,
        &[u8],
        &[u8],
        &str,
        chrono::DateTime<chrono::Utc>,
    ) -> Result<GeneratedKey, String>,
) {
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

fn domain_init() {
    let passphrase = get_passphrase();
    let db_pool = pool_with_migrations();

    println!("Generating 3 domain keypairs...");
    generate_and_store_keypairs(&db_pool, &passphrase, &[2, 3, 4], &|pool, pk, enc, fp, exp| {
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
    println!("Domain initialized with 3 keys.");
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
        &|pool, pk, enc, fp, exp| match pool {
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

    let domain_key = db_pool
        .list_active_domain_keys()
        .unwrap_or_else(|e| {
            eprintln!("Failed to list domain keys: {}", e);
            std::process::exit(1);
        })
        .into_iter()
        .next()
        .unwrap_or_else(|| {
            eprintln!("No active domain keys found. Run 'domain init' first.");
            std::process::exit(1);
        });

    let sk_bytes = liblinkkeys::crypto::decrypt_private_key(
        &domain_key.private_key_encrypted,
        passphrase.as_bytes(),
    )
    .unwrap_or_else(|e| {
        eprintln!("Failed to decrypt domain key: {}", e);
        std::process::exit(1);
    });

    let algorithm = liblinkkeys::crypto::SigningAlgorithm::from_str(&domain_key.algorithm)
        .unwrap_or_else(|| {
            eprintln!("Unsupported algorithm: {}", domain_key.algorithm);
            std::process::exit(1);
        });

    let expires_chrono = expires.map(|s| {
        chrono::DateTime::parse_from_rfc3339(s)
            .unwrap_or_else(|e| {
                eprintln!("Invalid --expires timestamp: {}", e);
                std::process::exit(1);
            })
            .with_timezone(&chrono::Utc)
    });

    let claim_value_bytes = claim_value.as_bytes();
    let claim = liblinkkeys::claims::sign_claim(
        &uuid::Uuid::now_v7().to_string(),
        claim_type,
        claim_value_bytes,
        user_id,
        &domain_key.id,
        algorithm,
        &sk_bytes,
        expires_chrono.as_ref().map(|e| e.to_rfc3339()).as_deref(),
    )
    .unwrap_or_else(|e| {
        eprintln!("Failed to sign claim: {}", e);
        std::process::exit(1);
    });

    let result = match &db_pool {
        #[cfg(feature = "postgres")]
        linkkeys::db::DbPool::Postgres(pool) => {
            let mut conn = pool.get().expect("Failed to get connection");
            let uid: uuid::Uuid = user_id.parse().unwrap_or_else(|_| {
                eprintln!("Invalid user UUID");
                std::process::exit(1);
            });
            let key_id: uuid::Uuid = domain_key.id.parse().expect("Invalid key UUID");
            linkkeys::db::claims::pg::create(
                &mut conn,
                uid,
                claim_type,
                claim_value_bytes,
                key_id,
                &claim.signature,
                expires_chrono,
            )
        }
        #[cfg(feature = "sqlite")]
        linkkeys::db::DbPool::Sqlite(pool) => {
            let mut conn = pool.get().expect("Failed to get connection");
            linkkeys::db::claims::sqlite::create(
                &mut conn,
                user_id,
                claim_type,
                claim_value_bytes,
                &domain_key.id,
                &claim.signature,
                expires,
            )
        }
    };

    match result {
        Ok(stored) => println!(
            "Claim set: id={} type={} signed_by={}",
            stored.id, stored.claim_type, stored.signed_by_key_id
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

    let fingerprints: Vec<String> = domain_keys.iter().map(|k| k.fingerprint.clone()).collect();

    // Build the expected API base URL.
    // API_HOSTNAME overrides DOMAIN_NAME for the URL (when API is on a subdomain).
    // PUBLIC_PORT overrides HTTPS_PORT for URL construction (when behind a gateway/LB).
    let api_hostname = std::env::var("API_HOSTNAME").unwrap_or_else(|_| domain_name.clone());
    let public_port: u16 = std::env::var("PUBLIC_PORT")
        .or_else(|_| std::env::var("HTTPS_PORT"))
        .unwrap_or_else(|_| "8443".to_string())
        .parse()
        .unwrap_or(8443);
    let api_base = if public_port == 443 {
        format!("https://{}", api_hostname)
    } else {
        format!("https://{}:{}", api_hostname, public_port)
    };

    println!("Domain: {}", domain_name);
    println!(
        "DNS name: {}",
        liblinkkeys::dns::linkkeys_dns_name(&domain_name)
    );
    println!();

    // Show expected record
    let expected_txt = liblinkkeys::dns::build_linkkeys_txt(&api_base, &fingerprints);
    println!("Expected TXT record:");
    println!(
        "  {} TXT \"{}\"",
        liblinkkeys::dns::linkkeys_dns_name(&domain_name),
        expected_txt
    );
    println!();

    // Look up actual DNS
    println!("DNS lookup results:");
    let dns_name = liblinkkeys::dns::linkkeys_dns_name(&domain_name);

    let resolver = TokioAsyncResolver::tokio_from_system_conf().unwrap_or_else(|e| {
        eprintln!("  Failed to create DNS resolver: {}", e);
        std::process::exit(1);
    });

    match resolver.txt_lookup(&dns_name).await {
        Ok(response) => {
            let mut found_linkkeys = false;
            for record in response.iter() {
                let txt_str = record.to_string();
                println!("  TXT: \"{}\"", txt_str);

                match liblinkkeys::dns::parse_linkkeys_txt(&txt_str) {
                    Ok(parsed) => {
                        found_linkkeys = true;
                        println!();
                        println!("  Parsed LinkKeys record:");
                        println!("    API base: {}", parsed.api_base);
                        if parsed.api_base != api_base {
                            println!(
                                "    WARNING: API base doesn't match expected ({})",
                                api_base
                            );
                        }

                        println!("    Fingerprints in DNS: {}", parsed.fingerprints.len());
                        for fp in &parsed.fingerprints {
                            let status = if fingerprints.contains(fp) {
                                "OK"
                            } else {
                                "NOT IN DB"
                            };
                            println!("      {} [{}]", fp, status);
                        }

                        // Check for DB keys missing from DNS
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
                    Err(_) => {
                        // Not a linkkeys record, skip
                    }
                }
            }

            if !found_linkkeys {
                println!();
                println!(
                    "  No LinkKeys TXT record found among {} record(s).",
                    response.iter().count()
                );
                println!("  Add the expected TXT record shown above to your DNS.");
            }
        }
        Err(e) => {
            println!("  No TXT records found: {}", e);
            println!();
            println!("  Add the expected TXT record shown above to your DNS.");
        }
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
