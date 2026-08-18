//! Domain-key maintenance: re-vouching encryption keys after a vouch-tag
//! epoch change.
//!
//! A signing key vouches for an encryption key exactly once, at creation, under
//! the then-current domain-separation tag (`KEY_VOUCH_TAG`). When the tag's
//! epoch changes (e.g. `-v1` → `-v1alpha`), every stored vouch stops verifying
//! on current peers and cross-domain logins fail at the encryption step. The
//! alpha policy is to re-sign, not to accept old tags — this module re-signs.

use crate::db::models::DomainKey;
use crate::db::DbPool;
use liblinkkeys::generated::types::DomainPublicKey;

/// What happened to one encryption key during a re-vouch pass.
#[derive(Debug, PartialEq, Eq)]
pub enum RevouchOutcome {
    /// The stored vouch already verifies under the current tag.
    AlreadyValid,
    /// A new vouch was signed and stored, by the named signing key.
    Revouched { signed_by_key_id: String },
}

/// Verify every non-revoked encryption key's stored vouch under the current
/// tag and re-sign any that fail, storing the new signature. Idempotent: a
/// second run finds every vouch valid and changes nothing.
///
/// The vouch covers the exact `expires_at` string the key is served with, so
/// the payload is rebuilt from the model's string fields — the same values
/// `DomainPublicKey` carries to verifiers.
///
/// Returns one `(key_id, outcome)` per encryption key, or an error message
/// when a key cannot be re-vouched (no active signing key, wrong passphrase,
/// storage failure). Signing keys need no vouch; they are DNS-pinned.
pub fn revouch_encryption_keys(
    pool: &DbPool,
    passphrase: &str,
) -> Result<Vec<(String, RevouchOutcome)>, String> {
    let all_keys = pool
        .list_all_domain_keys()
        .map_err(|e| format!("could not list domain keys: {e}"))?;

    let signing_keys: Vec<&DomainKey> = all_keys
        .iter()
        .filter(|k| {
            k.key_usage == "sign"
                && liblinkkeys::crypto::signing_key_validity(&k.expires_at, k.revoked_at.as_deref())
                    == liblinkkeys::crypto::KeyValidity::Valid
        })
        .collect();

    let mut results = Vec::new();
    for enc in all_keys
        .iter()
        .filter(|k| k.key_usage == "encrypt" && k.revoked_at.is_none())
    {
        let enc_pub: DomainPublicKey = enc.into();

        // Valid under the current tag when the named signer still vouches.
        let named_signer = enc
            .signed_by_key_id
            .as_deref()
            .and_then(|id| signing_keys.iter().find(|s| s.id == id));
        if let Some(signer) = named_signer {
            let signer_pub: DomainPublicKey = (*signer).into();
            if liblinkkeys::dns::verify_key_vouch(&enc_pub, &signer_pub) {
                results.push((enc.id.clone(), RevouchOutcome::AlreadyValid));
                continue;
            }
        }

        // Re-sign: prefer the originally named signer when it is still active,
        // else any active signing key.
        let signer = named_signer
            .copied()
            .or_else(|| signing_keys.first().copied())
            .ok_or_else(|| {
                format!(
                    "encryption key {} needs a re-vouch but no active signing key exists",
                    enc.id
                )
            })?;
        let signer_sk = liblinkkeys::crypto::decrypt_private_key(
            &signer.private_key_encrypted,
            passphrase.as_bytes(),
        )
        .map_err(|e| format!("could not decrypt signing key {}: {e}", signer.id))?;
        let signer_alg = liblinkkeys::crypto::SigningAlgorithm::parse_str(&signer.algorithm)
            .ok_or_else(|| {
                format!(
                    "signing key {} has unsupported algorithm {}",
                    signer.id, signer.algorithm
                )
            })?;
        // Sign over the recomputed fingerprint, exactly as verifiers recompute it.
        let fp = liblinkkeys::crypto::fingerprint(&enc.public_key);
        let vouch = liblinkkeys::dns::sign_key_vouch(&fp, &enc.expires_at, signer_alg, &signer_sk)
            .map_err(|e| format!("could not sign vouch for key {}: {e}", enc.id))?;
        pool.update_domain_key_vouch(&enc.id, &signer.id, &vouch)
            .map_err(|e| format!("could not store new vouch for key {}: {e}", enc.id))?;
        results.push((
            enc.id.clone(),
            RevouchOutcome::Revouched {
                signed_by_key_id: signer.id.clone(),
            },
        ));
    }
    Ok(results)
}

/// Startup self-heal: run a re-vouch pass and log the outcome. Never fatal —
/// a domain that cannot re-vouch (e.g. no passphrase in the environment) still
/// serves; same-instance flows do not need the vouch.
pub fn revouch_on_startup(pool: &DbPool) {
    let passphrase = match std::env::var("DOMAIN_KEY_PASSPHRASE") {
        Ok(p) => p,
        Err(_) => {
            log::warn!(
                "DOMAIN_KEY_PASSPHRASE not set; skipping encryption-key vouch check at startup"
            );
            return;
        }
    };
    match revouch_encryption_keys(pool, &passphrase) {
        Ok(results) => {
            for (key_id, outcome) in results {
                if let RevouchOutcome::Revouched { signed_by_key_id } = outcome {
                    log::info!(
                        "re-vouched encryption key {key_id} under the current vouch tag \
                         (signed by {signed_by_key_id})"
                    );
                }
            }
        }
        Err(e) => log::error!("encryption-key vouch check failed at startup: {e}"),
    }
}
