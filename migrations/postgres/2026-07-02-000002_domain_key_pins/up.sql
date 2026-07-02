-- TOFU pin of each peer domain's DNS fingerprint SET (SEC-01). `fingerprints`
-- is the sorted, comma-joined `fp=` set observed on first successful contact.
-- On later fetches the live DNS set is compared against this pin: an unexpected
-- change is refused (or, for a single-key rotation, accepted and re-pinned).
CREATE TABLE domain_key_pins (
    domain VARCHAR PRIMARY KEY,
    fingerprints VARCHAR NOT NULL,
    pinned_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_checked_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
