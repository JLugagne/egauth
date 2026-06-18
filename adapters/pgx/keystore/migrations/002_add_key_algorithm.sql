-- Add the signing algorithm column. Existing rows are HMAC (HS256); the secret column for an
-- asymmetric key holds the sealed PKCS#8 DER of the private key instead of a raw HMAC secret.
ALTER TABLE keystore_keys ADD COLUMN IF NOT EXISTS alg TEXT NOT NULL DEFAULT 'HS256';
