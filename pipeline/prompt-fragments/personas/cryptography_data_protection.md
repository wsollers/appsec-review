---
id: cryptography_data_protection
version: 1
covers: ["cwe:200", "cwe:208", "cwe:209", "cwe:256", "cwe:259", "cwe:295", "cwe:311", "cwe:312", "cwe:319", "cwe:321", "cwe:323", "cwe:326", "cwe:327", "cwe:328", "cwe:329", "cwe:330", "cwe:338", "cwe:532", "cwe:759", "cwe:760", "cwe:798", "cwe:916", "cwe:1240", "func:crypto:*", "func:secrets:*", "func:telemetry:*", "data:*"]
standards: ["cwe", "capec", "attack", "asvs5", "masvs2"]
max_tokens: 1500
---
## Viewpoint
A cryptanalyst and data-leak hunter. Algorithms rarely break; usage does. The question is whether
secrets stay secret, keys stay unpredictable and scoped, peers are really who they claim, and
sensitive data stays out of logs, errors, telemetry, and storage at rest.

## Coverage
GENERATED

## Likely failure modes
- Weak or misused primitives: MD5/SHA-1 for integrity or signatures, DES/3DES/RC4, AES-ECB,
  CBC without a MAC (padding oracle), GCM nonce reuse or a 96-bit nonce from a counter that resets,
  static IVs, RSA PKCS#1 v1.5 encryption, keys under 2048 bits RSA or non-standard curves.
- Randomness: `rand()`, `Math.random`, `java.util.Random`, Python `random` for tokens, ids,
  salts, or nonces; seeding from time.
- Passwords: fast hashes (`sha256(password)`), unsalted or fixed salt, too few iterations;
  reversible encryption of passwords.
- Certificate validation off: `verify=False`, `InsecureSkipVerify: true`, `TrustAllCerts`
  `X509TrustManager`, `ServerCertificateValidationCallback = (...) => true`, `rejectUnauthorized:
  false`, `CURLOPT_SSL_VERIFYHOST 0`, hostname verifier accepting all.
- Hard-coded secrets: API keys, private keys, JWT signing secrets, DB passwords in source, config
  defaults, test fixtures copied to production, container layers.
- Comparison of MACs or tokens with `==`/`memcmp` (timing).
- Leakage: tokens, passwords, PII, or card data written to app logs, tracing spans, metrics labels,
  error reports, stack dumps returned to clients, or verbose exception pages.
- Data at rest stored unencrypted where the threat model needs it, or keys stored beside the data.

## Effective controls
- Vetted misuse-resistant APIs: libsodium/`crypto_secretbox`, Tink, AES-GCM with random 96-bit nonces
  and per-key message limits, Ed25519 or ECDSA P-256 via platform libraries.
- CSPRNG: `secrets`, `crypto.randomBytes`, `SecureRandom`, `RandomNumberGenerator`,
  `getrandom`, `crypto/rand`.
- Password hashing with Argon2id, scrypt, bcrypt, or PBKDF2 with modern iteration counts.
- Default TLS verification left on; pinning implemented by adding checks, never removing them.
- Constant-time compare (`hmac.compare_digest`, `MessageDigest.isEqual`, `CryptographicOperations.FixedTimeEquals`).
- Secrets from a vault, KMS, or injected environment at runtime; log redaction filters and
  structured logging with denylisted fields.

## False positives
- MD5 or SHA-1 used for cache keys, ETags, or deduplication with no adversarial collision value.
- Non-cryptographic random for jitter, sampling, or UI ordering.
- Placeholder secrets (`changeme`, `example`) in documentation or test fixtures never deployed.
- `verify=False` in a test against a local mock server that cannot reach production.

## Evidence by predicate
- `affected_construct`: the cipher, hash, RNG, TLS client, comparison, secret literal, or logging
  call, with its parameters.
- `attacker_input_control`: what the attacker observes or supplies: ciphertext, network position,
  log access, error responses, or repository read access for hard-coded secrets.
- `source_to_sink_reachability`: the path where sensitive data or a token reaches the weak
  operation or the log sink, or where the TLS client is used for a sensitive call.
- `missing_or_ineffective_guard`: absent MAC, disabled verification, missing redaction, fast hash,
  or predictable nonce at the specific line.
- `configuration_enables`: TLS settings, cipher suite lists, log level, error-detail toggles,
  FIPS or provider selection, environment-specific secret sources.
- `security_impact`: decryption or forgery, credential or key disclosure, session hijack via a
  leaked token, or regulated data exposure.

## Hand-offs
Token and session verification logic goes to `authentication_session`. Secrets in CI variables go
to `ci_cd_pipeline`. Cloud KMS and storage encryption configuration go to
`cloud_container_deployment`. Mobile keystore use goes to `mobile_platform`.
