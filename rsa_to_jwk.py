#!/usr/bin/env python3
"""
rsa_to_jwk.py

Convertit une clé publique RSA (PEM ou DER) en JWK (JSON Web Key),
au format JWKS attendu par la plupart des serveurs OAuth/OIDC.

Usage:
    python3 rsa_to_jwk.py public_key.pem [-o jwks.json] [--kid my-key] [--alg RS256]

Supporte aussi les clés au format:
    - PEM public key ("-----BEGIN PUBLIC KEY-----")
    - PEM certificat X.509 ("-----BEGIN CERTIFICATE-----")
"""

import argparse
import base64
import hashlib
import json
import sys
from pathlib import Path

from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from cryptography import x509


def b64url_uint(value: int) -> str:
    """Encode un entier en base64url (sans padding), format requis par JWK."""
    byte_length = (value.bit_length() + 7) // 8
    raw = value.to_bytes(byte_length, byteorder="big")
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def load_rsa_public_key(data: bytes) -> RSAPublicKey:
    """Charge une clé publique RSA depuis du PEM (clé brute ou certificat)."""
    text = data.decode("utf-8", errors="ignore")

    if "BEGIN CERTIFICATE" in text:
        cert = x509.load_pem_x509_certificate(data)
        pub = cert.public_key()
    else:
        pub = load_pem_public_key(data)

    if not isinstance(pub, RSAPublicKey):
        raise ValueError("La clé fournie n'est pas une clé publique RSA.")
    return pub


def compute_kid(pub: RSAPublicKey) -> str:
    """Génère un kid déterministe basé sur un hash SHA-256 du modulus (utile si non fourni)."""
    numbers = pub.public_numbers()
    n_bytes = numbers.n.to_bytes((numbers.n.bit_length() + 7) // 8, "big")
    digest = hashlib.sha256(n_bytes).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")[:16]


def pubkey_to_jwk(pub: RSAPublicKey, kid: str, alg: str, use: str) -> dict:
    numbers = pub.public_numbers()
    return {
        "kty": "RSA",
        "e": b64url_uint(numbers.e),
        "use": use,
        "kid": kid,
        "alg": alg,
        "n": b64url_uint(numbers.n),
    }


def main():
    parser = argparse.ArgumentParser(description="Convertit une clé publique RSA (PEM) en JWK/JWKS.")
    parser.add_argument("input", help="Chemin du fichier contenant la clé publique (PEM ou certificat X.509)")
    parser.add_argument("-o", "--output", help="Fichier de sortie JSON (par défaut: stdout)")
    parser.add_argument("--kid", default=None, help="Key ID à utiliser (par défaut: dérivé du modulus)")
    parser.add_argument("--alg", default="RS256", help="Algorithme JWK (défaut: RS256)")
    parser.add_argument("--use", default="sig", help="Usage de la clé: 'sig' ou 'enc' (défaut: sig)")
    parser.add_argument("--pretty", action="store_true", help="Formatte le JSON avec indentation")
    args = parser.parse_args()

    input_path = Path(args.input)
    if not input_path.is_file():
        print(f"Erreur: fichier introuvable: {input_path}", file=sys.stderr)
        sys.exit(1)

    data = input_path.read_bytes()

    try:
        pub = load_rsa_public_key(data)
    except Exception as e:
        print(f"Erreur lors du chargement de la clé: {e}", file=sys.stderr)
        sys.exit(1)

    kid = args.kid or compute_kid(pub)
    jwk = pubkey_to_jwk(pub, kid=kid, alg=args.alg, use=args.use)

    jwks = {"keys": [jwk]}

    indent = 2 if args.pretty or args.output else None
    output_json = json.dumps(jwks, indent=indent)

    if args.output:
        Path(args.output).write_text(output_json + "\n")
        print(f"JWKS écrit dans: {args.output}")
    else:
        print(output_json)


if __name__ == "__main__":
    main()
