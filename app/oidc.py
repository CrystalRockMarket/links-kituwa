"""Pocket ID OIDC (authorization code + PKCE) for the operator console.

Only three things matter here: the ID token is signed by the issuer we trust,
it was minted for this client, and its `groups` claim contains the operator
group. Anything else is rejected with an explicit reason.
"""
from __future__ import annotations

import base64
import hashlib
import json
import secrets
import time
import urllib.error
import urllib.parse
import urllib.request

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa

DEFAULT_ISSUER = "https://auth.kituwa.com"
_JWKS_TTL = 600
_jwks_cache: dict[str, tuple[float, dict]] = {}


class OIDCError(Exception):
    pass


def _b64d(data: str) -> bytes:
    pad = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + pad)


def _get_json(url: str, timeout: int = 10) -> dict:
    req = urllib.request.Request(url, headers={"Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 (fixed issuer)
        return json.loads(resp.read().decode())


def discovery(issuer: str) -> dict:
    return _get_json(issuer.rstrip("/") + "/.well-known/openid-configuration")


def jwks(issuer: str, force: bool = False) -> dict:
    key = issuer.rstrip("/")
    hit = _jwks_cache.get(key)
    if hit and not force and time.time() - hit[0] < _JWKS_TTL:
        return hit[1]
    meta = discovery(key)
    data = _get_json(meta["jwks_uri"])
    _jwks_cache[key] = (time.time(), data)
    return data


def _pkce() -> tuple[str, str]:
    verifier = secrets.token_urlsafe(48)
    challenge = base64.urlsafe_b64encode(
        hashlib.sha256(verifier.encode()).digest()
    ).decode().rstrip("=")
    return verifier, challenge


def begin(issuer: str, client_id: str, redirect_uri: str) -> dict:
    """Return the authorize URL and the values that must survive to the callback."""
    meta = discovery(issuer)
    verifier, challenge = _pkce()
    state = secrets.token_urlsafe(24)
    nonce = secrets.token_urlsafe(24)
    params = {
        "response_type": "code",
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "scope": "openid profile email groups",
        "state": state,
        "nonce": nonce,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
    }
    return {
        "url": meta["authorization_endpoint"] + "?" + urllib.parse.urlencode(params),
        "state": state,
        "nonce": nonce,
        "verifier": verifier,
        "token_endpoint": meta["token_endpoint"],
    }


def exchange(token_endpoint: str, code: str, redirect_uri: str, client_id: str,
             client_secret: str, verifier: str) -> dict:
    body = urllib.parse.urlencode({
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": redirect_uri,
        "client_id": client_id,
        "client_secret": client_secret,
        "code_verifier": verifier,
    }).encode()
    req = urllib.request.Request(
        token_endpoint, data=body,
        headers={"Content-Type": "application/x-www-form-urlencoded",
                 "Accept": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:  # noqa: S310
            return json.loads(resp.read().decode())
    except urllib.error.HTTPError as exc:
        raise OIDCError(f"token endpoint returned {exc.code}") from exc


def _verify_signature(header: dict, signing_input: bytes, signature: bytes, keys: dict) -> None:
    kid = header.get("kid")
    jwk = None
    for key in keys.get("keys", []):
        if kid is None or key.get("kid") == kid:
            jwk = key
            break
    if jwk is None:
        raise OIDCError("no matching signing key")
    alg = header.get("alg", "RS256")
    digest = hashes.SHA256()
    if alg.startswith("RS"):
        n = int.from_bytes(_b64d(jwk["n"]), "big")
        e = int.from_bytes(_b64d(jwk["e"]), "big")
        pub = rsa.RSAPublicNumbers(e, n).public_key()
        try:
            pub.verify(signature, signing_input, padding.PKCS1v15(), digest)
        except InvalidSignature as exc:
            raise OIDCError("bad signature") from exc
    elif alg.startswith("ES"):
        crv = {"P-256": ec.SECP256R1, "P-384": ec.SECP384R1, "P-521": ec.SECP521R1}[jwk["crv"]]
        x = int.from_bytes(_b64d(jwk["x"]), "big")
        y = int.from_bytes(_b64d(jwk["y"]), "big")
        pub = ec.EllipticCurvePublicNumbers(x, y, crv()).public_key()
        try:
            pub.verify(signature, signing_input, ec.ECDSA(hashes.SHA256()))
        except InvalidSignature as exc:
            raise OIDCError("bad signature") from exc
    else:
        raise OIDCError(f"unsupported alg {alg}")


def verify_id_token(token: str, keys: dict, issuer: str, client_id: str,
                    nonce: str | None = None, now: float | None = None) -> dict:
    parts = token.split(".")
    if len(parts) != 3:
        raise OIDCError("malformed token")
    header = json.loads(_b64d(parts[0]))
    payload = json.loads(_b64d(parts[1]))
    signature = _b64d(parts[2])
    _verify_signature(header, f"{parts[0]}.{parts[1]}".encode(), signature, keys)

    now = time.time() if now is None else now
    if payload.get("iss") != issuer.rstrip("/"):
        raise OIDCError("wrong issuer")
    aud = payload.get("aud")
    auds = aud if isinstance(aud, list) else [aud]
    if client_id not in auds:
        raise OIDCError("wrong audience")
    if payload.get("exp", 0) < now:
        raise OIDCError("token expired")
    if payload.get("nbf") and payload["nbf"] > now + 60:
        raise OIDCError("token not yet valid")
    if nonce is not None and payload.get("nonce") != nonce:
        raise OIDCError("nonce mismatch")
    return payload


def has_group(payload: dict, group: str) -> bool:
    groups = payload.get("groups") or []
    if isinstance(groups, str):
        groups = [groups]
    for value in groups:
        name = value.get("name") if isinstance(value, dict) else value
        if name == group:
            return True
    return False
