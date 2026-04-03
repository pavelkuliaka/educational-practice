import base64
import hashlib
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend


def load_rsa_private_key(pem_string: str):
    return serialization.load_pem_private_key(
        pem_string.encode(), password=None, backend=default_backend()
    )


def int_to_base64url(integer):
    byte_length = (integer.bit_length() + 7) // 8
    return (
        base64.urlsafe_b64encode(integer.to_bytes(byte_length, "big"))
        .rstrip(b"=")
        .decode("utf-8")
    )


def build_jwks(private_key):
    public_key = private_key.public_key()
    n = public_key.public_numbers().n
    e = public_key.public_numbers().e
    return {
        "keys": [
            {
                "kid": "default",
                "kty": "RSA",
                "use": "sig",
                "alg": "RS256",
                "n": int_to_base64url(n),
                "e": int_to_base64url(e),
            }
        ]
    }


def verify_pkce(code_verifier: str, code_challenge: str, method: str) -> bool:
    if method == "plain":
        return code_verifier == code_challenge
    elif method == "S256":
        digest = hashlib.sha256(code_verifier.encode()).digest()
        challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode()
        return challenge == code_challenge
    return False
