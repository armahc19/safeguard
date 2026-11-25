"""Encrypt partner HMAC credentials at rest using the application's stable secret key."""
import base64
import hashlib
import hmac

from cryptography.fernet import Fernet


def _cipher(secret_key: str) -> Fernet:
    key = base64.urlsafe_b64encode(hashlib.sha256(secret_key.encode("utf-8")).digest())
    return Fernet(key)


def encrypt_partner_secret(secret: str, application_secret: str) -> str:
    return _cipher(application_secret).encrypt(secret.encode("utf-8")).decode("ascii")


def decrypt_partner_secret(ciphertext: str, application_secret: str) -> str:
    return _cipher(application_secret).decrypt(ciphertext.encode("ascii")).decode("utf-8")


def encrypt_partner_payload(payload: bytes, application_secret: str) -> str:
    return _cipher(application_secret).encrypt(payload).decode("ascii")


def protect_partner_reference(value: str, *, namespace: str, application_secret: str) -> str:
    """Create a stable, non-reversible reference token for repository joins."""
    key = hashlib.sha256((application_secret + ":partner-reference-v1").encode("utf-8")).digest()
    material = f"{namespace}:{value.strip()}".encode()
    return hmac.new(key, material, hashlib.sha256).hexdigest()
