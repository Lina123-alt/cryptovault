import os
import hmac
import hashlib
import base64
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes


# ── Dérivation de clé par rôle (HKDF) ─────────────────────────
def derive_role_key(master_key: bytes, role: str, salt: bytes) -> bytes:
    """Dérive une clé AES-256 unique par rôle depuis la clé maître."""
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=f"role:{role}".encode()
    )
    return hkdf.derive(master_key)


# ── Chiffrement AES-256-GCM ────────────────────────────────────
def encrypt(plaintext: str, key: bytes) -> str:
    """Chiffre une valeur texte, retourne base64(nonce + ciphertext)."""
    nonce = os.urandom(12)          # 96 bits recommandé pour GCM
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext.encode(), None)
    raw = nonce + ciphertext
    return base64.b64encode(raw).decode()


# ── Déchiffrement AES-256-GCM ──────────────────────────────────
def decrypt(token: str, key: bytes) -> str:
    """Déchiffre une valeur base64(nonce + ciphertext)."""
    raw = base64.b64decode(token.encode())
    nonce      = raw[:12]
    ciphertext = raw[12:]
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, None).decode()


# ── Hash déterministe HMAC-SHA256 (pour recherche) ────────────
def hmac_hash(value: str, secret: bytes) -> str:
    """Retourne un hash déterministe HMAC-SHA256 en hex."""
    return hmac.new(secret, value.encode(), hashlib.sha256).hexdigest()


# ── Génération d'un sel aléatoire ─────────────────────────────
def generate_salt() -> bytes:
    return os.urandom(16)
