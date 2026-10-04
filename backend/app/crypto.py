import base64
import json
import os
import secrets
from pathlib import Path
from threading import RLock
from argon2 import PasswordHasher
from argon2.exceptions import Argon2Error
from argon2.low_level import Type, hash_secret_raw
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from .config import config

password_hasher = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=4, type=Type.ID)
_key: bytes | None = None
_lock = RLock()


def b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode('ascii')


def unb64(value: str) -> bytes:
    return base64.urlsafe_b64decode(value.encode('ascii'))


def hash_password(password: str) -> str:
    return password_hasher.hash(password)


def verify_password(encoded: str, password: str) -> bool:
    try:
        return password_hasher.verify(encoded, password)
    except (Argon2Error, ValueError, TypeError):
        return False


def key_path() -> Path:
    return config.data_dir / 'keys' / 'master.key'


def get_key() -> bytes:
    global _key
    with _lock:
        if _key is None:
            raw = key_path().read_bytes()
            if len(raw) != 32:
                raise RuntimeError('Encryption subsystem unavailable')
            _key = raw
        return _key


def set_key(value: bytes) -> None:
    global _key
    if len(value) != 32:
        raise ValueError('Invalid encryption key')
    with _lock:
        directory = key_path().parent
        directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(directory, 0o700)
        temporary = directory / ('key-' + secrets.token_hex(8))
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(value)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, key_path())
        directory_fd = os.open(directory, os.O_RDONLY | getattr(os, 'O_DIRECTORY', 0))
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
        _key = value


def initialize_key() -> bytes:
    if key_path().exists():
        return get_key()
    value = AESGCM.generate_key(bit_length=256)
    set_key(value)
    return value


def encrypt_json(value: dict, context: str) -> str:
    nonce = secrets.token_bytes(12)
    plaintext = json.dumps(value, ensure_ascii=False, separators=(',', ':')).encode()
    ciphertext = AESGCM(get_key()).encrypt(nonce, plaintext, context.encode())
    return b64(nonce + ciphertext)


def decrypt_json(value: str, context: str) -> dict:
    raw = unb64(value)
    plaintext = AESGCM(get_key()).decrypt(raw[:12], raw[12:], context.encode())
    result = json.loads(plaintext)
    if not isinstance(result, dict):
        raise ValueError('Invalid encrypted record')
    return result


def derive_key(password: str, salt: bytes) -> bytes:
    return hash_secret_raw(password.encode(), salt, time_cost=3, memory_cost=65536,
                           parallelism=4, hash_len=32, type=Type.ID)


def wrap_key(password: str, context: str) -> str:
    salt, nonce = secrets.token_bytes(16), secrets.token_bytes(12)
    return b64(salt + nonce + AESGCM(derive_key(password, salt)).encrypt(nonce, get_key(), context.encode()))


def unwrap_key(password: str, envelope: str, context: str) -> bytes:
    raw = unb64(envelope)
    if len(raw) != 76:
        raise ValueError('Invalid key envelope')
    return AESGCM(derive_key(password, raw[:16])).decrypt(raw[16:28], raw[28:], context.encode())
