"""Ephemeral RSA key pairs for Phase 11.7 crypto tests."""

from __future__ import annotations

from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


def write_rsa_keypair(directory: Path, *, private_name: str, public_name: str) -> tuple[Path, Path]:
    directory.mkdir(parents=True, exist_ok=True)
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
    private_path = directory / private_name
    public_path = directory / public_name
    private_path.write_bytes(
        private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    public_path.write_bytes(
        private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    return private_path, public_path


def write_demo_key_set(directory: Path) -> dict[str, Path]:
    jwt_priv, jwt_pub = write_rsa_keypair(
        directory, private_name="jwt_private.pem", public_name="jwt_public.pem"
    )
    wrap_priv, wrap_pub = write_rsa_keypair(
        directory,
        private_name="data_wrap_private.pem",
        public_name="data_wrap_public.pem",
    )
    return {
        "jwt_private": jwt_priv,
        "jwt_public": jwt_pub,
        "data_wrap_private": wrap_priv,
        "data_wrap_public": wrap_pub,
    }
