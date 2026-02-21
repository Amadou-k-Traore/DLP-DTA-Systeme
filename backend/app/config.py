from __future__ import annotations

from pathlib import Path
from typing import Dict

from passlib.context import CryptContext
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


class Settings(BaseSettings):
    """
    Industrial-grade settings:
    - Loads from environment variables and optional .env file
    - Typed, validated
    """

    model_config = SettingsConfigDict(
        env_prefix="OCL_",          # OCL_ = Ollama Chat Logger
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # Security / JWT
    jwt_secret: str = Field(default="CHANGE_ME_SUPER_SECRET_LONG_RANDOM", min_length=24)
    jwt_algorithm: str = "HS256"
    jwt_exp_minutes: int = Field(default=8 * 60, ge=5, le=7 * 24 * 60)

    # Ollama
    ollama_base_url: str = "http://localhost:11434"
    ollama_model: str = "gemma3:4b"

    # Server
    allowed_origins: str = "*"  # comma-separated, ex: "http://127.0.0.1:5500,http://localhost:5500"
    host: str = "127.0.0.1"
    port: int = Field(default=8000, ge=1, le=65535)

    # Logging
    log_dir: Path = Path("logs")
    log_file: str = "chat_input.jsonl"
    flush_every: int = Field(default=1, ge=1, le=100)  # flush each N writes

    # Privacy knobs (helpful for DTA experiments)
    log_assistant_output: bool = True

    def log_path(self) -> Path:
        return self.log_dir / self.log_file


settings = Settings()


# ✅ 3 predefined users (hash computed at import time; OK for demo/research)
_predefined_plain = {
    "amadou": "Amadou@2026!",
    "alice": "Alice@2026!",
    "bob": "Bob@2026!",
}

PREDEFINED_USERS: Dict[str, Dict[str, str]] = {
    u: {
        "username": u,
        "password_plain": p,
        "role": "user",
    }
    for u, p in _predefined_plain.items()
}
