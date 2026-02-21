from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Optional


@dataclass(frozen=True)
class LogContext:
    request_id: str
    username: str
    client_ip: Optional[str] = None
    user_agent: Optional[str] = None


class Logger:
    """
    JSONL logger for:
      - user text messages
      - assistant responses
      - media uploads (image/audio)

    Produces one JSON object per line to be easy to tail/parse for DTA.
    """

    def __init__(self, log_dir: str, log_file: str, flush_every: int = 1):
        self.log_dir = Path(log_dir)
        self.log_file = log_file
        self.flush_every = max(1, int(flush_every))
        self._count = 0

        self.log_dir.mkdir(parents=True, exist_ok=True)
        self._path = self.log_dir / self.log_file

    def path(self) -> Path:
        return self._path

    def _append(self, obj: Dict[str, Any]) -> None:
        line = json.dumps(obj, ensure_ascii=False)
        with self._path.open("a", encoding="utf-8") as f:
            f.write(line + "\n")
            self._count += 1
            if self._count % self.flush_every == 0:
                f.flush()
                os.fsync(f.fileno())

    @staticmethod
    def _utc_ts() -> str:
        return datetime.utcnow().isoformat() + "Z"

    @staticmethod
    def _sha256_text(text: str) -> str:
        return hashlib.sha256(text.encode("utf-8")).hexdigest()

    @staticmethod
    def sha256_file(path: str) -> str:
        """
        Streaming SHA-256 over file content (handles large files).
        """
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(1024 * 1024), b""):
                h.update(chunk)
        return h.hexdigest()

    def log_user_input(self, ctx: LogContext, text: str, meta: Optional[Dict[str, Any]] = None) -> None:
        self._append(
            {
                "ts": self._utc_ts(),
                "event": "chat.user.text",
                "request_id": ctx.request_id,
                "username": ctx.username,
                "client_ip": ctx.client_ip,
                "user_agent": ctx.user_agent,
                "text": text,
                "text_sha256": self._sha256_text(text),
                "meta": meta or {},
            }
        )

    def log_assistant_output(self, ctx: LogContext, text: str, meta: Optional[Dict[str, Any]] = None) -> None:
        self._append(
            {
                "ts": self._utc_ts(),
                "event": "chat.assistant.text",
                "request_id": ctx.request_id,
                "username": ctx.username,
                "client_ip": ctx.client_ip,
                "user_agent": ctx.user_agent,
                "text": text,
                "meta": meta or {},
            }
        )

    def log_media_upload(
        self,
        ctx: LogContext,
        kind: str,  # "image" | "audio"
        saved_path: str,
        filename: str,
        content_type: str,
        size: int,
        sha256: str,
        meta: Optional[Dict[str, Any]] = None,
    ) -> None:
        if kind not in ("image", "audio"):
            kind = "media"

        self._append(
            {
                "ts": self._utc_ts(),
                "event": f"chat.user.{kind}",
                "request_id": ctx.request_id,
                "username": ctx.username,
                "client_ip": ctx.client_ip,
                "user_agent": ctx.user_agent,
                "filename": filename,
                "content_type": content_type,
                "size": int(size),
                "sha256": sha256,
                "path": saved_path.replace("\\", "/"),
                "meta": meta or {},
            }
        )
