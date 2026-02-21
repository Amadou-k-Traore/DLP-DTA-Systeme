from __future__ import annotations

import shutil
import uuid
from pathlib import Path
from typing import Dict, List, Optional

import httpx
from fastapi import Depends, FastAPI, File, Header, HTTPException, Request, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from .auth import authenticate_user, create_access_token, decode_token
from .config import settings
from .logger import Logger, LogContext
from .ollama_client import OllamaError, ollama_chat

app = FastAPI(title="Ollama Chat + Logger", version="2.2.0")


def _parse_origins(value: str) -> List[str]:
    v = (value or "").strip()
    if v == "*" or v == "":
        return ["*"]
    return [x.strip() for x in v.split(",") if x.strip()]


# CORS (configurable)
app.add_middleware(
    CORSMiddleware,
    allow_origins=_parse_origins(settings.allowed_origins),
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type"],
)

logger = Logger(settings.log_dir, settings.log_file, flush_every=settings.flush_every)

# Upload dir (relative to backend working dir)
UPLOAD_DIR = Path("uploads")
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)


class LoginIn(BaseModel):
    username: str = Field(min_length=2, max_length=32, pattern=r"^[a-zA-Z0-9_]+$")
    password: str = Field(min_length=4, max_length=128)


class LoginOut(BaseModel):
    access_token: str
    token_type: str = "bearer"


class ChatIn(BaseModel):
    text: str = Field(min_length=1, max_length=8000)
    history: Optional[List[Dict[str, str]]] = None


class ChatOut(BaseModel):
    request_id: str
    response: str


def get_current_user(authorization: Optional[str] = Header(default=None)) -> str:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing Bearer token")

    token = authorization.split(" ", 1)[1].strip()
    username = decode_token(token)

    if not username:
        raise HTTPException(status_code=401, detail="Invalid or expired token")

    return username


def _ctx_from_request(request_id: str, username: str, request: Optional[Request]) -> LogContext:
    client_ip = request.client.host if request and request.client else None
    user_agent = request.headers.get("user-agent") if request else None
    return LogContext(
        request_id=request_id,
        username=username,
        client_ip=client_ip,
        user_agent=user_agent,
    )


def _user_upload_dir(username: str) -> Path:
    d = UPLOAD_DIR / username
    d.mkdir(parents=True, exist_ok=True)
    return d


def _validate_upload(kind: str, content_type: Optional[str]) -> None:
    ct = (content_type or "").strip().lower()
    if not ct:
        raise HTTPException(status_code=400, detail="Missing content-type")

    if kind == "image" and not ct.startswith("image/"):
        raise HTTPException(status_code=400, detail=f"Invalid image type: {ct}")

    if kind == "audio" and not ct.startswith("audio/"):
        raise HTTPException(status_code=400, detail=f"Invalid audio type: {ct}")


@app.get("/api/health")
def health():
    return {
        "status": "ok",
        "ollama_base_url": settings.ollama_base_url,
        "model": settings.ollama_model,
        "log_path": str(settings.log_path()),
        "upload_dir": str(UPLOAD_DIR),
    }


@app.get("/api/ollama/health")
async def ollama_health():
    """
    Fast healthcheck (no generation):
    - Checks Ollama is reachable via /api/tags
    - Avoids timeouts with heavy models like gemma3:4b
    """
    try:
        async with httpx.AsyncClient(timeout=5.0, trust_env=False) as client:
            r = await client.get(f"{settings.ollama_base_url}/api/tags")
            r.raise_for_status()
            models = r.json().get("models", [])
            return {"status": "ok", "models_count": len(models)}
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Ollama health failed: {repr(e)}")


@app.post("/api/ollama/warmup")
async def ollama_warmup():
    """
    Warm-up endpoint:
    - Triggers a small generation so the model is loaded in memory
    - First call can be slow, subsequent requests are faster
    """
    try:
        _ = await ollama_chat([{"role": "user", "content": "Say 'ready'."}])
        return {"status": "ok"}
    except OllamaError as e:
        raise HTTPException(status_code=502, detail=str(e))


@app.post("/api/login", response_model=LoginOut)
def login(payload: LoginIn):
    user = authenticate_user(payload.username, payload.password)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid credentials")

    token = create_access_token(subject=user["username"])
    return LoginOut(access_token=token)


@app.get("/api/me")
def me(username: str = Depends(get_current_user)):
    return {"username": username}


@app.post("/api/upload/image")
async def upload_image(
    file: UploadFile = File(...),
    request: Request = None,
    username: str = Depends(get_current_user),
):
    request_id = str(uuid.uuid4())
    _validate_upload("image", file.content_type)

    dest_dir = _user_upload_dir(username)
    dest = dest_dir / f"{request_id}_{file.filename}"

    with dest.open("wb") as out:
        shutil.copyfileobj(file.file, out)

    size = dest.stat().st_size
    sha = logger.sha256_file(str(dest))

    ctx = _ctx_from_request(request_id, username, request)
    logger.log_media_upload(
        ctx=ctx,
        kind="image",
        saved_path=str(dest),
        filename=file.filename,
        content_type=file.content_type or "application/octet-stream",
        size=int(size),
        sha256=sha,
        meta={"channel": "web_chat"},
    )

    return {"status": "ok", "request_id": request_id, "path": str(dest).replace("\\", "/")}


@app.post("/api/upload/audio")
async def upload_audio(
    file: UploadFile = File(...),
    request: Request = None,
    username: str = Depends(get_current_user),
):
    request_id = str(uuid.uuid4())
    _validate_upload("audio", file.content_type)

    dest_dir = _user_upload_dir(username)
    dest = dest_dir / f"{request_id}_{file.filename}"

    with dest.open("wb") as out:
        shutil.copyfileobj(file.file, out)

    size = dest.stat().st_size
    sha = logger.sha256_file(str(dest))

    ctx = _ctx_from_request(request_id, username, request)
    logger.log_media_upload(
        ctx=ctx,
        kind="audio",
        saved_path=str(dest),
        filename=file.filename,
        content_type=file.content_type or "application/octet-stream",
        size=int(size),
        sha256=sha,
        meta={"channel": "web_chat"},
    )

    return {"status": "ok", "request_id": request_id, "path": str(dest).replace("\\", "/")}


@app.post("/api/chat", response_model=ChatOut)
async def chat(payload: ChatIn, request: Request, username: str = Depends(get_current_user)):
    request_id = str(uuid.uuid4())
    ctx = _ctx_from_request(request_id, username, request)

    #  Log user input for DTA
    logger.log_user_input(
        ctx=ctx,
        text=payload.text,
        meta={"channel": "web_chat"},
    )

    # Build messages safely (limit history size, accept only allowed roles)
    messages: List[Dict[str, str]] = [
        {"role": "system", "content": "You are a helpful assistant. Respond clearly and safely."}
    ]

    if payload.history:
        for m in payload.history[-20:]:
            role = m.get("role")
            content = m.get("content")
            if role in ("user", "assistant") and isinstance(content, str) and content.strip():
                messages.append({"role": role, "content": content})

    messages.append({"role": "user", "content": payload.text})

    try:
        assistant_text = await ollama_chat(messages)
    except OllamaError as e:
        raise HTTPException(status_code=502, detail=str(e))
    except Exception:
        raise HTTPException(status_code=502, detail="Unexpected backend error")

    if settings.log_assistant_output:
        logger.log_assistant_output(
            ctx=ctx,
            text=assistant_text,
            meta={"model": settings.ollama_model},
        )

    return ChatOut(request_id=request_id, response=assistant_text)
