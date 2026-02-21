#!/usr/bin/env python3
# -*- coding: utf-8 -*-


from __future__ import annotations

import os
import sys
import json
import time
import hashlib
import re
from dataclasses import dataclass
from datetime import datetime, timezone, timedelta
from threading import Event, Thread, Lock
from typing import Dict, Iterable, List, Optional, Set, Tuple

# ============
# DEPENDANCE PG (psycopg v3)
# ============
try:
    import psycopg
    from psycopg.rows import dict_row
except Exception as e:
    print(" psycopg non installé. Installe: pip install psycopg[binary]")
    raise


# --- PostgreSQL sur Ubuntu 
PG_HOST = "192.168.1.50"      # <-- IP de ta machine Ubuntu
PG_PORT = 5432
PG_DB   = "dta_policy"
PG_USER = "dta_user"
PG_PASS = "ChangeMe_StrongPwd!"

# --- Logs produits par TON backend (Windows path)
# Exemple backend: backend/logs/chat_input.jsonl, backend/logs/media_uploads.jsonl
CHAT_LOG_JSONL  = r"C:\Users\Amadou\OneDrive\Bureau\ollama-chat-logger\backend\logs\chat_input.jsonl"
MEDIA_LOG_JSONL = r"C:\Users\Amadou\OneDrive\Bureau\ollama-chat-logger\backend\logs\media_uploads.jsonl"

# --- Sorties DTA
CUSTOM_ALERT_LOG = r"C:\ProgramData\wazuh-agent\ossec.log"  # ⚠️ adapte si tu veux (ou mets un autre fichier)
# Recommandé (simple): un fichier dédié, ensuite Wazuh lit ce fichier
CUSTOM_ALERT_LOG = r"C:\Users\Amadou\OneDrive\Bureau\ollama-chat-logger\backend\logs\Custom_alert.log"

UI_DECISIONS_JSONL = r"C:\Users\Amadou\OneDrive\Bureau\ollama-chat-logger\backend\logs\ollama_dta_decisions.jsonl"
DTA_EXEC_LOG       = r"C:\Users\Amadou\OneDrive\Bureau\ollama-chat-logger\backend\logs\dta_exec.log"

# --- Rafraîchissement DB
REFRESH_INTERVAL_SEC = 60  # 1 minute (tu peux mettre 300)
POLL_SLEEP_SEC = 0.25

# --- Policy (durées)
HARD_BLOCK_MINUTES = 60          # blocage 60 min si fuite détectée
QUARANTINE_TRIGGER_ATTEMPTS = 3  # après 3 fuites
QUARANTINE_WINDOW_MIN = 10
QUARANTINE_DURATION_MIN = 30

# --- Sécurité logs: ne jamais écrire la donnée sensible brute
HASH_PREFIX_LEN = 16

# --- Heuristiques (soft-block) si tu veux
POTENTIAL_NAS_RE = re.compile(r"\b\d{3}[- ]?\d{3}[- ]?\d{3}\b")
POTENTIAL_DOB_RE = re.compile(r"\b(19|20)\d{2}[-/](0[1-9]|1[0-2])[-/](0[1-9]|[12]\d|3[01])\b")



def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()

def sha256_hex_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def sha256_file(path: str, chunk_size: int = 1024 * 1024) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()

def short_hash_text(s: str, n: int = HASH_PREFIX_LEN) -> str:
    if not s:
        return ""
    return sha256_hex_bytes(s.encode("utf-8"))[:n]

def safe_makedirs_for_file(path: str) -> None:
    d = os.path.dirname(path)
    if d:
        os.makedirs(d, exist_ok=True)

def safe_append_line(path: str, line: str) -> None:
    try:
        safe_makedirs_for_file(path)
        with open(path, "a", encoding="utf-8") as f:
            f.write(line + "\n")
            f.flush()
            os.fsync(f.fileno())
    except Exception as e:
        print(f"[DTA] ERROR writing {path}: {e}")

def safe_json_append(path: str, obj: dict) -> None:
    safe_append_line(path, json.dumps(obj, ensure_ascii=False))

def exec_log(msg: str) -> None:
    safe_append_line(DTA_EXEC_LOG, f"[{now_iso()}] {msg}")

def parse_ts(v) -> str:
    # pour normaliser un timestamp venant du backend
    if isinstance(v, str) and v.strip():
        return v
    return now_iso()




@dataclass(frozen=True)
class LogEvent:
    etype: str                 # "text" | "image" | "audio"
    username: str
    session_id: str
    request_id: str
    ts: str

    # text
    text: Optional[str] = None

    # media
    path: Optional[str] = None
    sha256: Optional[str] = None
    filename: Optional[str] = None
    mime: Optional[str] = None



class PostgresStore:
    def __init__(self):
        self.dsn = (
            f"host={PG_HOST} port={PG_PORT} dbname={PG_DB} "
            f"user={PG_USER} password={PG_PASS}"
        )

    def connect(self):
        # row_factory dict -> dict
        return psycopg.connect(self.dsn, row_factory=dict_row, connect_timeout=5)

    def load_sensitive_text(self) -> List[Dict]:
        with self.connect() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT label, value FROM sensitive_text")
                return cur.fetchall()

    def load_sensitive_media(self) -> List[Dict]:
        with self.connect() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT media_type, sha256, label FROM sensitive_media")
                return cur.fetchall()

    def upsert_policy(self, username: str, action: str, level: int,
                      blocked_until: Optional[datetime], reason: str) -> None:
        with self.connect() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO user_policy (username, action, policy_level, blocked_until, reason, updated_at)
                    VALUES (%s, %s, %s, %s, %s, NOW())
                    ON CONFLICT (username)
                    DO UPDATE SET action=EXCLUDED.action,
                                  policy_level=EXCLUDED.policy_level,
                                  blocked_until=EXCLUDED.blocked_until,
                                  reason=EXCLUDED.reason,
                                  updated_at=NOW()
                    """,
                    (username, action, level, blocked_until, reason),
                )
            conn.commit()

    def get_policy(self, username: str) -> Dict:
        with self.connect() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT username, action, policy_level, blocked_until, reason FROM user_policy WHERE username=%s",
                    (username,),
                )
                row = cur.fetchone()
                return row or {"username": username, "action": "allow", "policy_level": 0, "blocked_until": None, "reason": None}



class ReferenceCache:
    """
    Garde les références sensibles en mémoire.
    - Texte: liste de valeurs exactes -> regex (cherche dans phrase)
    - Média: set sha256 pour image/audio
    """
    def __init__(self):
        self.lock = Lock()
        self.text_values: List[Tuple[str, str]] = []  # (label, value)
        self.text_rx: Optional[re.Pattern] = None

        self.image_sha: Set[str] = set()
        self.audio_sha: Set[str] = set()

    def rebuild(self, text_rows: List[Dict], media_rows: List[Dict]) -> None:
        # --- texte
        tv = []
        for r in text_rows:
            label = str(r.get("label") or "").strip() or "unknown"
            value = str(r.get("value") or "").strip()
            if value:
                tv.append((label, value))

        # trie plus long -> match plus précis
        tv.sort(key=lambda x: len(x[1]), reverse=True)

        # on limite si énorme (prototype)
        tv = tv[:8000]

        pattern = None
        if tv:
            pattern = "(" + "|".join(re.escape(v) for _, v in tv) + ")"
        rx = re.compile(pattern) if pattern else None

        # --- media
        img = set()
        aud = set()
        for r in media_rows:
            mtype = str(r.get("media_type") or "").strip().lower()
            sh = str(r.get("sha256") or "").strip().lower()
            if not sh:
                continue
            if mtype == "image":
                img.add(sh)
            elif mtype == "audio":
                aud.add(sh)

        with self.lock:
            self.text_values = tv
            self.text_rx = rx
            self.image_sha = img
            self.audio_sha = aud

    def match_text(self, text: str) -> Optional[Tuple[str, str]]:
        """Retourne (label, matched_value) ou None"""
        if not text:
            return None
        with self.lock:
            rx = self.text_rx
            values = self.text_values
        if not rx:
            return None
        m = rx.search(text)
        if not m:
            return None
        matched = m.group(1)

        # retrouve le label correspondant (optionnel)
        # (on cherche dans la liste, coût ok car match rare)
        for label, v in values:
            if v == matched:
                return (label, matched)
        return ("unknown", matched)

    def is_sensitive_image_sha(self, sha: str) -> bool:
        sha = (sha or "").lower()
        if not sha:
            return False
        with self.lock:
            return sha in self.image_sha

    def is_sensitive_audio_sha(self, sha: str) -> bool:
        sha = (sha or "").lower()
        if not sha:
            return False
        with self.lock:
            return sha in self.audio_sha



# QUARANTINE / RATE


class QuarantineManager:
    def __init__(self):
        self.lock = Lock()
        self.attempts: Dict[str, List[float]] = {}
        self.quarantined_until: Dict[str, float] = {}


    def _now(self) -> float:
        return time.time()
    
# mise en attente.

    def is_quarantined(self, user: str) -> Tuple[bool, float]:
        now = self._now()
        with self.lock:
            until = self.quarantined_until.get(user, 0.0)
            if until <= now:
                if user in self.quarantined_until:
                    del self.quarantined_until[user]
                return (False, 0.0)
            return (True, until)

    def record_attempt(self, user: str) -> bool:
        now = self._now()
        window = QUARANTINE_WINDOW_MIN * 60
        with self.lock:
            lst = self.attempts.get(user, [])
            lst = [t for t in lst if (now - t) <= window]
            lst.append(now)
            self.attempts[user] = lst
            if len(lst) >= QUARANTINE_TRIGGER_ATTEMPTS:
                until = now + (QUARANTINE_DURATION_MIN * 60)
                self.quarantined_until[user] = until
                self.attempts[user] = []
                return True
        return False



def tail_jsonl(path: str, stop: Event) -> Iterable[dict]:
    """
    Tail -f robuste:
    - suit la croissance
    """
    safe_makedirs_for_file(path)
    if not os.path.exists(path):
        # crée fichier vide
        open(path, "a", encoding="utf-8").close()

    f = open(path, "r", encoding="utf-8", errors="ignore")
    f.seek(0, os.SEEK_END)

    while not stop.is_set():
        line = f.readline()
        if not line:
            time.sleep(POLL_SLEEP_SEC)
            continue
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
            if isinstance(obj, dict):
                yield obj
        except Exception:
            continue

    try:
        f.close()
    except Exception:
        pass




def parse_event(obj: dict) -> Optional[LogEvent]:
    # types attendus: text | image | audio
    etype = str(obj.get("type") or obj.get("event_type") or "").strip().lower()
    if etype not in ("text", "image", "audio"):
        # certains backends loggent "chat_input" / "media_upload"
        # on tente un mapping
        if "text" in obj and isinstance(obj.get("text"), str):
            etype = "text"
        elif obj.get("media_type") in ("image", "audio"):
            etype = obj.get("media_type")
        else:
            return None

    username = str(obj.get("username") or obj.get("user") or "unknown")
    session_id = str(obj.get("session_id") or obj.get("session") or "unknown")
    request_id = str(obj.get("request_id") or obj.get("req_id") or obj.get("id") or "unknown")
    ts = parse_ts(obj.get("ts") or obj.get("timestamp"))

    if etype == "text":
        text = obj.get("text") or obj.get("content") or ""
        if not isinstance(text, str):
            return None
        return LogEvent(
            etype="text",
            username=username,
            session_id=session_id,
            request_id=request_id,
            ts=ts,
            text=text,
        )

    # image/audio
    media_path = obj.get("path") or obj.get("file_path")
    sha = obj.get("sha256") or obj.get("file_sha256")
    fn = obj.get("filename")
    mime = obj.get("mime")

    if isinstance(media_path, str) and media_path and (sha is None or not str(sha).strip()):
        # si backend n’a pas loggé sha256, on le calcule localement (si fichier accessible)
        try:
            sha = sha256_file(media_path)
        except Exception:
            sha = None

    return LogEvent(
        etype=etype,
        username=username,
        session_id=session_id,
        request_id=request_id,
        ts=ts,
        path=str(media_path) if isinstance(media_path, str) else None,
        sha256=str(sha).lower() if sha else None,
        filename=str(fn) if isinstance(fn, str) else None,
        mime=str(mime) if isinstance(mime, str) else None,
    )

# OUTPUTS: WAZUH + UI DECISIONS


def wazuh_alert(event_type: str, details: dict) -> None:
    # IMPORTANT: pas de donnée sensible brute (utilise hash)
    payload = {
        "timestamp": now_iso(),
        "type": event_type,   # llm_leak_text | llm_leak_image | llm_leak_audio | policy_quarantine
        "canal": "OLLAMA_CHAT",
        "details": details,
    }
    safe_json_append(CUSTOM_ALERT_LOG, payload)

def ui_decision(user: str, session_id: str, level: int, action: str, message: str, evidence: dict) -> None:
    payload = {
        "ts": now_iso(),
        "user": user,
        "session_id": session_id,
        "policy_level": level,
        "action": action,  # allow | soft_block | hard_block | quarantine
        "message": message,
        "evidence": evidence,
    }
    safe_json_append(UI_DECISIONS_JSONL, payload)



def apply_soft_block(user: str, session_id: str, reason: str, evidence: dict) -> None:
    ui_decision(
        user=user,
        session_id=session_id,
        level=1,
        action="soft_block",
        message=reason,
        evidence=evidence,
    )

def apply_hard_block(pg: PostgresStore, user: str, session_id: str, reason: str, evidence: dict) -> None:
    # bloque côté UI + côté DB (backend peut refuser /api/chat)
    ui_decision(
        user=user,
        session_id=session_id,
        level=2,
        action="hard_block",
        message=reason,
        evidence=evidence,
    )

    blocked_until = datetime.now(timezone.utc) + timedelta(minutes=HARD_BLOCK_MINUTES)
    pg.upsert_policy(
        username=user,
        action="hard_block",
        level=2,
        blocked_until=blocked_until,
        reason=reason,
    )

def apply_quarantine(pg: PostgresStore, user: str, session_id: str, until_ts: float, evidence: dict) -> None:
    until_dt = datetime.fromtimestamp(until_ts, tz=timezone.utc)
    msg = "Compte temporairement restreint (quarantine) suite à des tentatives répétées de fuite."

    ui_decision(
        user=user,
        session_id=session_id,
        level=3,
        action="quarantine",
        message=msg,
        evidence={**evidence, "quarantine_until": until_dt.isoformat()},
    )

    pg.upsert_policy(
        username=user,
        action="quarantine",
        level=3,
        blocked_until=until_dt,
        reason="repeated_sensitive_attempts",
    )

    wazuh_alert(
        "policy_quarantine",
        {"policy_level": 3, "action": "quarantine", "user": user, "session_id": session_id, "quarantine_until": until_dt.isoformat()},
    )



def detect_text(cache: ReferenceCache, pg: PostgresStore, qm: QuarantineManager, ev: LogEvent) -> None:
    text = ev.text or ""
    user = ev.username
    session_id = ev.session_id

    # Quarantine déjà active ?
    quarantined, until = qm.is_quarantined(user)
    if quarantined:
        apply_quarantine(pg, user, session_id, until, {"reason": "already_quarantined"})
        return

    hit = cache.match_text(text)
    if hit:
        label, matched = hit
        # tentative enregistrée
        if qm.record_attempt(user):
            _, until2 = qm.is_quarantined(user)
            apply_quarantine(pg, user, session_id, until2, {"match_type": "text_exact", "label": label, "matched_hash": short_hash_text(matched)})
            return

        # hard block
        apply_hard_block(
            pg, user, session_id,
            reason="Envoi bloqué : donnée sensible détectée dans le texte.",
            evidence={"match_type": "text_exact", "label": label, "matched_hash": short_hash_text(matched), "request_id": ev.request_id},
        )
        wazuh_alert(
            "llm_leak_text",
            {"policy_level": 2, "action": "hard_block", "user": user, "session_id": session_id, "label": label, "matched_hash": short_hash_text(matched)},
        )
        return

    # Heuristique soft (optionnel)
    if POTENTIAL_NAS_RE.search(text) or POTENTIAL_DOB_RE.search(text):
        apply_soft_block(
            user, session_id,
            reason="Contenu potentiellement sensible détecté. Vérifie avant l’envoi.",
            evidence={"match_type": "text_potential", "request_id": ev.request_id},
        )
        return


def detect_media(cache: ReferenceCache, pg: PostgresStore, qm: QuarantineManager, ev: LogEvent) -> None:
    user = ev.username
    session_id = ev.session_id
    sha = (ev.sha256 or "").lower()

    quarantined, until = qm.is_quarantined(user)
    if quarantined:
        apply_quarantine(pg, user, session_id, until, {"reason": "already_quarantined"})
        return

    if ev.etype == "image":
        if sha and cache.is_sensitive_image_sha(sha):
            if qm.record_attempt(user):
                _, until2 = qm.is_quarantined(user)
                apply_quarantine(pg, user, session_id, until2, {"match_type": "image_sha256", "sha256": sha[:12]})
                return

            apply_hard_block(
                pg, user, session_id,
                reason="Envoi bloqué : image sensible détectée.",
                evidence={"match_type": "image_sha256", "sha256": sha, "filename": ev.filename, "request_id": ev.request_id},
            )
            wazuh_alert(
                "llm_leak_image",
                {"policy_level": 2, "action": "hard_block", "user": user, "session_id": session_id, "sha256_prefix": sha[:12]},
            )
            return

    if ev.etype == "audio":
        if sha and cache.is_sensitive_audio_sha(sha):
            if qm.record_attempt(user):
                _, until2 = qm.is_quarantined(user)
                apply_quarantine(pg, user, session_id, until2, {"match_type": "audio_sha256", "sha256": sha[:12]})
                return

            apply_hard_block(
                pg, user, session_id,
                reason="Envoi bloqué : audio sensible détecté.",
                evidence={"match_type": "audio_sha256", "sha256": sha, "filename": ev.filename, "request_id": ev.request_id},
            )
            wazuh_alert(
                "llm_leak_audio",
                {"policy_level": 2, "action": "hard_block", "user": user, "session_id": session_id, "sha256_prefix": sha[:12]},
            )
            return



def refresh_refs(cache: ReferenceCache, pg: PostgresStore, stop: Event) -> None:
    while not stop.is_set():
        try:
            t = pg.load_sensitive_text()
            m = pg.load_sensitive_media()
            cache.rebuild(t, m)
            exec_log(f"refs refreshed: text={len(t)} media={len(m)}")
        except Exception as e:
            exec_log(f"refresh error: {repr(e)}")

        for _ in range(REFRESH_INTERVAL_SEC):
            if stop.is_set():
                break
            time.sleep(1)



def watch_chat_logs(cache: ReferenceCache, pg: PostgresStore, qm: QuarantineManager, stop: Event) -> None:
    exec_log(f"watch chat logs: {CHAT_LOG_JSONL}")
    for obj in tail_jsonl(CHAT_LOG_JSONL, stop):
        ev = parse_event(obj)
        if not ev or ev.etype != "text":
            continue
        try:
            detect_text(cache, pg, qm, ev)
        except Exception as e:
            exec_log(f"detect_text error: {repr(e)}")

def watch_media_logs(cache: ReferenceCache, pg: PostgresStore, qm: QuarantineManager, stop: Event) -> None:
    exec_log(f"watch media logs: {MEDIA_LOG_JSONL}")
    for obj in tail_jsonl(MEDIA_LOG_JSONL, stop):
        ev = parse_event(obj)
        if not ev or ev.etype not in ("image", "audio"):
            continue
        try:
            detect_media(cache, pg, qm, ev)
        except Exception as e:
            exec_log(f"detect_media error: {repr(e)}")


def main() -> None:
    stop = Event()
    pg = PostgresStore()
    cache = ReferenceCache()
    qm = QuarantineManager()

    exec_log("DTA START (logs JSONL -> PostgreSQL -> UI decisions + Wazuh alerts + DB policy)")

    # initial refresh
    try:
        cache.rebuild(pg.load_sensitive_text(), pg.load_sensitive_media())
        exec_log("initial refs loaded OK")
    except Exception as e:
        exec_log(f"initial refs failed: {repr(e)}")

    threads = [
        Thread(target=refresh_refs, args=(cache, pg, stop), daemon=True),
        Thread(target=watch_chat_logs, args=(cache, pg, qm, stop), daemon=True),
        Thread(target=watch_media_logs, args=(cache, pg, qm, stop), daemon=True),
    ]
    for th in threads:
        th.start()

    try:
        while True:
            time.sleep(1.0)
    except KeyboardInterrupt:
        exec_log("DTA STOP requested")
        stop.set()
        time.sleep(1.0)


if __name__ == "__main__":
    main()
