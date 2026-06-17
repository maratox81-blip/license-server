# -*- coding: utf-8 -*-
"""
License Server - backend + web admin panel.
FastAPI + SQLite / PostgreSQL + Jinja2.

Local dev:  uvicorn main:app --reload            (uses SQLite)
Production: set DATABASE_URL env var             (uses PostgreSQL)

Run locally:
    uvicorn main:app --reload
"""

import os
import sqlite3
import secrets
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, Header, Request, Form, Response
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel

# ──────────────────────────────────────────────
# Конфигурация
# ──────────────────────────────────────────────
DATABASE_URL = os.environ.get("DATABASE_URL", "")          # set on Render
DB_PATH = Path(__file__).parent / "licenses.db"            # local SQLite fallback
TEMPLATES_DIR = Path(__file__).parent / "templates"

# Fallback: if running from /opt/render/project/src
if not TEMPLATES_DIR.exists():
    TEMPLATES_DIR = Path("/opt/render/project/src/templates")

ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "changeme")

# Простые сессии: token → True (хранятся в памяти сервера)
# При рестарте сервера сессии сбрасываются — это нормально
_sessions: set = set()

app = FastAPI(
    title="License Server",
    description="License server with admin panel.",
    version="1.3.0",
)

templates = Jinja2Templates(directory=str(TEMPLATES_DIR))

# ──────────────────────────────────────────────
# Абстракция БД: PostgreSQL или SQLite
# ──────────────────────────────────────────────

_USE_PG = bool(DATABASE_URL)

if _USE_PG:
    import psycopg2
    import psycopg2.extras

    # Render выдаёт URL вида postgres://... — psycopg2 требует postgresql://
    _PG_DSN = DATABASE_URL.replace("postgres://", "postgresql://", 1)

    @contextmanager
    def get_db():
        conn = psycopg2.connect(_PG_DSN)
        conn.autocommit = False
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def _fetchall(cursor) -> list[dict]:
        cols = [d[0] for d in cursor.description]
        return [dict(zip(cols, row)) for row in cursor.fetchall()]

    def _fetchone(cursor) -> dict | None:
        cols = [d[0] for d in cursor.description]
        row = cursor.fetchone()
        return dict(zip(cols, row)) if row else None

    # PostgreSQL использует %s вместо ?
    _PH = "%s"

else:
    @contextmanager
    def get_db():
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def _fetchall(cursor) -> list[dict]:
        return [dict(row) for row in cursor.fetchall()]

    def _fetchone(cursor) -> dict | None:
        row = cursor.fetchone()
        return dict(row) if row else None

    _PH = "?"


def _q(sql: str) -> str:
    """Replace ? placeholders for the active backend."""
    if _USE_PG:
        return sql.replace("?", "%s")
    return sql


def init_db():
    with get_db() as conn:
        cur = conn.cursor()
        if _USE_PG:
            cur.execute("""
                CREATE TABLE IF NOT EXISTS licenses (
                    id               SERIAL PRIMARY KEY,
                    license_key      TEXT    NOT NULL UNIQUE,
                    status           TEXT    NOT NULL DEFAULT 'active',
                    created_at       TEXT    NOT NULL,
                    expires_at       TEXT    NOT NULL,
                    activation_count INTEGER NOT NULL DEFAULT 0,
                    activation_limit INTEGER NOT NULL DEFAULT 1,
                    activated_devices TEXT   NOT NULL DEFAULT ''
                )
            """)
        else:
            cur.execute("""
                CREATE TABLE IF NOT EXISTS licenses (
                    id               INTEGER PRIMARY KEY AUTOINCREMENT,
                    license_key      TEXT    NOT NULL UNIQUE,
                    status           TEXT    NOT NULL DEFAULT 'active',
                    created_at       TEXT    NOT NULL,
                    expires_at       TEXT    NOT NULL,
                    activation_count INTEGER NOT NULL DEFAULT 0,
                    activation_limit INTEGER NOT NULL DEFAULT 1,
                    activated_devices TEXT   NOT NULL DEFAULT ''
                )
            """)
            # SQLite migration: add activated_devices column if missing
            try:
                cur.execute(
                    "ALTER TABLE licenses ADD COLUMN activated_devices TEXT NOT NULL DEFAULT ''"
                )
            except Exception:
                pass  # already exists


init_db()


# ──────────────────────────────────────────────
# Вспомогательные функции
# ──────────────────────────────────────────────

def generate_license_key() -> str:
    alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
    def seg():
        return "".join(secrets.choice(alphabet) for _ in range(4))
    return "-".join(seg() for _ in range(4))


def get_session_token(request: Request) -> str | None:
    return request.cookies.get("session")


def is_authenticated(request: Request) -> bool:
    token = get_session_token(request)
    return token is not None and token in _sessions


def get_all_keys():
    """Returns all keys with computed display_status."""
    now = datetime.now(timezone.utc)
    with get_db() as conn:
        cur = conn.cursor()
        cur.execute("SELECT * FROM licenses ORDER BY created_at DESC")
        rows = _fetchall(cur)

    keys = []
    for d in rows:
        if d["status"] == "blocked":
            d["display_status"] = "blocked"
        elif datetime.fromisoformat(d["expires_at"]) < now:
            d["display_status"] = "expired"
        else:
            d["display_status"] = "active"
        keys.append(d)
    return keys


def get_stats(keys: list) -> dict:
    return {
        "total": len(keys),
        "active_count": sum(1 for k in keys if k["display_status"] == "active"),
        "blocked_count": sum(1 for k in keys if k["display_status"] == "blocked"),
        "expired_count": sum(1 for k in keys if k["display_status"] == "expired"),
    }


# ──────────────────────────────────────────────
# Авторизация (для API)
# ──────────────────────────────────────────────

def require_admin(authorization: str = Header(default=None)):
    if not authorization or authorization != ADMIN_PASSWORD:
        raise HTTPException(
            status_code=401,
            detail="Unauthorized.",
            headers={"WWW-Authenticate": "ApiKey"},
        )


# ══════════════════════════════════════════════
# ВЕБ-ПАНЕЛЬ (HTML)
# ══════════════════════════════════════════════

@app.get("/login", response_class=HTMLResponse, include_in_schema=False)
def login_page(request: Request, error: str = ""):
    if is_authenticated(request):
        return RedirectResponse("/dashboard", status_code=302)
    return templates.TemplateResponse(
        request=request, name="login.html", context={"error": error}
    )


@app.post("/login", response_class=HTMLResponse, include_in_schema=False)
def login_submit(request: Request, response: Response, password: str = Form(...)):
    if password == ADMIN_PASSWORD:
        token = secrets.token_hex(32)
        _sessions.add(token)
        resp = RedirectResponse("/dashboard", status_code=302)
        resp.set_cookie("session", token, httponly=True, max_age=86400)
        return resp
    return templates.TemplateResponse(
        request=request, name="login.html", context={"error": "Incorrect password"}
    )


@app.get("/logout", include_in_schema=False)
def logout(request: Request):
    token = get_session_token(request)
    if token:
        _sessions.discard(token)
    resp = RedirectResponse("/login", status_code=302)
    resp.delete_cookie("session")
    return resp


@app.get("/dashboard", response_class=HTMLResponse, include_in_schema=False)
def dashboard(request: Request, message: str = "", error: str = "", new_key: str = ""):
    if not is_authenticated(request):
        return RedirectResponse("/login", status_code=302)
    keys = get_all_keys()
    stats = get_stats(keys)
    return templates.TemplateResponse(
        request=request, name="dashboard.html",
        context={"keys": keys, "message": message, "error": error,
                 "new_key": new_key, **stats}
    )


@app.post("/dashboard/create", include_in_schema=False)
def dashboard_create(
    request: Request,
    expires_in_days: int = Form(365),
    activation_limit: int = Form(1)
):
    if not is_authenticated(request):
        return RedirectResponse("/login", status_code=302)

    if expires_in_days <= 0 or activation_limit <= 0:
        keys = get_all_keys()
        stats = get_stats(keys)
        return templates.TemplateResponse(
            request=request, name="dashboard.html",
            context={"keys": keys, "error": "Values must be > 0",
                     "open_form": True, "new_key": "", "message": "", **stats}
        )

    created_at = datetime.now(timezone.utc)
    expires_at = created_at + timedelta(days=expires_in_days)
    new_key = None

    for _ in range(10):
        key = generate_license_key()
        try:
            with get_db() as conn:
                cur = conn.cursor()
                cur.execute(
                    _q("""INSERT INTO licenses
                       (license_key, status, created_at, expires_at, activation_count, activation_limit)
                       VALUES (?, 'active', ?, ?, 0, ?)"""),
                    (key, created_at.isoformat(), expires_at.isoformat(), activation_limit)
                )
            new_key = key
            break
        except Exception:
            continue

    keys = get_all_keys()
    stats = get_stats(keys)

    if not new_key:
        return templates.TemplateResponse(
            request=request, name="dashboard.html",
            context={"keys": keys, "error": "Failed to create key",
                     "new_key": "", "message": "", **stats}
        )

    return templates.TemplateResponse(
        request=request, name="dashboard.html",
        context={"keys": keys, "new_key": new_key, "message": "", "error": "", **stats}
    )


@app.post("/dashboard/block", include_in_schema=False)
def dashboard_block(request: Request, license_key: str = Form(...)):
    if not is_authenticated(request):
        return RedirectResponse("/login", status_code=302)

    with get_db() as conn:
        cur = conn.cursor()
        cur.execute(
            _q("UPDATE licenses SET status = 'blocked' WHERE license_key = ?"),
            (license_key,)
        )
        rowcount = cur.rowcount

    keys = get_all_keys()
    stats = get_stats(keys)
    ok = rowcount > 0
    return templates.TemplateResponse(
        request=request, name="dashboard.html",
        context={"keys": keys,
                 "message": f"Key {license_key} blocked" if ok else "",
                 "error": "" if ok else "Key not found",
                 "new_key": "", **stats}
    )


# ══════════════════════════════════════════════
# REST API (публичный + защищённый)
# ══════════════════════════════════════════════

class VerifyRequest(BaseModel):
    license_key: str
    device_id: str | None = None

class VerifyResponse(BaseModel):
    valid: bool
    reason: str | None = None
    expires_at: str | None = None

class CreateKeyRequest(BaseModel):
    expires_in_days: int = 365
    activation_limit: int = 1

class CreateKeyResponse(BaseModel):
    license_key: str
    expires_at: str
    activation_limit: int


@app.get("/", tags=["Info"])
def root():
    return {"status": "ok", "service": "License Server v1.2", "panel": "/login"}


@app.post("/verify", response_model=VerifyResponse, tags=["Public"])
def verify_license(body: VerifyRequest):
    """Public endpoint - verifies license key."""
    key = body.license_key.strip().upper()
    device_id = (body.device_id or "").strip()

    with get_db() as conn:
        cur = conn.cursor()
        cur.execute(_q("SELECT * FROM licenses WHERE license_key = ?"), (key,))
        row = _fetchone(cur)

    if row is None:
        return VerifyResponse(valid=False, reason="Лицензионный ключ не найден")
    if row["status"] == "blocked":
        return VerifyResponse(valid=False, reason="Лицензионный ключ заблокирован")

    expires_at = datetime.fromisoformat(row["expires_at"])
    if datetime.now(timezone.utc) > expires_at:
        return VerifyResponse(valid=False, reason="Срок действия лицензии истёк")

    # Parse the list of already-activated devices
    activated_raw = row["activated_devices"] or ""
    activated = [d for d in activated_raw.split(",") if d]

    already_activated = device_id and device_id in activated

    if not already_activated:
        # New device — check activation limit
        if row["activation_count"] >= row["activation_limit"]:
            return VerifyResponse(
                valid=False,
                reason=f"Превышен лимит активаций ({row['activation_limit']})"
            )
        # Register this device
        if device_id:
            activated.append(device_id)
            new_devices = ",".join(activated)
        else:
            new_devices = activated_raw

        with get_db() as conn:
            cur = conn.cursor()
            cur.execute(
                _q("""UPDATE licenses
                   SET activation_count = activation_count + 1,
                       activated_devices = ?
                   WHERE license_key = ?"""),
                (new_devices, key)
            )

    return VerifyResponse(valid=True, expires_at=row["expires_at"])


@app.post("/create_key", response_model=CreateKeyResponse, tags=["Admin API"])
def create_key(body: CreateKeyRequest, authorization: str = Header(default=None)):
    """Admin only. Header: Authorization: <password>"""
    require_admin(authorization)
    if body.expires_in_days <= 0 or body.activation_limit <= 0:
        raise HTTPException(status_code=400, detail="Значения должны быть > 0")

    created_at = datetime.now(timezone.utc)
    expires_at = created_at + timedelta(days=body.expires_in_days)

    for _ in range(10):
        key = generate_license_key()
        try:
            with get_db() as conn:
                cur = conn.cursor()
                cur.execute(
                    _q("""INSERT INTO licenses
                       (license_key, status, created_at, expires_at, activation_count, activation_limit)
                       VALUES (?, 'active', ?, ?, 0, ?)"""),
                    (key, created_at.isoformat(), expires_at.isoformat(), body.activation_limit)
                )
            return CreateKeyResponse(
                license_key=key,
                expires_at=expires_at.isoformat(),
                activation_limit=body.activation_limit,
            )
        except Exception:
            continue

    raise HTTPException(status_code=500, detail="Не удалось создать ключ")


@app.get("/keys", tags=["Admin API"])
def list_keys(limit: int = 50, offset: int = 0,
              authorization: str = Header(default=None)):
    """Admin only. Header: Authorization: <password>"""
    require_admin(authorization)
    with get_db() as conn:
        cur = conn.cursor()
        cur.execute(
            _q("SELECT * FROM licenses ORDER BY created_at DESC LIMIT ? OFFSET ?"),
            (limit, offset)
        )
        rows = _fetchall(cur)
        cur.execute("SELECT COUNT(*) FROM licenses")
        total = cur.fetchone()[0]
    return {"total": total, "keys": rows}


@app.post("/block_key", tags=["Admin API"])
def block_key(body: VerifyRequest, authorization: str = Header(default=None)):
    """Admin only. Header: Authorization: <password>"""
    require_admin(authorization)
    key = body.license_key.strip().upper()
    with get_db() as conn:
        cur = conn.cursor()
        cur.execute(
            _q("UPDATE licenses SET status = 'blocked' WHERE license_key = ?"), (key,)
        )
        if cur.rowcount == 0:
            raise HTTPException(status_code=404, detail="Ключ не найден")
    return {"success": True, "license_key": key, "status": "blocked"}
