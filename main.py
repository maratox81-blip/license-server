"""
License Server — бэкенд + веб-панель администратора.
FastAPI + SQLite + Jinja2.

Запуск:
    uvicorn main:app --reload
"""

import os
import sqlite3
import secrets
from datetime import datetime, timedelta, timezone
from pathlib import Path

from fastapi import FastAPI, HTTPException, Header, Request, Form, Response
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel

# ──────────────────────────────────────────────
# Конфигурация
# ──────────────────────────────────────────────
DB_PATH = Path(__file__).parent / "licenses.db"
TEMPLATES_DIR = Path(__file__).parent / "templates"

ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "changeme")

# Простые сессии: token → True (хранятся в памяти сервера)
# При рестарте сервера сессии сбрасываются — это нормально
_sessions: set = set()

app = FastAPI(
    title="License Server",
    description="Сервер лицензий с веб-панелью администратора.",
    version="1.2.0",
)

templates = Jinja2Templates(directory=str(TEMPLATES_DIR))


# ──────────────────────────────────────────────
# База данных
# ──────────────────────────────────────────────

def get_db() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    with get_db() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS licenses (
                id               INTEGER PRIMARY KEY AUTOINCREMENT,
                license_key      TEXT    NOT NULL UNIQUE,
                status           TEXT    NOT NULL DEFAULT 'active',
                created_at       TEXT    NOT NULL,
                expires_at       TEXT    NOT NULL,
                activation_count INTEGER NOT NULL DEFAULT 0,
                activation_limit INTEGER NOT NULL DEFAULT 1
            )
        """)
        conn.commit()


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
    """Возвращает все ключи с вычисленным display_status."""
    now = datetime.now(timezone.utc)
    with get_db() as conn:
        rows = conn.execute(
            "SELECT * FROM licenses ORDER BY created_at DESC"
        ).fetchall()

    keys = []
    for row in rows:
        d = dict(row)
        # Вычисляем статус для отображения
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
    return templates.TemplateResponse("login.html", {
        "request": request,
        "error": error
    })


@app.post("/login", response_class=HTMLResponse, include_in_schema=False)
def login_submit(request: Request, response: Response, password: str = Form(...)):
    if password == ADMIN_PASSWORD:
        token = secrets.token_hex(32)
        _sessions.add(token)
        resp = RedirectResponse("/dashboard", status_code=302)
        resp.set_cookie("session", token, httponly=True, max_age=86400)
        return resp
    return templates.TemplateResponse("login.html", {
        "request": request,
        "error": "Неверный пароль"
    })


@app.get("/logout", include_in_schema=False)
def logout(request: Request):
    token = get_session_token(request)
    if token:
        _sessions.discard(token)
    resp = RedirectResponse("/login", status_code=302)
    resp.delete_cookie("session")
    return resp


@app.get("/dashboard", response_class=HTMLResponse, include_in_schema=False)
def dashboard(request: Request, message: str = "", error: str = "",
              new_key: str = ""):
    if not is_authenticated(request):
        return RedirectResponse("/login", status_code=302)

    keys = get_all_keys()
    stats = get_stats(keys)

    return templates.TemplateResponse("dashboard.html", {
        "request": request,
        "keys": keys,
        "message": message,
        "error": error,
        "new_key": new_key,
        **stats
    })


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
        return templates.TemplateResponse("dashboard.html", {
            "request": request, "keys": keys,
            "error": "Значения должны быть больше 0",
            "open_form": True, "new_key": "", "message": "", **stats
        })

    created_at = datetime.now(timezone.utc)
    expires_at = created_at + timedelta(days=expires_in_days)
    new_key = None

    for _ in range(10):
        key = generate_license_key()
        try:
            with get_db() as conn:
                conn.execute(
                    """INSERT INTO licenses
                       (license_key, status, created_at, expires_at, activation_count, activation_limit)
                       VALUES (?, 'active', ?, ?, 0, ?)""",
                    (key, created_at.isoformat(), expires_at.isoformat(), activation_limit)
                )
                conn.commit()
            new_key = key
            break
        except sqlite3.IntegrityError:
            continue

    if not new_key:
        keys = get_all_keys()
        stats = get_stats(keys)
        return templates.TemplateResponse("dashboard.html", {
            "request": request, "keys": keys,
            "error": "Не удалось создать ключ",
            "new_key": "", "message": "", **stats
        })

    keys = get_all_keys()
    stats = get_stats(keys)
    return templates.TemplateResponse("dashboard.html", {
        "request": request, "keys": keys,
        "new_key": new_key, "message": "", "error": "", **stats
    })


@app.post("/dashboard/block", include_in_schema=False)
def dashboard_block(request: Request, license_key: str = Form(...)):
    if not is_authenticated(request):
        return RedirectResponse("/login", status_code=302)

    with get_db() as conn:
        result = conn.execute(
            "UPDATE licenses SET status = 'blocked' WHERE license_key = ?",
            (license_key,)
        )
        conn.commit()

    keys = get_all_keys()
    stats = get_stats(keys)
    msg = f"Ключ {license_key} заблокирован" if result.rowcount else "Ключ не найден"
    return templates.TemplateResponse("dashboard.html", {
        "request": request, "keys": keys,
        "message": msg if result.rowcount else "",
        "error": "" if result.rowcount else msg,
        "new_key": "", **stats
    })


# ══════════════════════════════════════════════
# REST API (публичный + защищённый)
# ══════════════════════════════════════════════

class VerifyRequest(BaseModel):
    license_key: str

class VerifyResponse(BaseModel):
    valid: bool
    reason: str | None = None

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
    """✅ Публичный — проверяет лицензионный ключ."""
    key = body.license_key.strip().upper()
    with get_db() as conn:
        row = conn.execute(
            "SELECT * FROM licenses WHERE license_key = ?", (key,)
        ).fetchone()

    if row is None:
        return VerifyResponse(valid=False, reason="Лицензионный ключ не найден")
    if row["status"] == "blocked":
        return VerifyResponse(valid=False, reason="Лицензионный ключ заблокирован")

    expires_at = datetime.fromisoformat(row["expires_at"])
    if datetime.now(timezone.utc) > expires_at:
        return VerifyResponse(valid=False, reason="Срок действия лицензии истёк")

    if row["activation_count"] >= row["activation_limit"]:
        return VerifyResponse(
            valid=False,
            reason=f"Превышен лимит активаций ({row['activation_limit']})"
        )

    with get_db() as conn:
        conn.execute(
            "UPDATE licenses SET activation_count = activation_count + 1 WHERE license_key = ?",
            (key,)
        )
        conn.commit()

    return VerifyResponse(valid=True)


@app.post("/create_key", response_model=CreateKeyResponse, tags=["Admin API"])
def create_key(body: CreateKeyRequest, authorization: str = Header(default=None)):
    """🔒 Header: Authorization: <пароль>"""
    require_admin(authorization)
    if body.expires_in_days <= 0 or body.activation_limit <= 0:
        raise HTTPException(status_code=400, detail="Значения должны быть > 0")

    created_at = datetime.now(timezone.utc)
    expires_at = created_at + timedelta(days=body.expires_in_days)

    for _ in range(10):
        key = generate_license_key()
        try:
            with get_db() as conn:
                conn.execute(
                    """INSERT INTO licenses
                       (license_key, status, created_at, expires_at, activation_count, activation_limit)
                       VALUES (?, 'active', ?, ?, 0, ?)""",
                    (key, created_at.isoformat(), expires_at.isoformat(), body.activation_limit)
                )
                conn.commit()
            return CreateKeyResponse(
                license_key=key,
                expires_at=expires_at.isoformat(),
                activation_limit=body.activation_limit,
            )
        except sqlite3.IntegrityError:
            continue

    raise HTTPException(status_code=500, detail="Не удалось создать ключ")


@app.get("/keys", tags=["Admin API"])
def list_keys(limit: int = 50, offset: int = 0,
              authorization: str = Header(default=None)):
    """🔒 Header: Authorization: <пароль>"""
    require_admin(authorization)
    with get_db() as conn:
        rows = conn.execute(
            "SELECT * FROM licenses ORDER BY created_at DESC LIMIT ? OFFSET ?",
            (limit, offset)
        ).fetchall()
        total = conn.execute("SELECT COUNT(*) FROM licenses").fetchone()[0]
    return {"total": total, "keys": [dict(r) for r in rows]}


@app.post("/block_key", tags=["Admin API"])
def block_key(body: VerifyRequest, authorization: str = Header(default=None)):
    """🔒 Header: Authorization: <пароль>"""
    require_admin(authorization)
    key = body.license_key.strip().upper()
    with get_db() as conn:
        result = conn.execute(
            "UPDATE licenses SET status = 'blocked' WHERE license_key = ?", (key,)
        )
        conn.commit()
        if result.rowcount == 0:
            raise HTTPException(status_code=404, detail="Ключ не найден")
    return {"success": True, "license_key": key, "status": "blocked"}
