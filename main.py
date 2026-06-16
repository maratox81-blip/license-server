License Server — бэкенд для проверки лицензионных ключей.
FastAPI + SQLite.

Публичные endpoint'ы: /verify
Защищённые (только админ): /create_key, /block_key, /keys

Запуск:
    uvicorn main:app --reload
"""

import os
import sqlite3
import secrets
from datetime import datetime, timedelta, timezone
from pathlib import Path

from fastapi import FastAPI, HTTPException, Header
from fastapi.security import APIKeyHeader
from pydantic import BaseModel

# ──────────────────────────────────────────────
# Конфигурация
# ──────────────────────────────────────────────
DB_PATH = Path(__file__).parent / "licenses.db"

# Пароль берётся из переменной окружения ADMIN_PASSWORD.
# Установи его в Render: Settings → Environment → Add Environment Variable.
# Локально можно задать в терминале: set ADMIN_PASSWORD=твой_пароль
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "changeme")

app = FastAPI(
    title="License Server",
    description=(
        "Сервер лицензий.\n\n"
        "**Публичные:** `/verify`\n\n"
        "**Только для админа** (Header `Authorization: <пароль>`): "
        "`/create_key`, `/block_key`, `/keys`"
    ),
    version="1.1.0",
)


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
# Авторизация
# ──────────────────────────────────────────────

def require_admin(authorization: str = Header(default=None)):
    """
    Dependency: проверяет Header Authorization.
    Если пароль неверный или отсутствует — возвращает 401.
    """
    if not authorization or authorization != ADMIN_PASSWORD:
        raise HTTPException(
            status_code=401,
            detail="Unauthorized. Неверный или отсутствующий пароль администратора.",
            headers={"WWW-Authenticate": "ApiKey"},
        )


# ──────────────────────────────────────────────
# Схемы
# ──────────────────────────────────────────────

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


# ──────────────────────────────────────────────
# Вспомогательные функции
# ──────────────────────────────────────────────

def generate_license_key() -> str:
    alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
    def seg():
        return "".join(secrets.choice(alphabet) for _ in range(4))
    return "-".join(seg() for _ in range(4))


# ──────────────────────────────────────────────
# Публичные endpoint'ы
# ──────────────────────────────────────────────

@app.get("/", tags=["Info"])
def root():
    """Проверка что сервер работает."""
    return {"status": "ok", "service": "License Server v1.1"}


@app.post("/verify", response_model=VerifyResponse, tags=["Public"])
def verify_license(body: VerifyRequest):
    """
    ✅ Публичный endpoint — проверяет лицензионный ключ.
    Авторизация не требуется.
    """
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


# ──────────────────────────────────────────────
# Защищённые endpoint'ы (только админ)
# ──────────────────────────────────────────────

@app.post("/create_key", response_model=CreateKeyResponse, tags=["Admin"])
def create_key(body: CreateKeyRequest, authorization: str = Header(default=None)):
    """
    🔒 Только для админа. Header: `Authorization: <пароль>`

    Создаёт новый лицензионный ключ XXXX-XXXX-XXXX-XXXX.
    """
    require_admin(authorization)

    if body.expires_in_days <= 0:
        raise HTTPException(status_code=400, detail="expires_in_days должно быть > 0")
    if body.activation_limit <= 0:
        raise HTTPException(status_code=400, detail="activation_limit должно быть > 0")

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
            break
        except sqlite3.IntegrityError:
            continue
    else:
        raise HTTPException(status_code=500, detail="Не удалось сгенерировать уникальный ключ")

    return CreateKeyResponse(
        license_key=key,
        expires_at=expires_at.isoformat(),
        activation_limit=body.activation_limit,
    )


@app.get("/keys", tags=["Admin"])
def list_keys(
    limit: int = 50,
    offset: int = 0,
    authorization: str = Header(default=None)
):
    """
    🔒 Только для админа. Header: `Authorization: <пароль>`

    Список всех лицензионных ключей.
    """
    require_admin(authorization)

    with get_db() as conn:
        rows = conn.execute(
            "SELECT * FROM licenses ORDER BY created_at DESC LIMIT ? OFFSET ?",
            (limit, offset)
        ).fetchall()
        total = conn.execute("SELECT COUNT(*) FROM licenses").fetchone()[0]

    return {"total": total, "keys": [dict(r) for r in rows]}


@app.post("/block_key", tags=["Admin"])
def block_key(body: VerifyRequest, authorization: str = Header(default=None)):
    """
    🔒 Только для админа. Header: `Authorization: <пароль>`

    Блокирует лицензионный ключ.
    """
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

