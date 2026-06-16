"""
License Server — простой бэкенд для проверки лицензионных ключей.
FastAPI + SQLite (через встроенный sqlite3, без ORM).

Запуск:
    uvicorn main:app --reload
"""

import sqlite3
import secrets
import string
from datetime import datetime, timedelta, timezone
from contextlib import contextmanager
from pathlib import Path

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

# ──────────────────────────────────────────────
# Конфигурация
# ──────────────────────────────────────────────
DB_PATH = Path(__file__).parent / "licenses.db"

app = FastAPI(
    title="License Server",
    description="Сервер проверки и создания лицензионных ключей",
    version="1.0.0",
)


# ──────────────────────────────────────────────
# База данных
# ──────────────────────────────────────────────

def get_db() -> sqlite3.Connection:
    """Открывает соединение с SQLite. row_factory для доступа по имени колонки."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """Создаёт таблицу licenses если её нет."""
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


# Инициализируем БД при старте
init_db()


# ──────────────────────────────────────────────
# Схемы запросов / ответов (Pydantic)
# ──────────────────────────────────────────────

class VerifyRequest(BaseModel):
    license_key: str


class VerifyResponse(BaseModel):
    valid: bool
    reason: str | None = None


class CreateKeyRequest(BaseModel):
    expires_in_days: int = 365      # Срок действия в днях
    activation_limit: int = 1       # Лимит активаций


class CreateKeyResponse(BaseModel):
    license_key: str
    expires_at: str
    activation_limit: int


# ──────────────────────────────────────────────
# Вспомогательные функции
# ──────────────────────────────────────────────

def generate_license_key() -> str:
    """
    Генерирует ключ формата XXXX-XXXX-XXXX-XXXX.
    Используются только заглавные буквы и цифры (без O, 0, I, 1 — легче читать).
    """
    alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
    def segment():
        return "".join(secrets.choice(alphabet) for _ in range(4))
    return "-".join(segment() for _ in range(4))


def now_iso() -> str:
    """Текущее время UTC в ISO-формате."""
    return datetime.now(timezone.utc).isoformat()


def parse_dt(iso: str) -> datetime:
    """Парсит ISO datetime строку обратно в объект."""
    return datetime.fromisoformat(iso)


# ──────────────────────────────────────────────
# Эндпоинты
# ──────────────────────────────────────────────

@app.get("/", tags=["Info"])
def root():
    """Проверка что сервер работает."""
    return {"status": "ok", "service": "License Server v1.0"}


@app.post("/verify", response_model=VerifyResponse, tags=["Licenses"])
def verify_license(body: VerifyRequest):
    """
    Проверяет лицензионный ключ.

    Возвращает {"valid": true} если:
    - ключ существует в базе
    - статус не blocked
    - срок действия не истёк
    - не превышен лимит активаций

    При успехе увеличивает activation_count на 1.
    """
    key = body.license_key.strip().upper()

    with get_db() as conn:
        row = conn.execute(
            "SELECT * FROM licenses WHERE license_key = ?", (key,)
        ).fetchone()

    # 1. Ключ не найден
    if row is None:
        return VerifyResponse(valid=False, reason="Лицензионный ключ не найден")

    # 2. Ключ заблокирован
    if row["status"] == "blocked":
        return VerifyResponse(valid=False, reason="Лицензионный ключ заблокирован")

    # 3. Срок истёк
    expires_at = parse_dt(row["expires_at"])
    if datetime.now(timezone.utc) > expires_at:
        return VerifyResponse(valid=False, reason="Срок действия лицензии истёк")

    # 4. Превышен лимит активаций
    if row["activation_count"] >= row["activation_limit"]:
        return VerifyResponse(
            valid=False,
            reason=f"Превышен лимит активаций ({row['activation_limit']})"
        )

    # 5. Всё ок — увеличиваем счётчик активаций
    with get_db() as conn:
        conn.execute(
            "UPDATE licenses SET activation_count = activation_count + 1 WHERE license_key = ?",
            (key,)
        )
        conn.commit()

    return VerifyResponse(valid=True)


@app.post("/create_key", response_model=CreateKeyResponse, tags=["Licenses"])
def create_key(body: CreateKeyRequest):
    """
    Создаёт новый лицензионный ключ формата XXXX-XXXX-XXXX-XXXX.

    Параметры:
    - expires_in_days: через сколько дней истекает (по умолчанию 365)
    - activation_limit: сколько раз можно активировать (по умолчанию 1)
    """
    if body.expires_in_days <= 0:
        raise HTTPException(status_code=400, detail="expires_in_days должно быть > 0")
    if body.activation_limit <= 0:
        raise HTTPException(status_code=400, detail="activation_limit должно быть > 0")

    created_at = datetime.now(timezone.utc)
    expires_at = created_at + timedelta(days=body.expires_in_days)

    # Генерируем уникальный ключ (на случай коллизии — повторяем)
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
            # Коллизия ключа — крайне редко, но обрабатываем
            continue
    else:
        raise HTTPException(status_code=500, detail="Не удалось сгенерировать уникальный ключ")

    return CreateKeyResponse(
        license_key=key,
        expires_at=expires_at.isoformat(),
        activation_limit=body.activation_limit,
    )


@app.get("/keys", tags=["Admin"])
def list_keys(limit: int = 50, offset: int = 0):
    """Список всех ключей (для административных целей)."""
    with get_db() as conn:
        rows = conn.execute(
            "SELECT * FROM licenses ORDER BY created_at DESC LIMIT ? OFFSET ?",
            (limit, offset)
        ).fetchall()
        total = conn.execute("SELECT COUNT(*) FROM licenses").fetchone()[0]

    return {
        "total": total,
        "keys": [dict(r) for r in rows]
    }


@app.post("/block_key", tags=["Admin"])
def block_key(body: VerifyRequest):
    """Блокирует лицензионный ключ."""
    key = body.license_key.strip().upper()
    with get_db() as conn:
        result = conn.execute(
            "UPDATE licenses SET status = 'blocked' WHERE license_key = ?", (key,)
        )
        conn.commit()
        if result.rowcount == 0:
            raise HTTPException(status_code=404, detail="Ключ не найден")
    return {"success": True, "license_key": key, "status": "blocked"}
