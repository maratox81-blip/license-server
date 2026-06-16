# License Server

Простой бэкенд для проверки и выдачи лицензионных ключей.  
**FastAPI + SQLite + Python**

---

## Установка

```bash
pip install fastapi uvicorn
```

---

## Запуск

```bash
cd D:\kiroproject\license_server
uvicorn main:app --reload
```

Сервер запустится на: **http://127.0.0.1:8000**  
Документация (Swagger): **http://127.0.0.1:8000/docs**

---

## API

### POST `/verify` — Проверить ключ

**Запрос:**
```json
{ "license_key": "ABCD-EFGH-IJKL-MNOP" }
```

**Ответ (успех):**
```json
{ "valid": true }
```

**Ответ (ошибка):**
```json
{ "valid": false, "reason": "Срок действия лицензии истёк" }
```

Возможные причины отказа:
- `"Лицензионный ключ не найден"`
- `"Лицензионный ключ заблокирован"`
- `"Срок действия лицензии истёк"`
- `"Превышен лимит активаций (N)"`

---

### POST `/create_key` — Создать ключ

**Запрос:**
```json
{
  "expires_in_days": 365,
  "activation_limit": 3
}
```

**Ответ:**
```json
{
  "license_key": "A3BC-D4EF-GH5J-KL6M",
  "expires_at": "2027-06-16T10:00:00+00:00",
  "activation_limit": 3
}
```

---

### GET `/keys` — Список всех ключей (admin)

```
GET /keys?limit=50&offset=0
```

---

### POST `/block_key` — Заблокировать ключ (admin)

**Запрос:**
```json
{ "license_key": "A3BC-D4EF-GH5J-KL6M" }
```

---

## Структура БД (licenses.db)

| Поле              | Тип      | Описание                        |
|-------------------|----------|---------------------------------|
| id                | INTEGER  | Первичный ключ                  |
| license_key       | TEXT     | Уникальный ключ XXXX-XXXX-XXXX-XXXX |
| status            | TEXT     | `active` / `blocked`            |
| created_at        | TEXT     | Дата создания (ISO UTC)         |
| expires_at        | TEXT     | Дата истечения (ISO UTC)        |
| activation_count  | INTEGER  | Сколько раз активировали        |
| activation_limit  | INTEGER  | Максимум активаций              |
