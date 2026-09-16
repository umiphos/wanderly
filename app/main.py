import base64
import hashlib
import hmac
import json
import os
import sqlite3
import time
from typing import Optional

from fastapi import Depends, FastAPI, Header, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from .seed import CONTENT


ADMIN_EMAIL = os.getenv("ADMIN_EMAIL", "")
ADMIN_PASSWORD_HASH = os.getenv("ADMIN_PASSWORD_HASH", "")
SECRET_KEY = os.getenv("SECRET_KEY", "")
TOKEN_TTL_SECONDS = int(os.getenv("TOKEN_TTL_SECONDS", "86400"))
CONTENT_DB_PATH = os.getenv("CONTENT_DB_PATH", "/data/content.db")

CORS_ORIGINS = [
    origin.strip()
    for origin in os.getenv("CORS_ORIGINS", "http://localhost:5173").split(",")
    if origin.strip()
]

app = FastAPI(title="Colima en el mapa API", version="0.1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_methods=["*"],
    allow_headers=["*"],
)


class AdminLogin(BaseModel):
    email: str
    password: str


class ContentUpdate(BaseModel):
    name: Optional[str] = None
    active: Optional[bool] = None
    description: Optional[str] = None


def get_db_connection():
    db_dir = os.path.dirname(CONTENT_DB_PATH)
    if db_dir:
        os.makedirs(db_dir, exist_ok=True)

    connection = sqlite3.connect(CONTENT_DB_PATH)
    connection.row_factory = sqlite3.Row
    return connection


def serialize_content_item(item: dict) -> dict:
    row = item.copy()
    row["active"] = bool(row["active"])
    row["featured"] = bool(row["featured"])
    row["tags"] = json.loads(row["tags"] or "[]") if isinstance(row["tags"], str) else row["tags"]
    return row


def init_content_db():
    with get_db_connection() as connection:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS content (
                slug TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                type TEXT NOT NULL,
                municipality TEXT NOT NULL,
                active INTEGER NOT NULL DEFAULT 1,
                featured INTEGER NOT NULL DEFAULT 0,
                description TEXT NOT NULL,
                schedule TEXT,
                lat REAL,
                lng REAL,
                location_note TEXT,
                tags TEXT NOT NULL DEFAULT '[]',
                image TEXT NOT NULL,
                position INTEGER NOT NULL DEFAULT 0
            )
            """
        )

        count = connection.execute("SELECT COUNT(*) FROM content").fetchone()[0]
        if count:
            return

        for position, item in enumerate(CONTENT):
            connection.execute(
                """
                INSERT INTO content (
                    slug, name, type, municipality, active, featured, description,
                    schedule, lat, lng, location_note, tags, image, position
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    item["slug"],
                    item["name"],
                    item["type"],
                    item["municipality"],
                    int(item.get("active", True)),
                    int(item.get("featured", False)),
                    item["description"],
                    item.get("schedule"),
                    item.get("lat"),
                    item.get("lng"),
                    item.get("location_note"),
                    json.dumps(item.get("tags", []), ensure_ascii=False),
                    item["image"],
                    position,
                ),
            )


def list_content_rows():
    init_content_db()
    with get_db_connection() as connection:
        rows = connection.execute("SELECT * FROM content ORDER BY position, name").fetchall()
        return [serialize_content_item(dict(row)) for row in rows]


def get_content_row(slug: str):
    init_content_db()
    with get_db_connection() as connection:
        row = connection.execute("SELECT * FROM content WHERE slug = ?", (slug,)).fetchone()
        return serialize_content_item(dict(row)) if row else None


def update_content_row(slug: str, updates: dict):
    if not updates:
        return get_content_row(slug)

    allowed_fields = {"name", "active", "description"}
    update_items = {key: value for key, value in updates.items() if key in allowed_fields}
    if not update_items:
        return get_content_row(slug)

    set_clause = ", ".join(f"{key} = ?" for key in update_items)
    values = [int(value) if key == "active" else value for key, value in update_items.items()]
    values.append(slug)

    init_content_db()
    with get_db_connection() as connection:
        connection.execute(f"UPDATE content SET {set_clause} WHERE slug = ?", values)

    return get_content_row(slug)


def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode("utf-8")).hexdigest()


def encode_base64_url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("utf-8").rstrip("=")


def decode_base64_url(data: str) -> bytes:
    padding = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + padding)


def sign_token(payload: dict) -> str:
    if not SECRET_KEY:
        raise HTTPException(500, "SECRET_KEY no configurado")

    encoded_payload = encode_base64_url(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
    signature = hmac.new(
        SECRET_KEY.encode("utf-8"),
        encoded_payload.encode("utf-8"),
        hashlib.sha256,
    ).digest()

    return f"{encoded_payload}.{encode_base64_url(signature)}"


def verify_token(token: str) -> dict:
    if not SECRET_KEY:
        raise HTTPException(500, "SECRET_KEY no configurado")

    try:
        encoded_payload, encoded_signature = token.split(".", 1)
    except ValueError:
        raise HTTPException(401, "Token invalido")

    expected_signature = hmac.new(
        SECRET_KEY.encode("utf-8"),
        encoded_payload.encode("utf-8"),
        hashlib.sha256,
    ).digest()

    if not hmac.compare_digest(encode_base64_url(expected_signature), encoded_signature):
        raise HTTPException(401, "Token invalido")

    try:
        payload = json.loads(decode_base64_url(encoded_payload))
    except Exception:
        raise HTTPException(401, "Token invalido")

    if payload.get("exp", 0) < int(time.time()):
        raise HTTPException(401, "Sesion expirada")

    return payload


def require_admin(authorization: str = Header(default="")) -> dict:
    scheme, _, token = authorization.partition(" ")
    if scheme.lower() != "bearer" or not token:
        raise HTTPException(401, "No autorizado")

    payload = verify_token(token)
    if payload.get("sub") != ADMIN_EMAIL:
        raise HTTPException(401, "No autorizado")

    return payload


@app.get("/api/health")
def health():
    return {"status": "ok"}


@app.get("/api/content")
def list_content(type: Optional[str] = None, municipality: Optional[str] = None, q: Optional[str] = None):
    rows = list_content_rows()
    if type:
        rows = [x for x in rows if x["type"] in type.split(",")]
    if municipality:
        rows = [x for x in rows if x["municipality"] == municipality]
    if q:
        rows = [x for x in rows if q.lower() in (x["name"] + " " + x["description"]).lower()]
    return rows


@app.get("/api/content/{slug}")
def get_content(slug: str):
    item = get_content_row(slug)
    if item and not item["active"]:
        item = None
    if not item:
        raise HTTPException(404, "Contenido no disponible")
    return item


@app.patch("/api/admin/content/{slug}")
def update_content(
    slug: str,
    payload: ContentUpdate,
    admin: dict = Depends(require_admin),
):
    item = get_content_row(slug)
    if not item:
        raise HTTPException(404, "Contenido no encontrado")

    return update_content_row(slug, payload.model_dump(exclude_unset=True))


@app.post("/api/admin/login")
def admin_login(payload: AdminLogin):
    if not ADMIN_EMAIL or not ADMIN_PASSWORD_HASH:
        raise HTTPException(500, "Credenciales admin no configuradas")

    valid_email = hmac.compare_digest(payload.email, ADMIN_EMAIL)
    valid_password = hmac.compare_digest(hash_password(payload.password), ADMIN_PASSWORD_HASH)

    if not valid_email or not valid_password:
        raise HTTPException(401, "Credenciales invalidas")

    expires_at = int(time.time()) + TOKEN_TTL_SECONDS
    token = sign_token({"sub": ADMIN_EMAIL, "exp": expires_at})

    return {
        "access_token": token,
        "token_type": "bearer",
        "expires_at": expires_at,
    }


@app.get("/api/admin/me")
def admin_me(admin: dict = Depends(require_admin)):
    return {"email": admin["sub"]}
