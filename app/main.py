from fastapi import FastAPI, HTTPException, Depends, FastAPI, Header, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional
from .seed import CONTENT
import os
import base64
import hashlib
import hmac
import json
import os
import time
from typing import Optional


ADMIN_EMAIL = os.getenv("ADMIN_EMAIL", "")
ADMIN_PASSWORD_HASH = os.getenv("ADMIN_PASSWORD_HASH", "")
SECRET_KEY = os.getenv("SECRET_KEY", "")
TOKEN_TTL_SECONDS = int(os.getenv("TOKEN_TTL_SECONDS", "86400"))

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


def decode_base64_url(data: str) -> bytes:
    padding = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + padding)

def verify_token(token: str) -> dict:
    if not SECRET_KEY:
        raise HTTPException(500, "SECRET_KEY no configurado")

    try:
        encoded_payload, encoded_signature = token.split(".", 1)
    except ValueError:
        raise HTTPException(401, "Token inválido")

    expected_signature = hmac.new(
        SECRET_KEY.encode("utf-8"),
        encoded_payload.encode("utf-8"),
        hashlib.sha256,
    ).digest()

    if not hmac.compare_digest(encode_base64_url(expected_signature), encoded_signature):
        raise HTTPException(401, "Token inválido")

    try:
        payload = json.loads(decode_base64_url(encoded_payload))
    except Exception:
        raise HTTPException(401, "Token inválido")

    if payload.get("exp", 0) < int(time.time()):
        raise HTTPException(401, "Sesión expirada")

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
def health(): return {"status": "ok"}

@app.get("/api/content")
def list_content(type: Optional[str] = None, municipality: Optional[str] = None, q: Optional[str] = None):
    rows = [x.copy() for x in CONTENT]
    if type: rows = [x for x in rows if x["type"] in type.split(",")]
    if municipality: rows = [x for x in rows if x["municipality"] == municipality]
    if q: rows = [x for x in rows if q.lower() in (x["name"] + " " + x["description"]).lower()]
    return rows

@app.get("/api/content/{slug}")
def get_content(slug: str):
    item = next((x for x in CONTENT if x["slug"] == slug and x["active"]), None)
    if not item: raise HTTPException(404, "Contenido no disponible")
    return item

@app.patch("/api/admin/content/{slug}")
def update_content(
    slug: str,
    payload: ContentUpdate,
    admin: dict = Depends(require_admin),
):
    item = next((x for x in CONTENT if x["slug"] == slug), None)
    if not item:
        raise HTTPException(404, "Contenido no encontrado")

    for key, value in payload.model_dump(exclude_unset=True).items():
        item[key] = value

    return item


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

@app.post("/api/admin/login")
def admin_login(payload: AdminLogin):
    if not ADMIN_EMAIL or not ADMIN_PASSWORD_HASH:
        raise HTTPException(500, "Credenciales admin no configuradas")

    valid_email = hmac.compare_digest(payload.email, ADMIN_EMAIL)
    valid_password = hmac.compare_digest(hash_password(payload.password), ADMIN_PASSWORD_HASH)

    if not valid_email or not valid_password:
        raise HTTPException(401, "Credenciales inválidas")

    expires_at = int(time.time()) + TOKEN_TTL_SECONDS
    token = sign_token({"sub": ADMIN_EMAIL, "exp": expires_at})

    return {
        "access_token": token,
        "token_type": "bearer",
        "expires_at": expires_at,
    }
