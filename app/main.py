from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional
from .seed import CONTENT

app = FastAPI(title="Colima en el mapa API", version="0.1.0")
app.add_middleware(CORSMiddleware, allow_origins=["http://localhost:5173"], allow_methods=["*"], allow_headers=["*"])

class ContentUpdate(BaseModel):
    name: Optional[str] = None
    active: Optional[bool] = None
    description: Optional[str] = None

@app.get("/api/health")
def health(): return {"status": "ok"}

@app.get("/api/content")
def list_content(type: Optional[str] = None, municipality: Optional[str] = None, q: Optional[str] = None):
    rows = [x.copy() for x in CONTENT if x["active"]]
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
def update_content(slug: str, payload: ContentUpdate):
    item = next((x for x in CONTENT if x["slug"] == slug), None)
    if not item: raise HTTPException(404, "Contenido no encontrado")
    for key, value in payload.model_dump(exclude_unset=True).items(): item[key] = value
    return item
