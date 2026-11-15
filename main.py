import os
import secrets
import sqlite3
from datetime import datetime, timedelta
from typing import Optional

from fastapi import FastAPI, Depends, HTTPException, Request, Query
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
import bcrypt
from dotenv import load_dotenv

from database import get_db, init_db
from auth import create_token, admin_middleware

load_dotenv()
app = FastAPI(title="Key Server", version="1.0.0", docs_url="/docs")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

class LoginReq(BaseModel):
    username: str
    password: str

class VerifyReq(BaseModel):
    key: str
    hwid: Optional[str] = None

class GenerateReq(BaseModel):
    count: int = Field(default=1, ge=1, le=100)
    duration_days: int = Field(default=30, ge=1)
    max_devices: int = Field(default=1, ge=1)
    prefix: str = "KEY"

class UpdateKeyReq(BaseModel):
    status: str

@app.on_event("startup")
def startup():
    init_db()

@app.get("/health")
def health():
    return {"status": "ok", "time": datetime.utcnow().isoformat()}

@app.post("/api/auth/login", tags=["Auth"])
def login(body: LoginReq):
    with get_db() as db:
        user = db.execute("SELECT * FROM users WHERE username = ?", (body.username,)).fetchone()

    if not user or not bcrypt.checkpw(body.password.encode(), user["password"].encode()):
        raise HTTPException(401, "Sai tài khoản hoặc mật khẩu")

    token = create_token({"id": user["id"], "username": user["username"], "role": user["role"]})
    return {"token": token, "user": {"username": user["username"], "role": user["role"]}}

@app.post("/api/auth/verify", tags=["Auth"])
def verify_key(body: VerifyReq, request: Request):
    ip = request.client.host if request.client else "unknown"
    ua = request.headers.get("user-agent", "")

    with get_db() as db:
        record = db.execute("SELECT * FROM keys WHERE key_value = ?", (body.key,)).fetchone()

        def log(success: bool):
            db.execute(
                "INSERT INTO logs (key_value, action, ip, user_agent, success) VALUES (?, ?, ?, ?, ?)",
                (body.key, "verify", ip, ua, 1 if success else 0),
            )

        if not record:
            log(False)
            return JSONResponse({"valid": False, "message": "Key không tồn tại"}, 404)

        if record["status"] != "active":
            log(False)
            return JSONResponse({"valid": False, "message": "Key đã bị khóa"}, 403)

        if record["hwid"] and record["hwid"] != body.hwid:
            log(False)
            return JSONResponse({"valid": False, "message": "Key khóa với thiết bị khác"}, 403)

        expires_at = record["expires_at"]
        if expires_at and datetime.fromisoformat(expires_at) < datetime.utcnow():
            db.execute("UPDATE keys SET status='expired' WHERE id=?", (record["id"],))
            log(False)
            return JSONResponse({"valid": False, "message": "Key đã hết hạn"}, 403)

        if not expires_at:
            expires = datetime.utcnow() + timedelta(days=record["duration_days"])
            expires_at = expires.isoformat()
            db.execute(
                "UPDATE keys SET expires_at=?, hwid=?, used_count=used_count+1 WHERE id=?",
                (expires_at, body.hwid, record["id"]),
            )

        log(True)
        return {
            "valid": True,
            "message": "Xác thực thành công",
            "expires_at": expires_at,
            "duration_days": record["duration_days"],
        }

@app.post("/api/admin/keys", tags=["Admin"])
def generate_keys(body: GenerateReq, user: dict = Depends(admin_middleware)):
    created = []
    with get_db() as db:
        for _ in range(body.count):
            p1 = secrets.token_hex(4).upper()
            p2 = secrets.token_hex(4).upper()
            p3 = secrets.token_hex(4).upper()
            key_value = f"{body.prefix}-{p1}-{p2}-{p3}"
            try:
                db.execute(
                    "INSERT INTO keys (key_value, duration_days, max_devices, created_by) VALUES (?, ?, ?, ?)",
                    (key_value, body.duration_days, body.max_devices, user["id"]),
                )
                created.append(key_value)
            except sqlite3.IntegrityError:
                continue
    return {"success": True, "keys": created, "count": len(created)}

@app.get("/api/admin/keys", tags=["Admin"])
def list_keys(status: Optional[str] = None, q: Optional[str] = None, limit: int = Query(default=100, le=500), user: dict = Depends(admin_middleware)):
    sql = "SELECT * FROM keys WHERE 1=1"
    params = []
    if status:
        sql += " AND status = ?"
        params.append(status)
    if q:
        sql += " AND key_value LIKE ?"
        params.append(f"%{q}%")
    sql += " ORDER BY id DESC LIMIT ?"
    params.append(limit)

    with get_db() as db:
        rows = db.execute(sql, params).fetchall()
    return [dict(r) for r in rows]

@app.patch("/api/admin/keys/{key_id}", tags=["Admin"])
def update_key(key_id: int, body: UpdateKeyReq, user: dict = Depends(admin_middleware)):
    with get_db() as db:
        db.execute("UPDATE keys SET status=? WHERE id=?", (body.status, key_id))
    return {"success": True}

@app.delete("/api/admin/keys/{key_id}", tags=["Admin"])
def delete_key(key_id: int, user: dict = Depends(admin_middleware)):
    with get_db() as db:
        db.execute("DELETE FROM keys WHERE id=?", (key_id,))
    return {"success": True}

@app.get("/api/admin/stats", tags=["Admin"])
def stats(user: dict = Depends(admin_middleware)):
    with get_db() as db:
        total = db.execute("SELECT COUNT(*) c FROM keys").fetchone()["c"]
        active = db.execute("SELECT COUNT(*) c FROM keys WHERE status='active'").fetchone()["c"]
        used = db.execute("SELECT COUNT(*) c FROM keys WHERE used_count > 0").fetchone()["c"]
        logs = db.execute("SELECT COUNT(*) c FROM logs").fetchone()["c"]
        recent_logs = db.execute("SELECT * FROM logs ORDER BY id DESC LIMIT 20").fetchall()

    return {"total": total, "active": active, "used": used, "logs": logs, "recentLogs": [dict(l) for l in recent_logs]}

@app.get("/")
def index():
    return FileResponse("static/index.html")

if os.path.isdir("static"):
    app.mount("/static", StaticFiles(directory="static"), name="static")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=int(os.getenv("PORT", 3000)), reload=True)
