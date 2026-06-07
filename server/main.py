import uvicorn
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from server.config import get_settings
from server.database import init_db
from server.auth.routes import router as auth_router
from server.auth.jwt_handler import verify_access_token
from server.chat.routes import router as chat_router
from server.chat.websocket import router as ws_router
from server.middleware.auth_middleware import LoggingMiddleware

settings = get_settings()

app = FastAPI(title="VChat Server", version="1.0.0")

# Request Logging Middleware
app.add_middleware(LoggingMiddleware)

# CORS configuration (essential for Android app HTTP and WebSocket connections)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Database table creation on startup
@app.on_event("startup")
async def on_startup():
    print("[Startup] Initializing Database tables...")
    try:
        await init_db()
        print("[Startup] Database tables initialized successfully.")
    except Exception as e:
        print(f"[Startup] Error initializing database tables: {e}")

# Legacy connection endpoint compatibility
@app.post("/connect")
async def connect(payload: dict):
    """Legacy compatibility endpoint verifying token from VChat application."""
    token = payload.get("token")
    if not token:
        raise HTTPException(status_code=400, detail="Missing token")
    
    decoded = verify_access_token(token)
    if not decoded:
        raise HTTPException(status_code=401, detail="Invalid or expired token")
        
    return {
        "status": "success",
        "username": decoded.get("username"),
        "user_id": decoded.get("sub")
    }

# Digital Asset Links for Android Passkey (WebAuthn) RP ID validation
@app.get("/.well-known/assetlinks.json")
async def asset_links():
    """Serve Digital Asset Links JSON for Android passkey RP ID validation."""
    return JSONResponse(
        content=[
            {
                "relation": [
                    "delegate_permission/common.handle_all_urls",
                    "delegate_permission/common.get_login_creds"
                ],
                "target": {
                    "namespace": "android_app",
                    "package_name": "com.ventura.vchat",
                    "sha256_cert_fingerprints": [
                        "BB:FD:5E:C2:E6:D1:A2:88:FC:8D:6F:70:BA:01:7C:E7:12:D3:25:BE:79:74:FA:B9:6D:9D:D0:70:AA:E8:EA:33"
                    ]
                }
            }
        ],
        media_type="application/json"
    )

# Health Check
@app.get("/health")
async def health():
    return {"status": "healthy"}

# Include Auth, Chat, and WebSocket routers
app.include_router(auth_router)
app.include_router(chat_router)
app.include_router(ws_router)

if __name__ == "__main__":
    print(f"Launching VChat Server on port {settings.SERVER_PORT}...")
    uvicorn.run("server.main:app", host="0.0.0.0", port=settings.SERVER_PORT, reload=False)
