import os
from datetime import datetime, timedelta, timezone
from typing import Optional, List

from fastapi import FastAPI, HTTPException, Depends, Header
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr, Field
import jwt
from passlib.context import CryptContext

from database import db, create_document, get_documents

# App
app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Security / Auth
JWT_SECRET = os.getenv("JWT_SECRET", "dev-secret-change-me")
JWT_ALG = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24 * 7  # 7 days
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Pydantic models
class RegisterRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=6)
    name: Optional[str] = None

class LoginRequest(BaseModel):
    email: EmailStr
    password: str

class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"

class MeResponse(BaseModel):
    id: str
    email: EmailStr
    name: Optional[str] = None
    role: str = "user"

# Settings models
class Member(BaseModel):
    id: str
    name: str
    email: EmailStr
    role: str = Field("Editor", pattern="^(Owner|Admin|Editor)$")

class SettingsPayload(BaseModel):
    # Account
    name: Optional[str] = None
    email: Optional[EmailStr] = None
    tz: Optional[str] = None
    notifNew: Optional[bool] = None
    notifVip: Optional[bool] = None
    notifAi: Optional[bool] = None
    twoFA: Optional[bool] = None

    # Workspace
    wsName: Optional[str] = None
    members: Optional[List[Member]] = None

    # AI
    tone: Optional[int] = Field(None, ge=0, le=100)
    brandVoice: Optional[str] = None
    exampleReplies: Optional[str] = None
    avoidWords: Optional[str] = None
    aiAutoReply: Optional[bool] = None
    maxReplyLen: Optional[int] = Field(None, ge=80, le=800)
    profanity: Optional[bool] = None
    keywords: Optional[List[str]] = None

    # Integrations
    integrations: Optional[List[dict]] = None

    # Billing
    plan: Optional[str] = None
    cycle: Optional[str] = None
    paymentMethod: Optional[str] = None

    # App prefs
    darkMode: Optional[bool] = None
    language: Optional[str] = None
    dtFormat: Optional[str] = None
    defaultView: Optional[str] = None


# Helpers

def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(password: str, hashed: str) -> bool:
    return pwd_context.verify(password, hashed)


def create_access_token(sub: str, email: str, role: str = "user") -> str:
    now = datetime.now(timezone.utc)
    payload = {
        "sub": sub,
        "email": email,
        "role": role,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)).timestamp()),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALG)


async def get_current_user(authorization: Optional[str] = Header(None)):
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="Not authenticated")
    token = authorization.split(" ", 1)[1]
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALG])
        email = payload.get("email")
        sub = payload.get("sub")
        if not email or not sub:
            raise HTTPException(status_code=401, detail="Invalid token")
        # lookup user
        user_doc = db["authuser"].find_one({"email": email}) if db else None
        if not user_doc:
            raise HTTPException(status_code=401, detail="User not found")
        return user_doc
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")


def default_settings_for_user(user_doc: dict) -> dict:
    # sensible defaults matching the UI
    return {
        "user_id": str(user_doc.get("_id")),
        "name": user_doc.get("name"),
        "email": user_doc.get("email"),
        "tz": "UTC",
        "notifNew": True,
        "notifVip": True,
        "notifAi": False,
        "twoFA": False,
        "wsName": "Default Workspace",
        "members": [
            {
                "id": str(user_doc.get("_id")),
                "name": user_doc.get("name") or user_doc.get("email").split("@")[0],
                "email": user_doc.get("email"),
                "role": "Owner",
            }
        ],
        "tone": 50,
        "brandVoice": "Friendly, concise, helpful. Avoid jargon.",
        "exampleReplies": "Thanks for reaching out! Here’s a quick answer…",
        "avoidWords": "guarantee, promise, 100%",
        "aiAutoReply": True,
        "maxReplyLen": 280,
        "profanity": True,
        "keywords": ["DEMO", "GUIDE", "PRICING"],
        "integrations": [
            {"name": "Instagram", "key": "instagram", "connected": True},
            {"name": "TikTok", "key": "tiktok", "connected": False},
            {"name": "Facebook", "key": "facebook", "connected": False},
            {"name": "Shopify", "key": "shopify", "connected": False},
        ],
        "plan": "Pro",
        "cycle": "Monthly",
        "paymentMethod": "Visa •••• 4242",
        "darkMode": True,
        "language": "English",
        "dtFormat": "YYYY-MM-DD, 24h",
        "defaultView": "Unified Inbox",
        "created_at": datetime.now(timezone.utc),
        "updated_at": datetime.now(timezone.utc),
    }

# Routes
@app.get("/")
def read_root():
    return {"message": "Hello from FastAPI Backend!"}


@app.get("/api/hello")
def hello():
    return {"message": "Hello from the backend API!"}


@app.get("/test")
def test_database():
    """Test endpoint to check if database is available and accessible"""
    response = {
        "backend": "✅ Running",
        "database": "❌ Not Available",
        "database_url": None,
        "database_name": None,
        "connection_status": "Not Connected",
        "collections": []
    }

    try:
        if db is not None:
            response["database"] = "✅ Available"
            response["database_url"] = "✅ Configured"
            response["database_name"] = db.name if hasattr(db, 'name') else "✅ Connected"
            response["connection_status"] = "Connected"

            try:
                collections = db.list_collection_names()
                response["collections"] = collections[:10]
                response["database"] = "✅ Connected & Working"
            except Exception as e:
                response["database"] = f"⚠️  Connected but Error: {str(e)[:50]}"
        else:
            response["database"] = "⚠️  Available but not initialized"

    except Exception as e:
        response["database"] = f"❌ Error: {str(e)[:50]}"

    import os as _os
    response["database_url"] = "✅ Set" if _os.getenv("DATABASE_URL") else "❌ Not Set"
    response["database_name"] = "✅ Set" if _os.getenv("DATABASE_NAME") else "❌ Not Set"

    return response


@app.post("/auth/register", response_model=TokenResponse)
def register(payload: RegisterRequest):
    if db is None:
        raise HTTPException(status_code=500, detail="Database not configured")
    email = payload.email.lower()
    # unique email check
    existing = db["authuser"].find_one({"email": email})
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered")

    user_doc = {
        "email": email,
        "name": payload.name or email.split("@")[0],
        "password_hash": hash_password(payload.password),
        "is_active": True,
        "role": "user",
        "created_at": datetime.now(timezone.utc),
        "updated_at": datetime.now(timezone.utc),
    }
    result = db["authuser"].insert_one(user_doc)
    user_id = str(result.inserted_id)
    # create default settings document for the user
    settings_doc = default_settings_for_user({"_id": result.inserted_id, **user_doc})
    db["settings"].insert_one(settings_doc)

    token = create_access_token(user_id, email, user_doc["role"])
    return TokenResponse(access_token=token)


@app.post("/auth/login", response_model=TokenResponse)
def login(payload: LoginRequest):
    if db is None:
        raise HTTPException(status_code=500, detail="Database not configured")
    email = payload.email.lower()
    user = db["authuser"].find_one({"email": email})
    if not user:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    if not verify_password(payload.password, user.get("password_hash", "")):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    if not user.get("is_active", True):
        raise HTTPException(status_code=403, detail="User is inactive")

    token = create_access_token(str(user.get("_id")), email, user.get("role", "user"))
    return TokenResponse(access_token=token)


@app.get("/auth/me", response_model=MeResponse)
def me(current_user=Depends(get_current_user)):
    return MeResponse(
        id=str(current_user.get("_id")),
        email=current_user.get("email"),
        name=current_user.get("name"),
        role=current_user.get("role", "user"),
    )


# Settings endpoints
@app.get("/settings")
def get_settings(current_user=Depends(get_current_user)):
    if db is None:
        raise HTTPException(status_code=500, detail="Database not configured")
    user_id = str(current_user.get("_id"))
    doc = db["settings"].find_one({"user_id": user_id})
    if not doc:
        # create defaults on demand
        doc = default_settings_for_user(current_user)
        db["settings"].insert_one(doc)
    # serialize
    doc["id"] = str(doc.get("_id")) if doc.get("_id") else None
    doc.pop("_id", None)
    return doc


@app.put("/settings")
def update_settings(payload: SettingsPayload, current_user=Depends(get_current_user)):
    if db is None:
        raise HTTPException(status_code=500, detail="Database not configured")
    user_id = str(current_user.get("_id"))
    update_data = {k: v for k, v in payload.dict(exclude_unset=True).items()}
    update_data["updated_at"] = datetime.now(timezone.utc)
    res = db["settings"].find_one_and_update(
        {"user_id": user_id},
        {"$set": update_data},
        upsert=True,
        return_document=True,
    )
    # fetch updated
    doc = db["settings"].find_one({"user_id": user_id})
    doc["id"] = str(doc.get("_id")) if doc.get("_id") else None
    doc.pop("_id", None)
    return doc


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
