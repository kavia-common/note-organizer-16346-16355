import os
from datetime import timedelta
from typing import Optional, List

from fastapi import FastAPI, Depends, HTTPException, status, Path, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel, Field, EmailStr
from jose import JWTError, jwt
from passlib.context import CryptContext
from dotenv import load_dotenv
from starlette.responses import JSONResponse

# Load environment variables from .env if present
load_dotenv()

# Configuration with environment variables and sensible defaults
JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY", "CHANGE_ME_DEV_SECRET")
JWT_ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")
JWT_ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("JWT_ACCESS_TOKEN_EXPIRE_MINUTES", "60"))
CORS_ALLOW_ORIGINS = [o.strip() for o in os.getenv("CORS_ALLOW_ORIGINS", "*").split(",")] if os.getenv("CORS_ALLOW_ORIGINS") else ["*"]

# OAuth2 configuration
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")

# Password hashing context
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# In-memory stores (for demo). In production, replace with database.
# Structure:
# users: {username: {"username": str, "email": str, "hashed_password": str, "id": int}}
# notes: {note_id: {...}}
# tags: set[str]
# folders: set[str]
users_store = {}
notes_store = {}
tags_store = set()
folders_store = set()

# Simple incremental counters for IDs (in-memory demo)
_user_id_counter = 1
_note_id_counter = 1

# -----------------------------
# Pydantic models and schemas
# -----------------------------

class Token(BaseModel):
    access_token: str = Field(..., description="JWT access token")
    token_type: str = Field(default="bearer", description="Token type")

class TokenData(BaseModel):
    username: Optional[str] = Field(None, description="Username embedded in the token")

class UserBase(BaseModel):
    username: str = Field(..., min_length=3, max_length=50, description="Unique username")
    email: EmailStr = Field(..., description="User email")

class UserCreate(UserBase):
    password: str = Field(..., min_length=6, max_length=128, description="User password")

class UserPublic(UserBase):
    id: int = Field(..., description="User ID")

class UserLogin(BaseModel):
    username: str = Field(..., description="Username")
    password: str = Field(..., description="Password")

class NoteBase(BaseModel):
    title: str = Field(..., max_length=200, description="Note title")
    content: str = Field(..., description="Note content in markdown or text")
    tags: List[str] = Field(default_factory=list, description="List of tag names")
    folder: Optional[str] = Field(default=None, description="Folder name")

class NoteCreate(NoteBase):
    pass

class NoteUpdate(BaseModel):
    title: Optional[str] = Field(None, max_length=200, description="Updated title")
    content: Optional[str] = Field(None, description="Updated content")
    tags: Optional[List[str]] = Field(default=None, description="Updated tags list")
    folder: Optional[Optional[str]] = Field(default=None, description="Updated folder (string or null to clear)")

class NotePublic(NoteBase):
    id: int = Field(..., description="Note ID")
    owner_id: int = Field(..., description="Owner user ID")

# -----------------------------
# Utility functions
# -----------------------------

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    # Compute expiration datetime directly; avoid creating unused temporary variables
    from datetime import datetime, timezone
    expire_dt = datetime.now(timezone.utc) + (expires_delta or timedelta(minutes=JWT_ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire_dt})
    encoded_jwt = jwt.encode(to_encode, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)
    return encoded_jwt

def get_user(username: str) -> Optional[dict]:
    return users_store.get(username)

def authenticate_user(username: str, password: str) -> Optional[dict]:
    user = get_user(username)
    if not user:
        return None
    if not verify_password(password, user["hashed_password"]):
        return None
    return user

async def get_current_user(token: str = Depends(oauth2_scheme)) -> dict:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_data = TokenData(username=username)
    except JWTError:
        raise credentials_exception
    user = get_user(username=token_data.username) if token_data.username else None
    if user is None:
        raise credentials_exception
    return user

def add_tags_and_folders(tags: List[str], folder: Optional[str]) -> None:
    for t in tags or []:
        if t:
            tags_store.add(t)
    if folder:
        folders_store.add(folder)

# -----------------------------
# FastAPI app and metadata
# -----------------------------

app = FastAPI(
    title="Notes Organizer API",
    description=(
        "A production-style FastAPI backend for a Note Organizer app.\n"
        "- JWT-based authentication\n"
        "- CRUD for notes\n"
        "- Organization via tags and folders\n"
        "- Search notes\n"
        "This demo uses in-memory storage. Replace with database in production."
    ),
    version="1.0.0",
    contact={"name": "Notes Backend", "url": "https://example.com"},
    terms_of_service="https://example.com/terms",
    license_info={"name": "MIT"},
    openapi_tags=[
        {"name": "health", "description": "Service health and readiness"},
        {"name": "auth", "description": "User authentication and session management"},
        {"name": "users", "description": "User management"},
        {"name": "notes", "description": "Notes CRUD and management"},
        {"name": "organization", "description": "Tags and folders management"},
        {"name": "search", "description": "Search notes"},
    ],
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ALLOW_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# -----------------------------
# Health endpoint
# -----------------------------

# PUBLIC_INTERFACE
@app.get("/", tags=["health"], summary="Health Check", description="Simple liveness probe returning Healthy.")
def health_check():
    """Health check endpoint."""
    return {"message": "Healthy"}

# -----------------------------
# Auth endpoints
# -----------------------------

# PUBLIC_INTERFACE
@app.post("/auth/register", response_model=UserPublic, tags=["auth"], summary="Register a new user", responses={
    201: {"description": "User registered successfully"},
    400: {"description": "User already exists"},
})
async def register_user(payload: UserCreate):
    """
    Register a new user with a username, email, and password.
    Returns the created user information (without password).
    """
    global _user_id_counter
    if payload.username in users_store:
        raise HTTPException(status_code=400, detail="Username already registered")
    hashed_password = get_password_hash(payload.password)
    user_obj = {
        "id": _user_id_counter,
        "username": payload.username,
        "email": str(payload.email),
        "hashed_password": hashed_password,
    }
    users_store[payload.username] = user_obj
    _user_id_counter += 1
    return UserPublic(id=user_obj["id"], username=user_obj["username"], email=user_obj["email"])

# PUBLIC_INTERFACE
@app.post("/auth/login", response_model=Token, tags=["auth"], summary="Login to obtain JWT token", responses={
    200: {"description": "Login successful, JWT issued"},
    401: {"description": "Invalid credentials"},
})
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    """
    Login with username and password to obtain a JWT access token.
    The token must be sent as a Bearer token in the Authorization header to access protected endpoints.
    """
    user = authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=JWT_ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(data={"sub": user["username"]}, expires_delta=access_token_expires)
    return Token(access_token=access_token, token_type="bearer")

# PUBLIC_INTERFACE
@app.get("/auth/me", response_model=UserPublic, tags=["auth"], summary="Get current user profile")
async def read_users_me(current_user: dict = Depends(get_current_user)):
    """
    Return the profile of the currently authenticated user.
    """
    return UserPublic(id=current_user["id"], username=current_user["username"], email=current_user["email"])

# -----------------------------
# Notes CRUD
# -----------------------------

# PUBLIC_INTERFACE
@app.post("/notes", response_model=NotePublic, status_code=201, tags=["notes"], summary="Create a new note")
async def create_note(note: NoteCreate, current_user: dict = Depends(get_current_user)):
    """
    Create a new note owned by the authenticated user.
    """
    global _note_id_counter
    # Validate and register tags/folders
    add_tags_and_folders(note.tags, note.folder)

    note_obj = {
        "id": _note_id_counter,
        "title": note.title,
        "content": note.content,
        "tags": list(dict.fromkeys([t for t in (note.tags or []) if t])),  # de-dup and remove empty
        "folder": note.folder or None,
        "owner_id": current_user["id"],
    }
    notes_store[_note_id_counter] = note_obj
    _note_id_counter += 1
    return NotePublic(**note_obj)

# PUBLIC_INTERFACE
@app.get("/notes", response_model=List[NotePublic], tags=["notes"], summary="List notes")
async def list_notes(
    current_user: dict = Depends(get_current_user),
    folder: Optional[str] = Query(default=None, description="Filter by folder"),
    tag: Optional[str] = Query(default=None, description="Filter by tag"),
):
    """
    List all notes owned by the current user, optionally filtering by folder or tag.
    """
    results = []
    for n in notes_store.values():
        if n["owner_id"] != current_user["id"]:
            continue
        if folder is not None and n.get("folder") != folder:
            continue
        if tag is not None and tag not in (n.get("tags") or []):
            continue
        results.append(NotePublic(**n))
    return results

# PUBLIC_INTERFACE
@app.get("/notes/{note_id}", response_model=NotePublic, tags=["notes"], summary="Get note by ID")
async def get_note(
    note_id: int = Path(..., description="Note ID"),
    current_user: dict = Depends(get_current_user),
):
    """
    Retrieve a single note by its ID, ensuring it belongs to the current user.
    """
    n = notes_store.get(note_id)
    if not n or n["owner_id"] != current_user["id"]:
        raise HTTPException(status_code=404, detail="Note not found")
    return NotePublic(**n)

# PUBLIC_INTERFACE
@app.put("/notes/{note_id}", response_model=NotePublic, tags=["notes"], summary="Update a note")
async def update_note(
    note_id: int = Path(..., description="Note ID"),
    payload: NoteUpdate = ...,
    current_user: dict = Depends(get_current_user),
):
    """
    Update a note's fields. Only provided fields are updated.
    """
    n = notes_store.get(note_id)
    if not n or n["owner_id"] != current_user["id"]:
        raise HTTPException(status_code=404, detail="Note not found")

    if payload.title is not None:
        n["title"] = payload.title
    if payload.content is not None:
        n["content"] = payload.content
    if payload.tags is not None:
        n["tags"] = list(dict.fromkeys([t for t in (payload.tags or []) if t]))
    if "folder" in payload.__dict__:
        # Accept None to clear folder, or string to set
        n["folder"] = payload.folder if payload.folder else None

    # Update org stores
    add_tags_and_folders(n.get("tags") or [], n.get("folder"))
    return NotePublic(**n)

# PUBLIC_INTERFACE
@app.delete("/notes/{note_id}", status_code=204, tags=["notes"], summary="Delete a note")
async def delete_note(
    note_id: int = Path(..., description="Note ID"),
    current_user: dict = Depends(get_current_user),
):
    """
    Delete a note by its ID, ensuring it belongs to the current user.
    """
    n = notes_store.get(note_id)
    if not n or n["owner_id"] != current_user["id"]:
        raise HTTPException(status_code=404, detail="Note not found")
    del notes_store[note_id]
    return JSONResponse(status_code=204, content=None)

# -----------------------------
# Organization: tags and folders
# -----------------------------

# PUBLIC_INTERFACE
@app.get("/organization/tags", response_model=List[str], tags=["organization"], summary="List tags")
async def list_tags(current_user: dict = Depends(get_current_user)):
    """
    List all tags that exist in the system for the current user's notes.
    Note: This demo uses a global tags_store; in production, scope tags per user.
    """
    # Filter tags based on current user's notes to avoid showing unused tags for that user
    user_tags = set()
    for n in notes_store.values():
        if n["owner_id"] == current_user["id"]:
            for t in n.get("tags") or []:
                user_tags.add(t)
    return sorted(user_tags)

# PUBLIC_INTERFACE
@app.get("/organization/folders", response_model=List[str], tags=["organization"], summary="List folders")
async def list_folders(current_user: dict = Depends(get_current_user)):
    """
    List all folders that exist in the system for the current user's notes.
    Note: This demo uses a global folders_store; in production, scope folders per user.
    """
    user_folders = set()
    for n in notes_store.values():
        if n["owner_id"] == current_user["id"] and n.get("folder"):
            user_folders.add(n["folder"])
    return sorted(user_folders)

# -----------------------------
# Search
# -----------------------------

# PUBLIC_INTERFACE
@app.get("/search", response_model=List[NotePublic], tags=["search"], summary="Search notes")
async def search_notes(
    q: str = Query(..., min_length=1, description="Search query string matched against title and content"),
    current_user: dict = Depends(get_current_user),
    tag: Optional[str] = Query(default=None, description="Optional tag filter"),
    folder: Optional[str] = Query(default=None, description="Optional folder filter"),
):
    """
    Search notes owned by the current user by text query, optionally filtered by tag and folder.
    """
    query_lower = q.lower()
    results = []
    for n in notes_store.values():
        if n["owner_id"] != current_user["id"]:
            continue
        if tag is not None and tag not in (n.get("tags") or []):
            continue
        if folder is not None and n.get("folder") != folder:
            continue
        if query_lower in (n["title"] or "").lower() or query_lower in (n["content"] or "").lower():
            results.append(NotePublic(**n))
    return results
