import json
import base64
import traceback
from typing import List
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.future import select
from sqlalchemy.ext.asyncio import AsyncSession
from webauthn.helpers import base64url_to_bytes, bytes_to_base64url

from server.database import get_db
from server.models import (
    User, PasskeyCredential, UserCreate, UserLogin, TokenResponse,
    PasskeyRegisterCompleteRequest, PasskeyLoginCompleteRequest
)
from server.auth.password import hash_password, verify_password
from server.auth.jwt_handler import create_access_token, get_current_user
from server.auth.passkey import (
    generate_reg_options, verify_reg_response,
    generate_auth_options, verify_auth_response
)

router = APIRouter(prefix="/auth", tags=["auth"])

@router.post("/register", response_model=TokenResponse)
async def register(user_data: UserCreate, db: AsyncSession = Depends(get_db)):
    """Register a new user with a username and password."""
    # Check if username exists
    result = await db.execute(select(User).filter(User.username == user_data.username))
    if result.scalars().first():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username already exists"
        )
    
    new_user = User(
        username=user_data.username,
        password_hash=hash_password(user_data.password)
    )
    db.add(new_user)
    await db.commit()
    await db.refresh(new_user)
    
    token = create_access_token(new_user.id, new_user.username)
    return TokenResponse(token=token, user_id=new_user.id, username=new_user.username)


@router.post("/login", response_model=TokenResponse)
async def login(credentials: UserLogin, db: AsyncSession = Depends(get_db)):
    """Log in with username and password, returning a JWT."""
    result = await db.execute(select(User).filter(User.username == credentials.username))
    user = result.scalars().first()
    
    if not user or not user.password_hash or not verify_password(credentials.password, user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password"
        )
    
    token = create_access_token(user.id, user.username)
    return TokenResponse(token=token, user_id=user.id, username=user.username)


@router.post("/request_token")
async def request_token(payload: dict, db: AsyncSession = Depends(get_db)):
    """Legacy endpoint compatibility. Returns JWT token for user_id."""
    user_id = payload.get("user_id")
    device_id = payload.get("device_id", "android_device")
    
    if not user_id:
        raise HTTPException(status_code=400, detail="Missing user_id")
        
    result = await db.execute(select(User).filter(User.id == user_id))
    user = result.scalars().first()
    
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
        
    token = create_access_token(user.id, user.username, device_id=device_id)
    return {"token": token}


# ==========================================
# Passkey Registration Endpoints
# ==========================================

@router.post("/passkey/register/begin")
async def begin_passkey_register(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Start registration process. Generates creation options for client."""
    # Find existing passkey credentials to exclude
    result = await db.execute(
        select(PasskeyCredential).filter(PasskeyCredential.user_id == current_user.id)
    )
    credentials = result.scalars().all()
    exclude_ids = [c.credential_id for c in credentials]
    
    try:
        options = generate_reg_options(
            user_id=current_user.id,
            username=current_user.username,
            exclude_credential_ids=exclude_ids
        )
        return options
    except Exception as e:
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Failed to generate options: {e}")


@router.post("/passkey/register/complete")
async def complete_passkey_register(
    req: PasskeyRegisterCompleteRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Complete registration process. Verifies challenge and saves credential."""
    try:
        credential_dict = json.loads(req.credential)
        verification = verify_reg_response(credential_dict)
    except Exception as e:
        traceback.print_exc()
        raise HTTPException(status_code=400, detail=str(e))
        
    # Store credential in DB
    new_cred = PasskeyCredential(
        user_id=current_user.id,
        credential_id=verification.credential_id,
        public_key=verification.credential_public_key,
        sign_count=verification.sign_count,
        name=credential_dict.get("name", "Dispositivo Android")
    )
    db.add(new_cred)
    await db.commit()
    return {"status": "success"}


# ==========================================
# Passkey Authentication Endpoints
# ==========================================

@router.post("/passkey/login/begin")
async def begin_passkey_login():
    """Start login process. Generates assertion options for client."""
    try:
        # Username-less login: allow any credential
        options = generate_auth_options()
        return options
    except Exception as e:
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Failed to generate options: {e}")


@router.post("/passkey/login/complete", response_model=TokenResponse)
async def complete_passkey_login(
    req: PasskeyLoginCompleteRequest,
    db: AsyncSession = Depends(get_db)
):
    """Complete login process. Verifies assertion signature and returns JWT."""
    try:
        credential_dict = json.loads(req.credential)
        credential_id_b64url = credential_dict.get("id", "")
        credential_id_bytes = base64url_to_bytes(credential_id_b64url)
    except Exception as e:
        raise HTTPException(status_code=400, detail="Invalid credential format")
        
    # Look up credential in DB
    result = await db.execute(
        select(PasskeyCredential).filter(PasskeyCredential.credential_id == credential_id_bytes)
    )
    cred = result.scalars().first()
    if not cred:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Passkey credential not found"
        )
        
    # Look up user
    user_result = await db.execute(select(User).filter(User.id == cred.user_id))
    user = user_result.scalars().first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
        
    # Verify assertion
    try:
        verification = verify_auth_response(
            credential_dict=credential_dict,
            stored_public_key=cred.public_key,
            stored_sign_count=cred.sign_count
        )
    except Exception as e:
        traceback.print_exc()
        raise HTTPException(status_code=401, detail=f"Passkey verification failed: {e}")
        
    # Update credential sign count
    cred.sign_count = verification.new_sign_count
    await db.commit()
    
    token = create_access_token(user.id, user.username)
    return TokenResponse(token=token, user_id=user.id, username=user.username)


# ==========================================
# Passkey Management Endpoints
# ==========================================

@router.get("/passkey/list")
async def list_passkeys(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """List all passkeys registered by the logged-in user."""
    result = await db.execute(
        select(PasskeyCredential).filter(PasskeyCredential.user_id == current_user.id)
    )
    credentials = result.scalars().all()
    
    return [
        {
            "id": bytes_to_base64url(c.credential_id),
            "name": c.name,
            "created_at": c.created_at
        }
        for c in credentials
    ]


@router.delete("/passkey/{credential_id_b64url}")
async def delete_passkey(
    credential_id_b64url: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Delete a registered passkey."""
    try:
        credential_id_bytes = base64url_to_bytes(credential_id_b64url)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid credential ID format")
        
    result = await db.execute(
        select(PasskeyCredential).filter(
            PasskeyCredential.credential_id == credential_id_bytes,
            PasskeyCredential.user_id == current_user.id
        )
    )
    cred = result.scalars().first()
    
    if not cred:
        raise HTTPException(status_code=404, detail="Passkey not found")
        
    await db.delete(cred)
    await db.commit()
    return {"status": "success"}
