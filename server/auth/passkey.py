import base64
import json
import time
from typing import Optional, List, Dict, Any
from webauthn import (
    generate_registration_options,
    verify_registration_response,
    generate_authentication_options,
    verify_authentication_response,
    options_to_json,
)
from webauthn.helpers import bytes_to_base64url, base64url_to_bytes
from webauthn.helpers.structs import (
    AttestationConveyancePreference,
    AuthenticatorSelectionCriteria,
    COSEAlgorithmIdentifier,
    PublicKeyCredentialDescriptor,
    PublicKeyCredentialParameters,
    PublicKeyCredentialRpEntity,
    PublicKeyCredentialUserEntity,
    UserVerificationRequirement,
    ResidentKeyRequirement,
)
from server.config import get_settings

settings = get_settings()

# In-memory store for active WebAuthn challenges
# Key: challenge_b64url (string)
# Value: {"challenge": bytes, "user_id": Optional[str], "expires_at": float}
_challenge_store: Dict[str, Dict[str, Any]] = {}

def store_challenge(challenge: bytes, user_id: Optional[str] = None, ttl: int = 300):
    """Store a generated challenge with an expiry time."""
    # Normalize key: strip base64url padding to avoid mismatch with browser clientDataJSON
    challenge_b64url = bytes_to_base64url(challenge).rstrip("=")
    _challenge_store[challenge_b64url] = {
        "challenge": challenge,
        "user_id": user_id,
        "expires_at": time.time() + ttl
    }

def verify_and_pop_challenge(challenge_b64url: str) -> Optional[bytes]:
    """Retrieve and remove a challenge from the store if valid and not expired."""
    # Normalize: strip padding to match how we store keys
    normalized = challenge_b64url.rstrip("=")
    item = _challenge_store.get(normalized)
    if not item:
        return None
    
    # Remove expired challenges
    if time.time() > item["expires_at"]:
        _challenge_store.pop(normalized, None)
        return None
    
    _challenge_store.pop(normalized, None)
    return item["challenge"]

def clean_expired_challenges():
    """Periodically clear expired challenges to free memory."""
    now = time.time()
    expired = [k for k, v in _challenge_store.items() if now > v["expires_at"]]
    for k in expired:
        _challenge_store.pop(k, None)


def generate_reg_options(user_id: str, username: str, exclude_credential_ids: List[bytes] = None) -> Dict[str, Any]:
    """Generate options for registering a new passkey."""
    clean_expired_challenges()
    
    user_id_bytes = user_id.encode("utf-8")
    
    # Format excluded credentials
    exclude_credentials = []
    if exclude_credential_ids:
        for cred_id in exclude_credential_ids:
            exclude_credentials.append(
                PublicKeyCredentialDescriptor(id=cred_id)
            )
            
    # Generate registration options
    options = generate_registration_options(
        rp_id=settings.RP_ID,
        rp_name=settings.RP_NAME,
        user_id=user_id_bytes,
        user_name=username,
        user_display_name=username,
        attestation_conveyance_preference=AttestationConveyancePreference.NONE,
        authenticator_selection=AuthenticatorSelectionCriteria(
            resident_key=ResidentKeyRequirement.REQUIRED,  # Required for username-less passkey login
            user_verification=UserVerificationRequirement.PREFERRED,
        ),
        supported_pub_key_algs=[
            COSEAlgorithmIdentifier.ECDSA_SHA_256,
            COSEAlgorithmIdentifier.RSASSA_PKCS1_v1_5_SHA_256,
        ],
        exclude_credentials=exclude_credentials,
    )
    
    # Store challenge (options.challenge is already bytes)
    store_challenge(options.challenge, user_id=user_id)
    
    # Convert options object to dict/JSON using the proper helper
    return json.loads(options_to_json(options))


def verify_reg_response(credential_dict: Dict[str, Any]) -> Any:
    """Verify the registration credential response from client."""
    # 1. Parse client data JSON to extract the challenge and origin
    try:
        client_data_json = credential_dict.get("response", {}).get("clientDataJSON", "")
        client_data_bytes = base64.urlsafe_b64decode(client_data_json + "==")
        client_data = json.loads(client_data_bytes.decode("utf-8"))
    except Exception as e:
        raise ValueError(f"Failed to parse clientDataJSON: {e}")
        
    challenge_b64url = client_data.get("challenge", "")
    origin = client_data.get("origin", "")
    
    # 2. Verify challenge exists in store
    expected_challenge = verify_and_pop_challenge(challenge_b64url)
    if not expected_challenge:
        raise ValueError("Invalid or expired registration challenge")
        
    # 3. Validate origin (allow Android signing cert origins or RP_ID domains)
    if not (origin.startswith("android:apk-key-hash:") or origin in settings.RP_ORIGINS):
        raise ValueError(f"Origin not allowed: {origin}")
        
    # 4. Verify using py_webauthn
    try:
        verification = verify_registration_response(
            credential=credential_dict,
            expected_challenge=expected_challenge,
            expected_origin=origin,
            expected_rp_id=settings.RP_ID,
            require_user_verification=False,
        )
        return verification
    except Exception as e:
        raise ValueError(f"WebAuthn verification failed: {e}")


def generate_auth_options(allow_credential_ids: List[bytes] = None) -> Dict[str, Any]:
    """Generate options for authenticating with a passkey."""
    clean_expired_challenges()
    
    # Format allowed credentials (empty if discoverable credentials are preferred)
    allow_credentials = []
    if allow_credential_ids:
        for cred_id in allow_credential_ids:
            allow_credentials.append(
                PublicKeyCredentialDescriptor(id=cred_id)
            )
            
    options = generate_authentication_options(
        rp_id=settings.RP_ID,
        allow_credentials=allow_credentials,
        user_verification=UserVerificationRequirement.PREFERRED,
    )
    
    # Store challenge (options.challenge is already bytes)
    store_challenge(options.challenge)
    
    return json.loads(options_to_json(options))


def verify_auth_response(
    credential_dict: Dict[str, Any],
    stored_public_key: bytes,
    stored_sign_count: int
) -> Any:
    """Verify the authentication credential response from client."""
    # 1. Parse client data JSON to extract challenge and origin
    try:
        client_data_json = credential_dict.get("response", {}).get("clientDataJSON", "")
        client_data_bytes = base64.urlsafe_b64decode(client_data_json + "==")
        client_data = json.loads(client_data_bytes.decode("utf-8"))
    except Exception as e:
        raise ValueError(f"Failed to parse clientDataJSON: {e}")
        
    challenge_b64url = client_data.get("challenge", "")
    origin = client_data.get("origin", "")
    
    # 2. Verify challenge exists in store
    expected_challenge = verify_and_pop_challenge(challenge_b64url)
    if not expected_challenge:
        raise ValueError("Invalid or expired authentication challenge")
        
    # 3. Validate origin
    if not (origin.startswith("android:apk-key-hash:") or origin in settings.RP_ORIGINS):
        raise ValueError(f"Origin not allowed: {origin}")
        
    # 4. Verify using py_webauthn
    try:
        verification = verify_authentication_response(
            credential=credential_dict,
            expected_challenge=expected_challenge,
            expected_origin=origin,
            expected_rp_id=settings.RP_ID,
            credential_public_key=stored_public_key,
            credential_sign_count=stored_sign_count,
            require_user_verification=False,
        )
        return verification
    except Exception as e:
        raise ValueError(f"WebAuthn verification failed: {e}")
