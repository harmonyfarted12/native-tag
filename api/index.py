import json
import secrets
import base64 as _base64
import requests
import random
import jwt  # pip install PyJWT
from flask import Flask, jsonify, request, Response
from datetime import datetime, timedelta, timezone
# APK METHOD LAND BACKEND POSTED BY L1RSON110
class GameInfo:
    def __init__(self) -> None:
        self.TitleId:   str = "4D94F"
        self.SecretKey: str = "OWTU8J3HOZKFX751K3C33GPIP6TB35HEAQQ6PH8ZCO8NO75I9N"
        self.AppCreds:  str = "OC|1358888013967187|0ec4b351f6d1d95f563f4e8bb76b9bd2"
        self.OculusAppId: str = "1358888013967187"
        self.EntitlementCheck: bool = False
        self.MothershipJwtSecret: str = "asgduigsduifgasiudgyiusdfgf8sdgtfd97gsd978sdgfgsdfuifgsiudfgiusdfgiusdgfiusgdiugsidgf"  # Set this to a long random secret string

    def GetAuthHeaders(self) -> dict[str, str]:
        return {
            "content-type": "application/json",
            "X-SecretKey":  self.SecretKey
        }

    def GetTitle(self) -> str:
        return self.TitleId


settings = GameInfo()
app = Flask(__name__)
playfabCache = {}
muteCache = {}
valid_host = None

SuccessfulAuthy = "https://discord.com/api/webhooks/1539825967235866664/cJ-wLkbL7PdPw3UI0k5dGlANtC_8tcyiUTaaT8-4SRk2IpMj08yh11Dy2ikoX8-iiykw"
FailedAuthy = "https://discord.com/api/webhooks/1539825967235866664/cJ-wLkbL7PdPw3UI0k5dGlANtC_8tcyiUTaaT8-4SRk2IpMj08yh11Dy2ikoX8-iiykw"

# Stores issued attestation nonces -> issued_at timestamp (unix seconds)
# Used to prevent replay attacks - each nonce can only be used once
nonceStore: dict[str, float] = {}

def ReturnFunctionJson(data, funcname, funcparam={}):
    rjson = data.get("FunctionParameter", {})
    userId = rjson.get("CallerEntityProfile", {}).get("Lineage", {}).get("TitlePlayerAccountId")

    req = requests.post(
        url=f"https://{settings.TitleId}.playfabapi.com/Server/ExecuteCloudScript",
        json={
            "PlayFabId": userId,
            "FunctionName": funcname,
            "FunctionParameter": funcparam
        },
        headers=settings.GetAuthHeaders()
    )

    if req.status_code == 200:
        return jsonify(req.json().get("data").get("FunctionResult")), req.status_code
    else:
        return jsonify({}), req.status_code

def ValidateOculusAccount(Nonce: str, OculusId: str, ClientCustomId: str) -> tuple[bool, str | None, str | None, str | None]:
    VerifyNonceReq = requests.post(
        url="https://graph.oculus.com/user_nonce_validate",
        json={"access_token": settings.AppCreds, "nonce": Nonce, "user_id": OculusId},
        headers={"Content-Type": "application/json"}
    )
    print(json.dumps(VerifyNonceReq.json(), indent=2))
    if not VerifyNonceReq.json().get("is_valid"):
        return (False, None, None, "Nonce validation failed")

    OculusDataReq = requests.get(
        url=f"https://graph.oculus.com/{OculusId}?access_token={settings.AppCreds}&fields=org_scoped_id,alias",
        headers={"Content-Type": "application/json"}
    )
    print(json.dumps(OculusDataReq.json(), indent=2))
    if OculusDataReq.status_code != 200:
        return (False, None, None, "Failed to retrieve Oculus data")

    OculusData = OculusDataReq.json()
    OrgScope = OculusData.get("org_scoped_id")
    Alias = OculusData.get("alias")

    if not OrgScope:
        return (False, None, None, "Missing org_scoped_id")
    if not Alias:
        return (False, None, None, "Missing alias")

    ServerCustomId = f"OCULUS{OrgScope}"
    
    if ClientCustomId.startswith("OCULUS"):
        ClientOrgScope = ClientCustomId[6:]
    elif ClientCustomId.startswith("OC"):
        ClientOrgScope = ClientCustomId[2:]
    else:
        return (False, None, None, "Invalid CustomId prefix")
    
    if ClientOrgScope != OrgScope:
        return (False, None, None, "CustomId mismatch")

    return (True, ServerCustomId, Alias, None)

def CheckUserEntitlement(OculusId: str) -> tuple[bool, str | None, dict | None]:
    if not settings.EntitlementCheck:
        return (True, None, {"status": "skipped", "reason": "EntitlementCheck disabled"})
    
    EntitlementReq = requests.post(
        url=f"https://graph.oculus.com/{settings.OculusAppId}/verify_entitlement",
        data={
            "access_token": settings.AppCreds,
            "user_id": str(OculusId)
        }
    )
    
    print(f"Entitlement check response: {EntitlementReq.status_code}")
    print(json.dumps(EntitlementReq.json(), indent=2))
    
    result = EntitlementReq.json()
    response_info = {"status_code": EntitlementReq.status_code, "response": result}
    
    if EntitlementReq.status_code != 200:
        return (False, "Failed to verify entitlement", response_info)
    
    if "error" in result or not result.get("success", False):
        return (False, "User does not own this application", response_info)
    
    return (True, None, response_info)

# ─── META ATTESTATION HELPERS ─────────────────────────────────────────────────

def _generate_challenge_nonce() -> str:
    """
    Generates a cryptographically secure Base64URL-encoded nonce from 32 random
    bytes (produces 43 chars). Meta requires 22-172 chars, so 43 is well within range.
    Each nonce must only be used once to prevent replay attacks.
    """
    raw = secrets.token_bytes(32)
    return _base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _decode_attestation_claims(b64_claims: str) -> dict:
    """
    Decodes the Base64URL-encoded claims string returned by Meta's
    platform_integrity/verify endpoint into a Python dict.
    """
    padded = b64_claims + "=" * (-len(b64_claims) % 4)
    return json.loads(_base64.urlsafe_b64decode(padded))


def verify_mothership_token(token: str) -> tuple[bool, dict | None, str | None]:
    """
    Verifies a signed MothershipToken JWT issued by /api/PlayFabAuthentication (Action=Attestation).
    Returns (is_valid, payload, error_reason).
    Call this from any route that needs to gate on attestation status.
    """
    try:
        payload = jwt.decode(
            token,
            settings.MothershipJwtSecret,
            algorithms=["HS256"]
        )
        return (True, payload, None)
    except jwt.ExpiredSignatureError:
        return (False, None, "MothershipToken expired")
    except jwt.InvalidTokenError as e:
        return (False, None, f"MothershipToken invalid: {e}")

# ─── META ATTESTATION ROUTES ──────────────────────────────────────────────────

def _issue_nonce() -> dict:
    """
    Step 1 of the attestation handshake, now dispatched from
    /api/PlayFabAuthentication (Action == "GetNonce") instead of its own route.

    The client calls this first to receive a fresh challenge nonce, then passes
    that nonce to ovr_DeviceApplicationIntegrity_GetIntegrityToken() on the headset.
    Meta's SDK contacts Meta's attestation server in the background and returns
    a signed attestation token back to the client app.

    Returns:
        { "nonce": "<base64url string, 43 chars>" }
    """
    nonce = _generate_challenge_nonce()
    now_ts = datetime.now(timezone.utc).timestamp()
    nonceStore[nonce] = now_ts

    # Prune nonces older than 10 minutes to prevent unbounded memory growth
    cutoff = now_ts - 600
    expired_keys = [k for k, v in nonceStore.items() if v < cutoff]
    for k in expired_keys:
        nonceStore.pop(k, None)

    print(f"[Attestation] Issued nonce: {nonce}")
    return {"nonce": nonce}


def _complete_attestation(rjson: dict):
    """
    Step 2 of the attestation handshake, now dispatched from
    /api/PlayFabAuthentication (Action == "Attestation") instead of its own route.

    The client POSTs the attestation token it received from the Meta SDK along
    with its PlayFabId. This function:
      1. Calls Meta's platform_integrity/verify to validate the token signature
      2. Base64URL-decodes the returned claims
      3. Validates: nonce (replay protection), expiry, timestamp freshness,
         app_integrity_state, device_integrity_state, and device ban status
      4. On success, returns a signed MothershipToken (JWT) the client can use
         for subsequent authenticated requests

    Request body:
        {
            "Action":            "Attestation",
            "attestation_token": "<token from Meta SDK>",
            "playfab_id":        "<PlayFabId>"
        }

    Returns a (body_dict, status_code) tuple. Caller is responsible for jsonify().
    """
    if not rjson:
        return {"error": "Missing request body"}, 400

    attestation_token = rjson.get("attestation_token")
    playfab_id        = rjson.get("playfab_id")

    if not attestation_token:
        return {"error": "Missing attestation_token"}, 400
    if not playfab_id:
        return {"error": "Missing playfab_id"}, 400

    # ── 1. Send token to Meta for verification ────────────────────────────────
    verify_url = (
        f"https://graph.oculus.com/platform_integrity/verify"
        f"?token={attestation_token}&access_token={settings.AppCreds}"
    )
    verify_req = requests.get(verify_url)
    verify_json = verify_req.json()
    print("[Attestation] Meta verify response:", json.dumps(verify_json, indent=2))

    data_list = verify_json.get("data", [])
    if not data_list:
        return {"error": "Attestation verification failed: no data returned from Meta"}, 403

    entry = data_list[0]
    if entry.get("message") != "success":
        reason = entry.get("message", "unknown")
        return {"error": f"Attestation verification failed: {reason}"}, 403

    # ── 2. Decode claims ──────────────────────────────────────────────────────
    try:
        claims = _decode_attestation_claims(entry["claims"])
    except Exception as e:
        return {"error": f"Failed to decode attestation claims: {e}"}, 500

    print("[Attestation] Decoded claims:", json.dumps(claims, indent=2))

    request_details = claims.get("request_details", {})
    app_state       = claims.get("app_state", {})
    device_state    = claims.get("device_state", {})
    device_ban      = claims.get("device_ban", {})

    # ── 3. Validate claims ────────────────────────────────────────────────────

    # 3a. Nonce must match one we issued and must not have been used before.
    #     This is the primary defense against replay attacks.
    returned_nonce = request_details.get("nonce")
    if not returned_nonce or returned_nonce not in nonceStore:
        return {
            "error": "Nonce mismatch or already consumed. Possible replay attack."
        }, 403
    nonceStore.pop(returned_nonce)  # Consume immediately - single use only

    # 3b. Token must not be expired (Meta sets exp to 24 hours after creation)
    exp = request_details.get("exp", 0)
    now_ts = datetime.now(timezone.utc).timestamp()
    if now_ts > exp:
        return {"error": "Attestation token has expired"}, 403

    # 3c. Token timestamp must be recent (within 5 minutes of now)
    token_ts = request_details.get("timestamp", 0)
    if abs(now_ts - token_ts) > 300:
        return {"error": "Attestation token timestamp is too far from server time"}, 403

    # 3d. App must be installed from the Meta Horizon Store (not sideloaded/modded)
    app_integrity = app_state.get("app_integrity_state", "")
    if app_integrity != "StoreRecognized":
        print(f"[Attestation] App integrity failed: {app_integrity}")
        return {
            "error": f"App integrity check failed: {app_integrity}",
            "BanMessage": "Unrecognised or modified APK detected.",
            "BanExpirationTime": "Indefinite"
        }, 403

    # 3e. Device bootloader must not be unlocked / OS must not be tampered with.
    #     NotTrusted = unlocked bootloader or invalid system image.
    #     Basic = locked bootloader but some post-boot compromise detected.
    #     Advanced = fully trusted device.
    device_integrity = device_state.get("device_integrity_state", "")
    if device_integrity == "NotTrusted":
        print(f"[Attestation] Device integrity failed: {device_integrity}")
        return {
            "error": "Device integrity check failed: NotTrusted",
            "BanMessage": "Unlocked bootloader or invalid system image detected.",
            "BanExpirationTime": "Indefinite"
        }, 403

    # 3f. Check Meta's device ban status
    if device_ban.get("is_banned"):
        remaining = device_ban.get("remaining_ban_time", "unknown")
        print(f"[Attestation] Device is banned. Remaining: {remaining}")
        return {
            "error": "Device is banned",
            "BanMessage": "This device has been banned from the application.",
            "BanExpirationTime": str(remaining)
        }, 403

    # ── 4. Issue MothershipToken (signed JWT) ─────────────────────────────────
    unique_id  = device_state.get("unique_id", "")
    package_id = app_state.get("package_id", "")

    jwt_payload = {
        "sub":              playfab_id,          # PlayFab player identity
        "unique_id":        unique_id,            # Device fingerprint (rotates every 30 days)
        "package_id":       package_id,           # APK package name
        "app_integrity":    app_integrity,        # "StoreRecognized"
        "device_integrity": device_integrity,     # "Advanced" or "Basic"
        "iat":              int(now_ts),           # Issued at
        "exp":              int(now_ts) + 3600,   # Expires in 1 hour
    }

    mothership_token = jwt.encode(
        jwt_payload,
        settings.MothershipJwtSecret,
        algorithm="HS256"
    )

    print(f"[Attestation] Issued MothershipToken for PlayFabId={playfab_id}, device_integrity={device_integrity}")

    return {
        "MothershipToken":   mothership_token,
        "PlayFabId":         playfab_id,
        "UniqueDeviceId":    unique_id,
        "AppIntegrity":      app_integrity,
        "DeviceIntegrity":   device_integrity,
    }, 200

# ─── EXISTING ROUTES (UNCHANGED) ─────────────────────────────────────────────

@app.route("/", methods=["POST", "GET"])
def main():
    return "DISCORD.GG/APKMETHOD"

@app.route("/api/PlayFabAuthentication", methods=["POST", "GET"])
def playfabauthentication():
    global valid_host

    request_host = request.headers.get("Host")

    if valid_host is None:
        valid_host = request_host

    if request_host != valid_host:
        return "", 404

    if "UnityPlayer" not in request.headers.get("User-Agent", ""):
        return Response(
            json.dumps({"BanMessage": "Unable To Validate User Agent Integrity.", "BanExpirationTime": "Indefinite"}, indent=1),
            mimetype="application/json"
        ), 403

    # ── Dispatch: GetNonce and Attestation now live here instead of on their
    # own routes. AppId/CustomId/Nonce full-auth flow remains the default path
    # when no Action is given, so old clients keep working unchanged.
    rjson_peek = request.get_json(silent=True)
    action = (rjson_peek or {}).get("Action") or request.args.get("Action")

    if request.method == "GET" and action is None:
        # Bare GET with no Action = nonce issuance (old /api/attestation/begin GET behavior)
        action = "GetNonce"

    if action == "GetNonce":
        return jsonify(_issue_nonce()), 200

    if action == "Attestation":
        body, status = _complete_attestation(rjson_peek or {})
        return jsonify(body), status

    # Optional: verify MothershipToken if present in this request.
    # NOTE: this only proves DEVICE integrity (not rooted/modded). It does NOT
    # prove account ownership on its own — attestation_complete accepts a raw
    # playfab_id from the client with no verification, so a valid MothershipToken
    # cannot be trusted to skip CustomId/Nonce/OculusId checks below. Doing that
    # would let anyone forge an Attestation call with an arbitrary playfab_id and
    # then log in as that account with no Oculus proof at all. Token stays a gate
    # on top of the full flow, not a replacement for it.
    mothership_token_header = request.headers.get("X-Mothership-Token")
    if mothership_token_header:
        is_valid_mt, mt_payload, mt_error = verify_mothership_token(mothership_token_header)
        if not is_valid_mt:
            print(f"[PlayFabAuth] MothershipToken verification failed: {mt_error}")
            return jsonify({"Message": "Invalid attestation token.", "Error": "ForbiddenInvalidMothershipToken"}), 403
        print(f"[PlayFabAuth] MothershipToken valid for sub={mt_payload.get('sub')}")

    rjson = rjson_peek
    if rjson is None:
        return jsonify({"Message": "Request body is missing or cannot be parsed.", "Error": "BadRequestBadBody"}), 400

    print(json.dumps(rjson, indent=2))

    AppVersion = rjson.get("AppVersion")
    OculusId = rjson.get("OculusId")
    Nonce = rjson.get("Nonce")
    CustomId = rjson.get("CustomId")
    Platform = rjson.get("Platform")
    AppId = rjson.get("AppId")

    client_ip = request.headers.get("X-Forwarded-For", request.remote_addr)
    if client_ip and "," in client_ip:
        client_ip = client_ip.split(",")[0].strip()

    if CustomId is None:
        if FailedAuthy:
            fail_embed = {
                "content": None,
                "embeds": [{
                    "title": "Auth Failed Missing CustomId",
                    "description": f"```OculusId: {OculusId}\nIP Address: {client_ip}\nNonce: {Nonce}\nFailure Reason: Missing CustomId parameter```",
                    "color": 0x8B0000
                }]
            }
            requests.post(url=FailedAuthy, json=fail_embed)
        return jsonify({"Message": "Failed To Validate Account Ownership.", "Error": "FailedRequestNoCustomId"}), 403
    if Nonce is None:
        if FailedAuthy:
            fail_embed = {
                "content": None,
                "embeds": [{
                    "title": "Auth Failed Missing Nonce",
                    "description": f"```OculusId: {OculusId}\nIP Address: {client_ip}\nFailure Reason: Missing Nonce parameter```",
                    "color": 0x8B0000
                }]
            }
            requests.post(url=FailedAuthy, json=fail_embed)
        return jsonify({"Message": "Failed To Validate Account Ownership.", "Error": "FailedRequestNoNonce"}), 403
    if AppId is None:
        if FailedAuthy:
            fail_embed = {
                "content": None,
                "embeds": [{
                    "title": "Auth Failed Missing AppId",
                    "description": f"```OculusId: {OculusId}\nIP Address: {client_ip}\nNonce: {Nonce}\nFailure Reason: Missing AppId parameter```",
                    "color": 0x8B0000
                }]
            }
            requests.post(url=FailedAuthy, json=fail_embed)
        return jsonify({"Message": "Failed To Validate AppId.", "Error": "FailedRequestNoAppId"}), 403
    if Platform is None:
        if FailedAuthy:
            fail_embed = {
                "content": None,
                "embeds": [{
                    "title": "Auth Failed Missing Platform",
                    "description": f"```OculusId: {OculusId}\nIP Address: {client_ip}\nNonce: {Nonce}\nFailure Reason: Missing Platform parameter```",
                    "color": 0x8B0000
                }]
            }
            requests.post(url=FailedAuthy, json=fail_embed)
        return jsonify({"Message": "Unable To Validate Platform", "Error": "Platform Validation Failed"}), 403
    if OculusId is None:
        if FailedAuthy:
            fail_embed = {
                "content": None,
                "embeds": [{
                    "title": "Auth Failed Missing OculusId",
                    "description": f"```IP Address: {client_ip}\nNonce: {Nonce}\nFailure Reason: Missing OculusId parameter```",
                    "color": 0x8B0000
                }]
            }
            requests.post(url=FailedAuthy, json=fail_embed)
        return jsonify({"Message": "Failed To Validate Account Ownership.", "Error": "FailedRequestNoOculusId"}), 403

    if AppId != settings.TitleId:
        if FailedAuthy:
            fail_embed = {
                "content": None,
                "embeds": [{
                    "title": "Auth Failed Wrong AppId",
                    "description": f"```OculusId: {OculusId}\nIP Address: {client_ip}\nAppId: {AppId}\nNonce: {Nonce}\nFailure Reason: Wrong AppId expected {settings.TitleId}```",
                    "color": 0x8B0000
                }]
            }
            requests.post(url=FailedAuthy, json=fail_embed)
        return jsonify({"Message": "Failed To Validate AppId.", "Error": "BadRequestAppIdMismatch"}), 403

    if Platform == "Windows":
        if FailedAuthy:
            fail_embed = {
                "content": None,
                "embeds": [{
                    "title": "Auth Failed Invalid Platform",
                    "description": f"```OculusId: {OculusId}\nIP Address: {client_ip}\nPlatform: {Platform}\nNonce: {Nonce}\nFailure Reason: Platform must be Quest```",
                    "color": 0x8B0000
                }]
            }
            requests.post(url=FailedAuthy, json=fail_embed)
        return jsonify({"Message": "Failed To Validate Platform.", "Error": "ForbiddenPlatform"}), 403

    is_valid, server_custom_id, alias, error_reason = ValidateOculusAccount(
        Nonce=Nonce,
        OculusId=OculusId,
        ClientCustomId=CustomId
    )

    if not is_valid:
        print(f"Validation failed: {error_reason}")
        if FailedAuthy:
            fail_embed = {
                "content": None,
                "embeds": [{
                    "title": "Auth Failed Validation Error",
                    "description": f"```OculusId: {OculusId}\nCustomId: {CustomId}\nIP Address: {client_ip}\nNonce: {Nonce}\nFailure Reason: {error_reason}```",
                    "color": 0x8B0000
                }]
            }
            requests.post(url=FailedAuthy, json=fail_embed)
        return jsonify({"Message": "Failed To Validate Account Ownership.", "Error": "ForbiddenValidationFailed"}), 403

    entitled, entitlement_error, entitlement_response = CheckUserEntitlement(OculusId)
    if not entitled:
        print(f"Entitlement check failed: {entitlement_error}")
        if FailedAuthy:
            fail_embed = {
                "content": None,
                "embeds": [{
                    "title": "Auth Failed No Game Entitlement",
                    "description": f"```OculusId: {OculusId}\nCustomId: {server_custom_id}\nAlias: {alias}\nIP Address: {client_ip}\nNonce: {Nonce}\nFailure Reason: {entitlement_error}\nEntitlement Response: {json.dumps(entitlement_response)}```",
                    "color": 0x8B0000
                }]
            }
            requests.post(url=FailedAuthy, json=fail_embed)
        return jsonify({"Message": "You do not own this application.", "Error": "ForbiddenNotEntitled"}), 403

    custom_id = server_custom_id
    print(f"Validated user with alias: {alias}")
    if custom_id == "OCULUS0":
        ban_req = requests.post(
            url=f"https://{settings.TitleId}.playfabapi.com/Admin/BanUsers",
            json={
                "Bans": [
                    {
                        "PlayFabId": rjson.get("currentPlayerId"),
                        "DurationInHours": None, 
                        "Reason": "CHEATING."
                    }
                ]
            },
            headers=settings.GetAuthHeaders()
        )
        if ban_req.status_code == 200:
            return jsonify({"Message": "bro was banned for: Lemonloader", "Error": "Banned"}), 403
        else:
            return jsonify({"Message": "Failed to ban user", "Error": "InternalError"}), 500

    url = f"https://{settings.TitleId}.playfabapi.com/Server/LoginWithServerCustomId"
    login_request = requests.post(
        url=url,
        json={
            "ServerCustomId": custom_id,
            "CreateAccount": True
        },
        headers=settings.GetAuthHeaders()
    )

    if login_request.status_code == 200:
        data = login_request.json().get("data")
        sessionTicket = data.get("SessionTicket")
        entityToken = data.get("EntityToken").get("EntityToken")
        playFabId = data.get("PlayFabId")
        entityType = data.get("EntityToken").get("Entity").get("Type")
        entityId = data.get("EntityToken").get("Entity").get("Id")

        print(requests.post(
            url=f"https://{settings.TitleId}.playfabapi.com/Server/LinkServerCustomId",
            json={
                "ForceLink": True,
                "ServerCustomId": custom_id,
                "PlayFabId": playFabId
            },
            headers=settings.GetAuthHeaders()
        ).json())

        AccountCreationIsoTimestamp_req = requests.post(
            url=f"https://{settings.TitleId}.playfabapi.com/Server/GetUserAccountInfo",
            json={"PlayFabId": playFabId},
            headers=settings.GetAuthHeaders()
        )
        AccountCreationIsoTimestamp = AccountCreationIsoTimestamp_req.json().get("data").get("UserInfo").get("Created")

        response_body = {
            "SessionTicket": sessionTicket,
            "EntityToken": entityToken,
            "PlayFabId": playFabId,
            "EntityId": entityId,
            "EntityType": entityType,
            "AccountCreationIsoTimestamp": AccountCreationIsoTimestamp
        }
        print(json.dumps(response_body, indent=2))

        if SuccessfulAuthy:
            success_embed = {
                "content": None,
                "embeds": [{
                    "title": "=== PlayFab Auth Success ===",
                    "description": f"```PlayFabId: {playFabId}\nOculusId: {OculusId}\nCustomId: {custom_id}\nAlias: {alias}\nIP Address: {client_ip}\nEntitlement Response: {json.dumps(entitlement_response)}```",
                    "color": 0x3498DB
                }]
            }
            requests.post(url=SuccessfulAuthy, json=success_embed)

        return jsonify(response_body), 200
    else:
        if login_request.status_code == 403:
            ban_info = login_request.json()
            if ban_info.get('errorCode') == 1002:
                ban_message = ban_info.get('errorMessage', "No ban message provided.")
                ban_details = ban_info.get('errorDetails', {})
                ban_expiration_key = next(iter(ban_details.keys()), None)
                ban_expiration_list = ban_details.get(ban_expiration_key, [])
                ban_expiration = ban_expiration_list[0] if len(ban_expiration_list) > 0 else "No expiration date provided."
                print(ban_info)
                return jsonify({
                    'BanMessage': ban_expiration_key,
                    'BanExpirationTime': ban_expiration
                }), 403
            else:
                error_message = ban_info.get('errorMessage', 'Forbidden without ban information.')
                return jsonify({
                    'Error': 'PlayFab Error',
                    'Message': error_message
                }), 403
        else:
            error_info = login_request.json()
            error_message = error_info.get('errorMessage', 'An error occurred.')
            return jsonify({
                'Error': 'PlayFab Error',
                'Message': error_message
            }), login_request.status_code

@app.route("/api/CachePlayFabId", methods=["POST", "GET"])
def cacheplatfabid():
    rjson = request.get_json()

    playfabCache[rjson.get("PlayFabId")] = rjson

    return jsonify({"Message": "Success"}), 200

@app.route('/api/TitleData', methods=['POST', 'GET'])
def titledata():
    if request.method != "POST":
        return "", 404
    response_data = {
        "AutoMuteCheckedHours": {
            "hours": 169
        },
        "AutoName_Adverbs": [
            "Cool", "Fine", "Bald", "Bold", "Half", 
            "Only", "Calm", "Fab", "Ice", "Mad", 
            "Rad", "Big", "New", "Old", "Shy"
        ],
        "AutoName_Nouns": [
            "Gorilla", "Chicken", "Darling", "Sloth", "King", 
            "Queen", "Royal", "Major", "Actor", "Agent", 
            "Elder", "Honey", "Nurse", "Doctor", "Rebel", 
            "Shape", "Ally", "Driver", "Deputy"
        ],
        "BundleBoardSign": "<color=#ff4141>discord.gg/VKFuNbHvtH</color>",
        "BundleKioskButton": "<color=#ff4141>discord.gg/VKFuNbHvtH</color>",
        "BundleKioskSign": "<color=#ff4141>discord.gg/VKFuNbHvtH/</color>",
        "BundleLargeSign": "<color=#ff4141>discord.gg/VKFuNbHvtH</color>",
        "EmptyFlashbackText": "FLOOR TWO NOW OPEN\n FOR BUSINESS\n\nSTILL SEARCHING FOR\nBOX LABELED 2021",
        "EnableCustomAuthentication": True,
        "GorillanalyticsChance": 4320,
        "LatestPrivacyPolicyVersion": "2024.09.20",
        "LatestTOSVersion": "2024.09.20",
        "MOTD": "<color=orange>WELCOME TO BLAWG TAGZ</color>  <color=green>HAVE FUN!</color>  <color=red>CREDITS TO HARLUM BRAZI</color>  <color=red>GAME GOT SHUT DOWN ON APP LAB BUT WILL COME BACK ON MONDAY THE PROVET APP LAB IS OPEN SO GAME IS STILL ACTIVE!</color>  <color=yellow>IF YOU ENJOY THE GAME, PLEASE GIVE IT  (5 STARS)!</color> <color=yellow>https://discord.gg/aDhrFgNrxt</color>",
        "SeasonalStoreBoardSign": "<color=#ff7241>FALL!</color>",
        "TOS_2024.09.20": "discord.gg/VKFuNbHvtH",
        "TOBAlreadyOwnCompTxt": "discord.gg/VKFuNbHvtH",
        "TOBAlreadyOwnPurchaseBundle": "BLABLABLA",
        "TOBDefCompTxt": "discord.gg/VKFuNbHvtH",
        "TOBDefPurchaseBtnDefTxt": "BLABLABLA",
        "UseLegacyIAP": False
        
    }
    return jsonify(response_data)


@app.route("/api/GetAcceptedAgreements", methods=['POST', 'GET'])
def GetAcceptedAgreements():
    data = request.json

    return jsonify({"PrivacyPolicy": "1.1.67", "TOS": "11.05.22.2"}), 200

@app.route("/api/SubmitAcceptedAgreements", methods=['POST', 'GET'])
def SubmitAcceptedAgreements():
    data = request.json

    return jsonify({"PrivacyPolicy": "1.1.67", "TOS": "11.05.22.2"}), 200

@app.route('/api/GetName', methods=['POST', 'GET'])
def GetName():
    return jsonify({"result": f"GORILLA{random.randint(1000,9999)}"})

@app.route("/api/ConsumeOculusIAP", methods=["POST", "GET"])
def consumeoculusiap():
    rjson = request.get_json()

    accessToken = rjson.get("userToken")
    userId = rjson.get("userID")
    playFabId = rjson.get("playFabId")
    nonce = rjson.get("nonce")
    platform = rjson.get("platform")
    sku = rjson.get("sku")
    debugParams = rjson.get("debugParemeters")

    req = requests.post(
        url=f"https://graph.oculus.com/consume_entitlement?nonce={nonce}&user_id={userId}&sku={sku}&access_token={settings.AppCreds}",
        headers={
            "content-type": "application/json"
        }
    )

    if bool(req.json().get("success")):
        return jsonify({"result": True})
    else:
        return jsonify({"error": True})


@app.route("/api/TryDistributeCurrencyV2", methods=["POST"])
def TryDistributeCurrencyV2():
    if request.method != "POST":
        return "", 404

    rjson = request.json
    sr_a_day = 500  
    current_player_id = rjson.get("CallerEntityProfile", {}).get("Lineage", {}).get("MasterPlayerAccountId")

    get_data_response = requests.post(
        f"https://{settings.TitleId}.playfabapi.com/Server/GetUserReadOnlyData",
        headers=settings.GetAuthHeaders(),
        json={
            "PlayFabId": current_player_id,
            "Keys": ["DailyLogin"]
        }
    )

    daily_login_value = get_data_response.json().get("data").get("Data").get("DailyLogin", {}).get("Value", None)

    last_login_date = None
    if daily_login_value:
        last_login_date = datetime.fromisoformat(daily_login_value.replace("Z", "+00:00")).astimezone(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)

    if not last_login_date or last_login_date < datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0, tzinfo=timezone.utc):
        requests.post(
            f"https://{settings.TitleId}.playfabapi.com/Server/AddUserVirtualCurrency",
            headers=settings.GetAuthHeaders(),
            json={
                "PlayFabId": current_player_id,
                "VirtualCurrency": "SR",
                "Amount": sr_a_day
            }
        )

        requests.post(
            f"https://{settings.TitleId}.playfabapi.com/Server/UpdateUserReadOnlyData",
            headers=settings.GetAuthHeaders(),
            json={
                "PlayFabId": current_player_id,
                "Data": {
                    "DailyLogin": datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0, tzinfo=timezone.utc).isoformat()
                }
            }
        )

    return "", 200

@app.route("/api/ShouldUserAutomutePlayer", methods=["POST", "GET"])
def shoulduserautomuteplayer():
    return jsonify(muteCache)

@app.route("/api/photon", methods=["POST", "GET"])
def photonauth():
    print(f"Received {request.method} request at /api/photon")
    AuthTicketUrl = f"https://{settings.TitleId}.playfabapi.com/Server/AuthenticateSessionTicket"
    VALID_APPS = [f"{settings.TitleId}"]

    if request.method == "GET":
        PlayerId = request.args.get("username")
        token = request.args.get("token")
        if not PlayerId or not token:
            return jsonify({"resultCode": 3, "message": "Failed to parse token from request", "userId": None, "nickname": None}), 400
        print(f"Player: {PlayerId} Has Authed In Old Update.")
        return jsonify({"resultCode": 1, "message": f"User: {PlayerId} Was Authed.", "username": PlayerId, "token": token}), 200

    elif request.method == "POST":
        newData = request.get_json()
        AppId = newData.get("AppId")
        AppVersion = newData.get("AppVersion")
        Ticket = newData.get("Ticket")
        Token = newData.get("Token")
        Nonce = newData.get("Nonce")
        Platform = newData.get("Platform")
        print(json.dumps(newData, indent=2))

        # Verify MothershipToken if present
        mothership_token_header = newData.get("MothershipToken") or request.headers.get("X-Mothership-Token")
        if mothership_token_header:
            is_valid_mt, mt_payload, mt_error = verify_mothership_token(mothership_token_header)
            if not is_valid_mt:
                print(f"[Photon] MothershipToken verification failed: {mt_error}")
                return jsonify({"ResultCode": 3, "Message": "Invalid attestation token.", "Error": "ForbiddenInvalidMothershipToken"}), 403
            print(f"[Photon] MothershipToken valid for sub={mt_payload.get('sub')}, device_integrity={mt_payload.get('device_integrity')}")

        if AppId not in VALID_APPS:
            print(f"Invalid AppId: {AppId}")
            return jsonify({"ResultCode": 2, "Message": "Invalid AppId parameter", "Error": "BadRequestWrongAppId"}), 403

        if Platform != "Quest":
            print("Users Platform Is Not Quest")
            return jsonify({"Error": "Bad request", "ResultCode": 3, "Message": "Platform Must Be Quest Fella"}), 403

        AuthSessionTicketReq = requests.post(url=AuthTicketUrl, json={
            "SessionTicket": Ticket
        }, headers=settings.GetAuthHeaders())
        print(AuthSessionTicketReq)

        if AuthSessionTicketReq.status_code != 200:
            print(f"SessionTicket: {Ticket} Is Invalid")
            return jsonify({"ResultCode": 2, "Message": "Invalid SessionTicket parameter", "Error": "BadRequestBadSessionTicket"}), 403

        if AuthSessionTicketReq.status_code == 200:
            getdata = AuthSessionTicketReq.json().get("data").get("UserInfo", {})
            UserId = getdata.get("PlayFabId")
            
            AccountInfoReq = requests.post(
                url=f"https://{settings.TitleId}.playfabapi.com/Server/GetUserAccountInfo",
                json={"PlayFabId": UserId},
                headers=settings.GetAuthHeaders()
            )
            
            if AccountInfoReq.status_code != 200:
                print(f"Failed to get account info for UserId: {UserId}")
                return jsonify({"ResultCode": 3, "Message": "Failed to get account info", "Error": "BadRequestAccountInfo"}), 403
            
            accountData = AccountInfoReq.json().get("data", {}).get("UserInfo", {})
            print(f"AccountInfo response: {json.dumps(accountData, indent=2)}")
            ServerCustomIdInfo = accountData.get("ServerCustomIdInfo") or {}
            CustomId = ServerCustomIdInfo.get("CustomId") if ServerCustomIdInfo else None
            
            if not CustomId or not (CustomId.startswith("OCULUS") or CustomId.startswith("OC")):
                print(f"Invalid or missing ServerCustomId: {CustomId}")
                return jsonify({"ResultCode": 3, "Message": "Invalid ServerCustomId", "Error": "BadRequestInvalidCustomId"}), 403
            
            if CustomId.startswith("OCULUS"):
                OrgScopedCustomId = CustomId[6:]
            else:
                OrgScopedCustomId = CustomId[2:]
            print(f"OrgScopedCustomId: {OrgScopedCustomId}")

            OrgScopeUrl = f"https://graph.oculus.com/{OrgScopedCustomId}?access_token={settings.AppCreds}"
            GetOculusIdReq = requests.get(url=OrgScopeUrl, headers={"Content-Type": "application/json"})

            if "error" in GetOculusIdReq.json():
                print("User Did Not Pass The OrgScope Check.")
                return jsonify({"ResultCode": 3, "Message": "Did Not Pass OrgScopeId Checker", "Error": "BadRequestInvalidOrgScopeId"}), 403

            if UserId is None or len(UserId) != 16:
                print(f"UserId: {UserId} Is Not 16 Characters Long.")
                return jsonify({"ResultCode": 3, "Message": "Did Not UserId Length Checker", "Error": "BadRequestBadUserId"}), 403

            OculusId = GetOculusIdReq.json().get("id")
            print(f"Users OculusId Is: {OculusId}")

            VerifyNonceReq = requests.post(
                url="https://graph.oculus.com/user_nonce_validate",
                json={"access_token": settings.AppCreds, "nonce": newData.get("Nonce"), "user_id": OculusId},
                headers={"Content-Type": "application/json"}
            )
            print(VerifyNonceReq.json())
            nonce_json_data = VerifyNonceReq.json()

            if VerifyNonceReq.status_code != 200 or "is_valid" not in nonce_json_data:
                print(f"User: {UserId} Has Failed The Nonce Verification. Nonce: {Nonce}")
                return jsonify({"ResultCode": 1, "Message": "Failed Nonce Verification", "Error": "BadRequestInvalidNonce"}), 403

            print(f"{UserId} Was Authed Succesfully.")
            return jsonify({
                "ResultCode": 1,
                "Message": "Yay Servers Work Ig",
                "AppId": AppId,
                "AppVersion": AppVersion,
                "Nonce": Nonce,
                "OculusId": OculusId,
                "Ticket": Ticket,
                "Token": Token,
                "UserId": UserId
            }), 200

if __name__ == "__main__":
    app.run("0.0.0.0", 8080) # DISCORD.GG/APKMETHOD
