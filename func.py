import io
import json
import logging
import base64
import time
import requests
from fdk import response
import ociVault

logger = logging.getLogger()
logger.setLevel(logging.INFO)

oauth_apps = {}
scope_cache = {}
CACHE_TTL = 900
ADMIN_SCOPE = "urn:opc:idm:__myscopes__"


def mask_value(value, visible=10):
    if not value:
        return "<empty>"
    if len(value) <= visible:
        return "*" * len(value)
    return value[:visible] + "...(masked)"


def build_response(ctx, status_code, payload):
    return response.Response(
        ctx,
        response_data=json.dumps(payload),
        status_code=status_code,
        headers={"Content-Type": "application/json"}
    )


def deny(ctx, message, status_code=401):
    logger.error("deny: %s", message)
    return build_response(ctx, status_code, {"active": False, "error": message})


def initContext(context):
    if "idcs" in oauth_apps:
        return

    oauth_apps["idcs"] = {
        "base_url": context["identity_domain_base_url"].rstrip("/"),
        "client_id": context["client_id"],  # admin app client_id
        "client_secret": ociVault.getSecret(context["secret_ocid"])
    }

    logger.info(
        "initContext: base_url=%s admin_client_id=%s",
        oauth_apps["idcs"]["base_url"],
        mask_value(oauth_apps["idcs"]["client_id"])
    )


def extract_basic_auth(auth_header):
    if not auth_header:
        raise Exception("Authorization token is missing")

    if not auth_header.startswith("Basic "):
        raise Exception("Authorization must use Basic scheme")

    encoded = auth_header.split(" ", 1)[1].strip()
    try:
        decoded = base64.b64decode(encoded).decode("utf-8")
    except Exception:
        raise Exception("Basic credentials are not valid base64")

    if ":" not in decoded:
        raise Exception("Basic credentials must be client_id:client_secret")

    client_id, client_secret = decoded.split(":", 1)
    if not client_id or not client_secret:
        raise Exception("client_id or client_secret is empty")

    logger.info("extract_basic_auth: client_id=%s", mask_value(client_id))
    return client_id, client_secret


def get_access_token(client_id, client_secret, scope=None):
    token_url = oauth_apps["idcs"]["base_url"] + "/oauth2/v1/token"

    encoded = base64.b64encode(f"{client_id}:{client_secret}".encode()).decode()
    headers = {
        "Authorization": f"Basic {encoded}",
        "Content-Type": "application/x-www-form-urlencoded"
    }

    # Default scope for bootstrap/admin lookups
    effective_scope = scope if scope else ADMIN_SCOPE

    form = {
        "grant_type": "client_credentials",
        "scope": effective_scope
    }

    logger.info(
        "get_access_token: client_id=%s scope=%s",
        mask_value(client_id),
        effective_scope
    )

    resp = requests.post(token_url, headers=headers, data=form, timeout=8)
    logger.info("get_access_token: status=%s", resp.status_code)

    if resp.status_code != 200:
        logger.error("get_access_token: body=%s", resp.text)
        raise Exception("Token request failed")

    token = resp.json().get("access_token")
    if not token:
        raise Exception("Token endpoint did not return access_token")

    return token


def decode_jwt_payload(jwt_token):
    parts = jwt_token.split(".")
    if len(parts) < 2:
        raise Exception("Invalid JWT token format")

    payload_b64 = parts[1]
    padding = "=" * (-len(payload_b64) % 4)
    payload_json = base64.urlsafe_b64decode(payload_b64 + padding).decode("utf-8")
    return json.loads(payload_json)


def fetch_app_by_client_guid(client_guid):
    admin_token = get_access_token(
        oauth_apps["idcs"]["client_id"],
        oauth_apps["idcs"]["client_secret"],
        ADMIN_SCOPE
    )

    url = (
        f"{oauth_apps['idcs']['base_url']}/admin/v1/Apps/{client_guid}"
        f"?attributes=id,name,allowedScopes"
    )

    headers = {
        "Authorization": f"Bearer {admin_token}",
        "Accept": "application/json"
    }

    logger.info("fetch_app_by_client_guid: guid=%s", mask_value(client_guid))
    resp = requests.get(url, headers=headers, timeout=8)
    logger.info("fetch_app_by_client_guid: status=%s", resp.status_code)

    if resp.status_code != 200:
        logger.error("fetch_app_by_client_guid: body=%s", resp.text)
        raise Exception("Failed to fetch app details by client_guid")

    return resp.json()


def classify_scope(scope_obj):
    """
    Keep full raw scope for token request.
    Derive short business scope for API Gateway auth response.
    """
    val = (scope_obj.get("value") or "").strip()
    fqs = (scope_obj.get("fqs") or "").strip()
    raw = fqs if fqs else val
    if not raw:
        return None

    business = None
    if "oic_api_" in raw:
        idx = raw.find("oic_api_")
        suffix = raw[idx:]
        for delim in [":", "/", " ", ","]:
            if delim in suffix:
                suffix = suffix.split(delim, 1)[0]
        business = suffix

    return {
        "raw": raw,  # full scope string
        "business": business,
        "is_consumer": "consumer::all" in raw
    }


def get_client_scopes(client_id, client_secret):
    now = time.time()
    cached = scope_cache.get(client_id)

    if cached and cached["expiry"] > now:
        logger.info("get_client_scopes: cache hit for %s", mask_value(client_id))
        return cached["data"]

    logger.info("get_client_scopes: cache miss for %s", mask_value(client_id))

    caller_token = get_access_token(client_id, client_secret)  # with ADMIN_SCOPE default
    claims = decode_jwt_payload(caller_token)

    logger.info("get_client_scopes: token_claim_keys=%s", list(claims.keys()))
    client_guid = claims.get("client_guid")
    logger.info("get_client_scopes: client_guid=%s", mask_value(client_guid))

    if not client_guid:
        raise Exception("client_guid not found in token claims")

    app_data = fetch_app_by_client_guid(client_guid)
    allowed = app_data.get("allowedScopes", [])

    parsed = [classify_scope(s) for s in allowed]
    parsed = [p for p in parsed if p]

    business_scope = next((p["business"] for p in parsed if p["business"]), None)
    consumer_scope_full = next((p["raw"] for p in parsed if p["is_consumer"]), None)

    logger.info("get_client_scopes: business_scope=%s", business_scope)
    logger.info("get_client_scopes: consumer_scope_full=%s", consumer_scope_full)

    result = {
        "business_scope": business_scope,
        "consumer_scope_full": consumer_scope_full
    }

    scope_cache[client_id] = {
        "data": result,
        "expiry": now + CACHE_TTL
    }

    return result


def read_auth_token(ctx, data):
    try:
        raw = data.getvalue() if data is not None else b""
        logger.info("read_auth_token: payload_bytes=%d", len(raw))

        if raw:
            payload = json.loads(raw.decode("utf-8"))
            logger.info("read_auth_token: top_keys=%s", list(payload.keys()))

            # GitHub sample shape: payload.data.token
            nested_data = payload.get("data", {})
            if isinstance(nested_data, dict):
                logger.info("read_auth_token: data_keys=%s", list(nested_data.keys()))
                token = nested_data.get("token") or nested_data.get("authorization")
                if token:
                    logger.info("read_auth_token: token found in payload.data")
                    return token

            token = payload.get("token") or payload.get("authorization")
            if token:
                logger.info("read_auth_token: token found in payload root")
                return token

            req = payload.get("request", {})
            if isinstance(req, dict):
                headers = req.get("headers", {})
                if isinstance(headers, dict):
                    token = (
                        headers.get("Authorization")
                        or headers.get("authorization")
                        or headers.get("token")
                    )
                    if token:
                        logger.info("read_auth_token: token found in payload.request.headers")
                        return token

    except Exception as ex:
        logger.warning("read_auth_token: payload parse error: %s", str(ex))

    try:
        headers = ctx.Headers() or {}
        logger.info("read_auth_token: fn_header_keys=%s", list(headers.keys()))
        token = (
            headers.get("Authorization")
            or headers.get("authorization")
            or headers.get("token")
            or headers.get("Token")
        )
        if token:
            logger.info("read_auth_token: token found in fn headers")
            return token
    except Exception as ex:
        logger.warning("read_auth_token: ctx.Headers read error: %s", str(ex))

    logger.error("read_auth_token: token not found in payload or headers")
    return None


def handler(ctx, data: io.BytesIO = None):
    try:
        logger.info("handler: start")
        initContext(dict(ctx.Config()))

        auth_header = read_auth_token(ctx, data)
        if not auth_header:
            return deny(ctx, "Authorization header/token not found")

        logger.info("handler: auth_scheme=%s", auth_header.split(" ", 1)[0])

        client_id, client_secret = extract_basic_auth(auth_header)
        scopes = get_client_scopes(client_id, client_secret)

        business_scope = scopes.get("business_scope")
        consumer_scope_full = scopes.get("consumer_scope_full")

        if not business_scope:
            return deny(ctx, "No business scope assigned")
        if not consumer_scope_full:
            return deny(ctx, "consumer::all not assigned")

        # IMPORTANT: request token with full scope string from IAM App
        logger.info("handler: using full consumer scope=%s", consumer_scope_full)
        oic_token = get_access_token(client_id, client_secret, consumer_scope_full)

        logger.info("handler: success for %s", mask_value(client_id))
        return build_response(ctx, 200, {
            "active": True,
            "scope": business_scope,
            "token": f"Bearer {oic_token}",
            "context": {"token": f"Bearer {oic_token}"}
        })

    except Exception as ex:
        logger.exception("handler: unhandled exception")
        return deny(ctx, str(ex), 500)

