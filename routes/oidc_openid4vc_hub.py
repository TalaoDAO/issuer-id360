"""ID360 KYC flow followed by CORE PID issuance through openid4vc-hub."""

import base64
import io
import json
import logging
import uuid
from datetime import datetime, timezone

import qrcode
import requests
from dateutil.relativedelta import relativedelta
from flask import jsonify, redirect, render_template, request, url_for

from id360 import ID360_API_KEY, OPENID4VC_HUB_API_KEY


ID360_SESSION_LIFE = 24 * 60 * 60
ID360_TOKEN_LIFE = 14 * 60
HUB_ISSUANCE_LIFE = 600
HUB_REQUEST_TIMEOUT = 10
CALLBACK_LOCK_LIFE = 60

# CORE PID configuration from the openid4vc-hub sandbox.
OPENID4VC_HUB_ISSUER = "core-pid-issuer"
OPENID4VC_HUB_PID_CONFIGURATION_ID = "eu.europa.ec.eudi.pid_jwt_vc"
OPENID4VC_HUB_GRANT_TYPE = (
    "urn:ietf:params:oauth:grant-type:pre-authorized_code"
)

# Set these values for the target Hub deployment, or expose equivalent
# attributes on mode as openid4vc_hub_url / openid4vc_hub_api_key.
OPENID4VC_HUB_URL = "https://openid4vc-hub.com"

red = None
mode = None

def init_app(app, red_app, mode_app):
    global red, mode
    red = red_app
    mode = mode_app

    app.add_url_rule(
        "/id360/wait/<code>",
        endpoint="openid4vc_hub_wait",
        view_func=oidc4vc_wait,
        methods=["GET"],
    )

    app.add_url_rule(
        "/id360",
        endpoint="openid4vc_hub_login",
        view_func=login_oidc,
        methods=["GET"],
    )

    app.add_url_rule(
        "/id360/callback/<code>",
        endpoint="openid4vc_hub_id360_callback",
        view_func=oidc_id360callback,
        methods=["GET", "POST"],
    )

    app.add_url_rule(
        "/id360/kyc_status/<code>",
        endpoint="openid4vc_hub_kyc_status",
        view_func=get_status_kyc,
        methods=["GET"],
    )

    app.add_url_rule(
        "/id360/offer/<code>",
        endpoint="openid4vc_hub_offer",
        view_func=oidc4vc_offer,
        methods=["GET"],
    )

    app.add_url_rule(
        "/id360/status/<code>",
        endpoint="openid4vc_hub_status",
        view_func=oidc4vc_status,
        methods=["GET"],
    )
    


def _hub_base_url() -> str:
    value = getattr(mode, "openid4vc_hub_url", None) or OPENID4VC_HUB_URL
    return (value or "").rstrip("/")


def _hub_api_key() -> str:
    return getattr(mode, "openid4vc_hub_api_key", None) or OPENID4VC_HUB_API_KEY


def _hub_headers() -> dict:
    api_key = _hub_api_key()
    if not api_key:
        raise RuntimeError("openid4vc-hub API key is not configured")
    return {
        "Accept": "application/json",
        "Content-Type": "application/json",
        "X-API-Key": api_key,
    }


def _hub_url(path: str) -> str:
    base_url = _hub_base_url()
    if not base_url:
        raise RuntimeError("openid4vc-hub URL is not configured")
    return base_url + path


def loginID360() -> bool:
    """Authenticate against ID360 and cache the token in Redis."""
    headers = {
        "accept": "application/json",
        "Content-Type": "application/json",
    }
    json_data = {"username": mode.username, "password": mode.password}

    try:
        response = requests.post(
            mode.url + "api/1.0.0/user/login/",
            headers=headers,
            json=json_data,
            timeout=HUB_REQUEST_TIMEOUT,
        )
    except requests.RequestException:
        logging.exception("loginID360 connection failed")
        return False

    if response.status_code != 200:
        logging.error("login ID360 failed returned status %s", response.status_code)
        return False

    token = response.json()["token"]
    red.setex("token", ID360_TOKEN_LIFE, token)
    return True


def _id360_token(*, refresh: bool = False) -> str | None:
    token = None if refresh else red.get("token")
    if token is None:
        if not loginID360():
            return None
        token = red.get("token")
    if token is None:
        return None
    if isinstance(token, bytes):
        token = token.decode()
    return token


def create_dossier(code: str, *, retry_on_unauthorized: bool = True) -> str | None:
    """Create the ID360 dossier used to obtain PID claims."""
    token = _id360_token()
    if token is None:
        return None

    headers = {
        "accept": "application/json",
        "Authorization": "Token " + token,
        "Content-Type": "application/json",
    }
    json_data = {
        "callback_url": (
            mode.server + "/id360/callback/" + code
        ),
        "browser_callback_url": (
            mode.server + "/id360/wait/" + code
        ),
        "client_reference": "Talao CORE PID issuer",
        "callback_headers": {
            "code": code,
            "api-key": ID360_API_KEY,
        },
    }

    url = mode.url + "api/1.0.0/process/" + mode.journey_oidc + "/enrollment/"
    try:
        response = requests.post(
            url,
            headers=headers,
            json=json_data,
            timeout=HUB_REQUEST_TIMEOUT,
        )
    except requests.RequestException:
        logging.exception("create_dossier request failed")
        return None

    if response.status_code == 401:
        if retry_on_unauthorized and _id360_token(refresh=True):
            return create_dossier(code, retry_on_unauthorized=False)
        return None

    if response.status_code != 200:
        logging.error("create_dossier returned status = %s", response.status_code)
        return None

    red.setex(
        code,
        ID360_SESSION_LIFE,
        json.dumps({"id_dossier": response.json()["id"], "KYC": "PENDING"}),
    )
    return (
        mode.url
        + "static/process_ui/index.html#/enrollment/"
        + response.json()["api_key"]
        + "?lang=en"
    )


def get_dossier(
    id_dossier: str, *, retry_on_unauthorized: bool = True
) -> dict | None:
    token = _id360_token()
    if token is None:
        logging.error("ID360 token expired in redis")
        return None

    headers = {
        "accept": "application/json",
        "Authorization": "Token " + token,
    }
    try:
        response = requests.get(
            mode.url
            + "api/1.0.0/enrollment/"
            + str(id_dossier)
            + "/report?allow_draft=false",
            headers=headers,
            timeout=HUB_REQUEST_TIMEOUT,
        )
    except requests.RequestException:
        logging.exception("get_dossier request connection failed")
        return None

    if response.status_code == 200:
        return response.json()
    if response.status_code == 401:
        if retry_on_unauthorized and _id360_token(refresh=True):
            return get_dossier(id_dossier, retry_on_unauthorized=False)
        return None
    if response.status_code == 404:
        logging.warning("dossier %s expired", id_dossier)
        return None

    logging.error("error requesting dossier status: %s", response.status_code)
    return None


def login_oidc():
    """Start ID360 identification before creating the Hub issuance."""
    code = str(uuid.uuid4())
    redirect_link = create_dossier(code)
    if not redirect_link:
        return jsonify(error="kyc_provider_failed"), 502
    return redirect(redirect_link)


def oidc4vc_wait(code):
    return render_template(
        "openid4vc_hub_wait.html",
        status_url=url_for("openid4vc_hub_kyc_status", code=code),
    )


def get_status_kyc(code):
    raw = red.get(code)
    if raw is None:
        return jsonify(status="None")
    if isinstance(raw, bytes):
        raw = raw.decode()

    try:
        code_data = json.loads(raw)
    except (TypeError, json.JSONDecodeError):
        return jsonify(status="None")

    return jsonify(
        status=code_data.get("KYC", "None"),
        url=code_data.get("url", ""),
    )


def _build_pid_claims(dossier: dict) -> dict:
    """Map ID360 output to the CORE PID claim names configured in the Hub."""
    now = datetime.now(timezone.utc).replace(microsecond=0)
    is_idnumeric = dossier.get("id_verification_service") == "IdNumericExternalMethod"

    if is_idnumeric:
        source = dossier["external_methods"]["id_num"]["results"][
            "id_num_out_token"
        ][0]["payload"]
        birthdate = source.get("birthdate")
        given_name = source.get("given_name")
        family_name = source.get("family_name")
        gender = source.get("gender")
        sex = {"male": 1, "female": 2}.get(
            gender.lower() if isinstance(gender, str) else gender
        )
        nationalities = ["FR"] if source.get("typ") == "ID" else []
    else:
        source = dossier.get("identity", {})
        birthdate = source.get("birth_date")
        given_name = " ".join(
            value.strip()
            for value in (source.get("first_names") or [])
            if isinstance(value, str) and value.strip()
        )
        family_name = source.get("name")
        gender = source.get("gender")
        sex = {"M": 1, "F": 2}.get(
            gender.upper() if isinstance(gender, str) else gender
        )
        nationalities = ["FR"]

    family_name = family_name.strip() if isinstance(family_name, str) else ""
    given_name = given_name.strip() if isinstance(given_name, str) else ""
    birthdate = birthdate[:10] if isinstance(birthdate, str) else ""

    missing_claims = [
        name
        for name, value in (
            ("family_name", family_name),
            ("given_name", given_name),
            ("birthdate", birthdate),
            ("sex", sex),
        )
        if value in (None, "")
    ]
    if missing_claims:
        raise ValueError(
            "Missing or unsupported required PID claims: "
            + ", ".join(missing_claims)
        )

    try:
        parsed_birthdate = datetime.strptime(birthdate, "%Y-%m-%d").date()
    except ValueError as error:
        raise ValueError("Invalid PID birthdate") from error
    if parsed_birthdate > now.date():
        raise ValueError("PID birthdate cannot be in the future")
    birthdate = parsed_birthdate.isoformat()

    claims = {
        "family_name": family_name,
        "given_name": given_name,
        "birthdate": birthdate,
        "nationalities": nationalities,
        "date_of_expiry": (now + relativedelta(years=5)).date().isoformat(),
        "issuing_authority": "Talao",
        "issuing_country": "FR",
        "sex": sex,
        "date_of_issuance": now.date().isoformat(),
    }

    # Keep optional fields only when ID360 actually provides them.
    if is_idnumeric:
        if source.get("document_number"):
            claims["document_number"] = source["document_number"]
        if source.get("place_of_birth"):
            claims["place_of_birth"] = source["place_of_birth"]

    return claims


def _create_hub_pid_issuance(claims: dict) -> dict:
    payload = {
        "issuer": OPENID4VC_HUB_ISSUER,
        "grant_type": OPENID4VC_HUB_GRANT_TYPE,
        "expires_in": HUB_ISSUANCE_LIFE,
        "credentials": [
            {
                "credential_configuration_id": OPENID4VC_HUB_PID_CONFIGURATION_ID,
                "claims": claims,
            }
        ],
    }

    response = requests.post(
        _hub_url("/api/v1/issuances"),
        headers=_hub_headers(),
        json=payload,
        timeout=HUB_REQUEST_TIMEOUT,
    )

    try:
        body = response.json()
    except ValueError:
        body = {"error": response.text or f"HTTP {response.status_code}"}

    if response.status_code not in (200, 201):
        raise RuntimeError(
            f"Hub issuance creation failed ({response.status_code}): "
            + json.dumps(body, ensure_ascii=False)
        )

    if not body.get("issuance_id") or not body.get("qr_code_content"):
        raise RuntimeError("Hub response is missing issuance_id or qr_code_content")

    return body


def _set_kyc_error(code: str, id_dossier, description: str = "") -> None:
    red.setex(
        code,
        HUB_ISSUANCE_LIFE,
        json.dumps(
            {
                "id_dossier": id_dossier,
                "KYC": "KO",
                "url": "",
                "error": description,
            }
        ),
    )


def oidc_id360callback(code: str):
    """Receive ID360 result and create the CORE PID issuance in the Hub."""
    if request.headers.get("api-key") != ID360_API_KEY:
        return jsonify("Unauthorized"), 403

    raw = red.get(code)
    if raw is None:
        logging.error("redis expired %s", code)
        return jsonify("ok")
    if isinstance(raw, bytes):
        raw = raw.decode()

    try:
        code_data = json.loads(raw)
        id_dossier = code_data["id_dossier"]
    except (TypeError, KeyError, json.JSONDecodeError):
        logging.error("invalid Redis state for %s", code)
        return jsonify("ok")

    body = request.get_json(silent=True) or {}
    status = body.get("status")
    logging.info("ID360 callback for code %s: %s", code, status)

    if status not in {"CANCELED", "FAILED", "KO", "OK"}:
        return jsonify("ok")

    lock_key = f"openid4vc_hub:callback:{code}"
    if not red.set(lock_key, "1", nx=True, ex=CALLBACK_LOCK_LIFE):
        logging.info("ID360 callback already being processed for %s", code)
        return jsonify("ok")

    try:
        current_raw = red.get(code)
        if isinstance(current_raw, bytes):
            current_raw = current_raw.decode()
        try:
            current_state = json.loads(current_raw)
        except (TypeError, json.JSONDecodeError):
            logging.error("invalid Redis state for %s", code)
            return jsonify("ok")

        if current_state.get("KYC") != "PENDING":
            logging.info(
                "Ignoring duplicate ID360 callback for %s in state %s",
                code,
                current_state.get("KYC"),
            )
            return jsonify("ok")

        if status in {"CANCELED", "FAILED", "KO"}:
            _set_kyc_error(code, id_dossier, f"ID360 status: {status}")
            return jsonify("ok")

        red.setex(
            code,
            HUB_ISSUANCE_LIFE,
            json.dumps(
                {
                    "id_dossier": id_dossier,
                    "KYC": "CREATING",
                    "url": "",
                }
            ),
        )

        dossier = get_dossier(id_dossier)
        if not dossier:
            _set_kyc_error(code, id_dossier, "Cannot retrieve ID360 dossier")
            return jsonify("ok")

        try:
            claims = _build_pid_claims(dossier)
            hub_issuance = _create_hub_pid_issuance(claims)
        except (
            KeyError,
            TypeError,
            ValueError,
            requests.RequestException,
            RuntimeError,
        ) as error:
            logging.exception("Cannot create CORE PID issuance")
            _set_kyc_error(code, id_dossier, str(error))
            return jsonify("ok")

        offer_url = mode.server + "/id360/offer/" + code
        red.setex(
            code,
            HUB_ISSUANCE_LIFE,
            json.dumps(
                {
                    "id_dossier": id_dossier,
                    "KYC": "OK",
                    "url": offer_url,
                    "issuance_id": hub_issuance["issuance_id"],
                    "qr_code_content": hub_issuance["qr_code_content"],
                    "credential_offer_uri": hub_issuance.get(
                        "credential_offer_uri"
                    ),
                    "expires_at": hub_issuance.get("expires_at"),
                }
            ),
        )
        return jsonify("ok")
    finally:
        red.delete(lock_key)


def _load_code_state(code: str) -> dict | None:
    raw = red.get(code)
    if raw is None:
        return None
    if isinstance(raw, bytes):
        raw = raw.decode()
    try:
        return json.loads(raw)
    except (TypeError, json.JSONDecodeError):
        return None


def _qr_data_uri(content: str) -> str:
    image = qrcode.make(content)
    output = io.BytesIO()
    image.save(output, format="PNG")
    encoded = base64.b64encode(output.getvalue()).decode()
    return "data:image/png;base64," + encoded


def oidc4vc_offer(code: str):
    state = _load_code_state(code)
    if not state or state.get("KYC") != "OK":
        return render_template(
            "openid4vc_hub_error.html",
            error="issuance_not_found",
            error_description="The issuance session is unavailable or expired.",
        ), 404

    qr_code_content = state.get("qr_code_content")
    issuance_id = state.get("issuance_id")
    if not qr_code_content or not issuance_id:
        return render_template(
            "openid4vc_hub_error.html",
            error="invalid_issuance_state",
            error_description="The Hub issuance data is incomplete.",
        ), 500

    return render_template(
        "openid4vc_hub_pid.html",
        code=code,
        issuance_id=issuance_id,
        qr_code_content=qr_code_content,
        qr_image=_qr_data_uri(qr_code_content),
        status_url=mode.server + "/id360/status/" + code,
        expires_at=state.get("expires_at"),
    )


def oidc4vc_status(code: str):
    """Proxy Hub polling so the Hub API key is never exposed to the browser."""
    state = _load_code_state(code)
    if not state or not state.get("issuance_id"):
        return jsonify(error="issuance_not_found"), 404

    issuance_id = state["issuance_id"]
    try:
        response = requests.get(
            _hub_url(f"/api/v1/issuances/{issuance_id}"),
            headers=_hub_headers(),
            timeout=HUB_REQUEST_TIMEOUT,
        )
    except (requests.RequestException, RuntimeError) as error:
        return (
            jsonify(
                status="failed",
                error="hub_unreachable",
                error_description=str(error),
            ),
            502,
        )

    try:
        body = response.json()
    except ValueError:
        body = {
            "error": "invalid_hub_response",
            "error_description": response.text,
        }

    return jsonify(body), response.status_code
