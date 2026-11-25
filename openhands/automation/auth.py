"""Authentication for the automations service API.

Supports four authentication methods (checked in order):
1. Trusted identity assertion forwarded by an authenticated ingress
2. API key via Authorization: Bearer header
3. API key via X-Session-API-Key header (matches agent-server convention,
   useful behind reverse proxies that overwrite the Authorization header)
4. Cookie: the OpenHands web UI session cookie, either the new OAuth v2
   ``openhands_auth`` JWT cookie or the legacy ``keycloak_auth`` cookie

Trusted ingress identity is validated locally and authorized through Sandbox
Server's organization membership endpoint. Other methods validate against the
OpenHands API GET /api/v1/users/me endpoint.
"""

import hashlib
import logging
import secrets
import uuid
from enum import StrEnum
from typing import Any

import httpx
import jwt
from cachetools import TTLCache
from fastapi import Depends, HTTPException, Request, status
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator
from pydantic.dataclasses import dataclass
from tenacity import (
    RetryCallState,
    before_sleep_log,
    retry,
    retry_if_result,
    stop_after_attempt,
    wait_exponential,
)

from openhands.automation.config import get_config


logger = logging.getLogger("automation.auth")

# Auth cache - initialized lazily to use config values
_auth_cache: TTLCache[str, "AuthenticatedUser"] | None = None

# Session cookies accepted from the OpenHands web UI. ``openhands_auth`` is
# the OAuth v2 JWT cookie issued to new logins; ``keycloak_auth`` is the
# legacy chunked cookie that existing sessions still carry. Both are checked,
# new first, so a client mid-migration that holds the old cookie keeps working
# while new logins authenticate with the new one. ``keycloak_auth`` alone is
# chunked, but we reassemble either name defensively.
SESSION_COOKIE_NAMES = ("openhands_auth", "keycloak_auth")
X_ORG_ID_HEADER = "X-Org-Id"
TRUSTED_IDENTITY_NAMESPACE = uuid.UUID("7aa6df4c-9243-4bad-8933-7863e0412d5c")
# Keep parity with OpenHands' cookie chunking helper: 8 * 3000 bytes is
# comfortably above expected session token sizes while staying bounded.
MAX_SESSION_COOKIE_CHUNKS = 8


def _get_auth_cache() -> TTLCache[str, "AuthenticatedUser"]:
    """Get or create the auth cache with config-based settings."""
    global _auth_cache
    if _auth_cache is None:
        http_config = get_config().http
        _auth_cache = TTLCache[str, AuthenticatedUser](
            maxsize=http_config.auth_cache_size,
            ttl=http_config.auth_cache_ttl,
        )
    return _auth_cache


def _reset_auth_cache() -> None:
    """Reset the auth cache so it will be recreated with new config values.

    Called by clear_config_cache() to ensure tests that change config see
    the new cache settings take effect.
    """
    global _auth_cache
    _auth_cache = None


class AuthMethod(StrEnum):
    """Authentication method used for the request."""

    API_KEY = "api_key"
    COOKIE = "cookie"
    LOCAL_API_KEY = "local_api_key"
    TRUSTED_IDENTITY = "trusted_identity"


def create_http_client() -> httpx.AsyncClient:
    """Create a new httpx client for auth requests."""
    return httpx.AsyncClient(timeout=get_config().http.http_timeout)


def get_http_client(request: Request) -> httpx.AsyncClient:
    """FastAPI dependency to get the shared httpx client from app.state.

    The client is created during app startup and stored in app.state.http_client.
    This enables proper dependency injection and makes testing easier.
    """
    client: httpx.AsyncClient | None = getattr(request.app.state, "http_client", None)
    if client is None or client.is_closed:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="HTTP client not initialized",
        )
    return client


@dataclass
class AuthenticatedUser:
    user_id: uuid.UUID
    org_id: uuid.UUID
    email: str
    role: str
    permissions: list[str]
    auth_method: AuthMethod
    api_key: str | None = None  # Set when auth_method == API_KEY
    model_profile_names: frozenset[str] | None = None
    active_model_profile_name: str | None = None
    identity_provider: str | None = None
    identity_tenant_id: str | None = None
    identity_subject_id: str | None = None


def _store_authenticated_user(
    request: Request, user: AuthenticatedUser
) -> AuthenticatedUser:
    request.state.authenticated_user = user
    return user


class _LLMProfiles(BaseModel):
    """Consuming subset of the upstream ``LLMProfiles`` model.

    Mirrors ``openhands/app_server/settings/llm_profiles.py``: the
    ``/api/v1/users/me`` response embeds ``llm_profiles`` as
    ``{"profiles": {name: {...}}, "active": str | None}``. We only read the
    profile names and the active name, so the profile values are typed ``Any``.

    Tolerant by design, matching upstream's "degrade rather than fail" stance
    (its own validators drop invalid profiles and reconcile a stale ``active``):
    this is optional secondary metadata, so an unexpected shape becomes "no
    profiles" instead of failing authentication.
    """

    model_config = ConfigDict(extra="ignore")

    profiles: dict[str, Any] = Field(default_factory=dict)
    active: str | None = None

    @field_validator("profiles", mode="before")
    @classmethod
    def _ignore_non_object_profiles(cls, v: Any) -> Any:
        return v if isinstance(v, dict) else {}

    @field_validator("active", mode="before")
    @classmethod
    def _ignore_non_string_active(cls, v: Any) -> Any:
        return v if isinstance(v, str) else None

    def profile_names(self) -> frozenset[str]:
        """Return the set of saved profile names (empty when there are none)."""
        return frozenset(self.profiles)


class _UsersMe(BaseModel):
    """Consuming subset of the OpenHands ``/api/v1/users/me`` response.

    Field types mirror the upstream ``SaasUserInfo`` model (which extends
    ``UserInfo`` → ``Settings``): ``id``/``org_id``/``email``/``role`` are
    ``str | None`` and ``permissions`` is ``list[str] | None`` — all nullable,
    as the SaaS endpoint serializes them (e.g. as ``null`` without org context).

    Modelling the response with pydantic means an incompatible upstream change
    to a field we rely on fails fast (surfaced as a 502) instead of silently
    mis-parsing — the failure mode that previously hid an ``active`` profile
    field-name bug. ``extra="ignore"`` keeps us forward-compatible with new
    response fields we do not read (such as ``org_name``).
    """

    model_config = ConfigDict(extra="ignore")

    id: str | None = None
    org_id: str | None = None
    email: str | None = None
    role: str | None = None
    permissions: list[str] | None = None
    llm_profiles: _LLMProfiles | None = None

    @field_validator("llm_profiles", mode="before")
    @classmethod
    def _ignore_non_object_profiles(cls, v: Any) -> Any:
        # Secondary metadata: anything that is not a JSON object is treated as
        # absent so a shape change here can never break authentication.
        return v if isinstance(v, dict) else None


class _OrganizationMembership(BaseModel):
    """Consuming subset of Sandbox Server's organization membership response."""

    model_config = ConfigDict(extra="ignore")

    org_id: uuid.UUID
    user_id: uuid.UUID
    role: str
    permissions: list[str]


def _trusted_identity_user_id(
    provider: str, tenant_id: str, subject_id: str
) -> uuid.UUID:
    """Stable Automation-local owner id for one immutable external identity."""
    return uuid.uuid5(
        TRUSTED_IDENTITY_NAMESPACE,
        "\0".join((provider, tenant_id, subject_id)),
    )


def _decode_trusted_identity_assertion(
    assertion: str,
) -> tuple[str, str, str]:
    """Validate the ingress assertion and return provider, tenant, subject."""
    settings = get_config().service
    if not settings.trusted_identity_assertions_enabled:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Trusted identity authentication is not configured",
        )

    try:
        header = jwt.get_unverified_header(assertion)
        if header.get("alg") != "HS256" or header.get("typ") != "JWT":
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid trusted identity assertion",
            )
        claims = jwt.decode(
            assertion,
            settings.trusted_identity_assertion_secret,
            algorithms=["HS256"],
            issuer=settings.trusted_identity_assertion_issuer,
            audience=settings.trusted_identity_assertion_audience,
            leeway=settings.trusted_identity_assertion_clock_skew_seconds,
            options={"require": ["oid", "tid", "sub", "iss", "aud", "iat", "exp"]},
        )
    except HTTPException:
        raise
    except jwt.PyJWTError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid trusted identity assertion",
        ) from e

    subject_id = claims.get("oid")
    tenant_id = claims.get("tid")
    issued_at = claims.get("iat")
    expires_at = claims.get("exp")
    if (
        not isinstance(subject_id, str)
        or not subject_id.strip()
        or not isinstance(tenant_id, str)
        or not tenant_id.strip()
        or claims.get("sub") != subject_id
        or not isinstance(issued_at, (int, float))
        or not isinstance(expires_at, (int, float))
        or expires_at <= issued_at
        or expires_at - issued_at
        > settings.trusted_identity_assertion_max_lifetime_seconds
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid trusted identity assertion",
        )
    return "entra", tenant_id, subject_id


def clear_auth_cache() -> None:
    """Clear all cached authentication data. Useful for testing."""
    _get_auth_cache().clear()


def _credential_cache_key(
    credential: str, auth_method: AuthMethod, x_org_id: str | None
) -> str:
    """Hash auth scope for use as a cache key (never store raw credentials)."""
    cache_material = "\0".join((auth_method.value, x_org_id or "", credential))
    return hashlib.sha256(cache_material.encode()).hexdigest()


def _extract_x_org_id(request: Request) -> str | None:
    """Extract and normalize the optional organization scope header."""
    header_value = request.headers.get(X_ORG_ID_HEADER, "").strip()
    if not header_value:
        return None

    try:
        return str(uuid.UUID(header_value))
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid X-Org-Id header (must be a UUID)",
        ) from exc


def _is_rate_limited(response: httpx.Response) -> bool:
    """Check if response is a 429 rate limit response."""
    return response.status_code == 429


def _return_last_response(retry_state: RetryCallState) -> httpx.Response:
    """Return the last response when retries are exhausted."""
    logger.warning(
        "Rate limit retries exhausted after %d attempts",
        retry_state.attempt_number,
    )
    # Defensive check: outcome should be set by tenacity, but guard against
    # potential library changes or edge cases for type safety
    if retry_state.outcome is None:
        raise RuntimeError("retry_error_callback invoked without outcome")
    return retry_state.outcome.result()


# Module-level retry decorator for auth requests.
# Config is read at import time and frozen for the process lifetime.
_http_config = get_config().http
_auth_retry = retry(
    retry=retry_if_result(_is_rate_limited),
    stop=stop_after_attempt(_http_config.auth_max_retries + 1),
    wait=wait_exponential(
        multiplier=_http_config.auth_initial_backoff,
        max=_http_config.auth_max_backoff,
    ),
    before_sleep=before_sleep_log(logger, logging.WARNING),
    retry_error_callback=_return_last_response,
)


@_auth_retry
async def _make_auth_request_with_retry(
    client: httpx.AsyncClient,
    url: str,
    headers: dict[str, str],
) -> httpx.Response:
    """Make an auth request with exponential backoff retry on 429 responses.

    Uses tenacity for retry logic with exponential backoff.

    Args:
        client: The httpx client to use for requests
        url: The URL to request
        headers: Request headers

    Returns:
        The HTTP response (may still be a 429 if all retries exhausted)

    Raises:
        httpx.RequestError: If there's a network/connection error
    """
    return await client.get(url, headers=headers)


def _get_local_user() -> AuthenticatedUser:
    """Return a default user for local mode authentication.

    Used when authenticating with local_api_key in self-hosted deployments.
    Provides deterministic user/org IDs for consistent data ownership.

    Security notes:
    - Uses deterministic UUID5 based on DNS namespace, meaning every self-hosted
      installation gets identical user/org IDs. This ensures consistent data
      ownership tracking across service restarts.
    - If logs or database exports containing these IDs are shared between
      separate installations, data attribution could be ambiguous. For isolated
      deployments (the typical self-hosted case), this is acceptable.

    Access model:
    - Grants admin role with manage_automations permission, giving full access.
    - Self-hosted deployments typically have full trust in their environment,
      so permissive defaults are appropriate. Read-only or restricted access
      modes could be added later if needed via additional config options.
    """
    # Use deterministic UUIDs based on namespace (consistent across restarts)
    local_user_id = uuid.uuid5(uuid.NAMESPACE_DNS, "openhands-local-user")
    local_org_id = uuid.uuid5(uuid.NAMESPACE_DNS, "openhands-local-org")

    return AuthenticatedUser(
        user_id=local_user_id,
        org_id=local_org_id,
        email="local@localhost",
        role="admin",
        permissions=["view_automations", "manage_automations"],
        auth_method=AuthMethod.LOCAL_API_KEY,
        api_key=None,
    )


def require_permission(permission: str):
    """Factory that returns a FastAPI dependency enforcing a permission.

    Checks whether the authenticated user has the given permission string
    in their permissions list.  Raises HTTP 403 if missing, otherwise
    returns the ``AuthenticatedUser``.
    """

    async def _check(
        request: Request,
        user: "AuthenticatedUser" = Depends(authenticate_request),
    ) -> "AuthenticatedUser":
        # The audit hook reads the actor from here. authenticate_request stores
        # it too, but a caller may override that dependency.
        _store_authenticated_user(request, user)
        if permission not in user.permissions:
            logger.warning(
                "Permission denied: user %s missing permission %s",
                user.user_id,
                permission,
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Requires {permission} permission",
            )
        return user

    return _check


def _extract_api_key(request: Request) -> str | None:
    """Extract an API key from the request headers.

    Checks Authorization: Bearer first, then X-Session-API-Key as a fallback
    (useful behind reverse proxies that overwrite the Authorization header).
    Returns None when neither header carries a key.
    """
    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        key = auth_header.removeprefix("Bearer ").strip()
        if not key:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Empty API key",
            )
        return key

    session_key = request.headers.get("X-Session-API-Key", "").strip()
    return session_key or None


def _extract_session_cookie(request: Request) -> tuple[str, str] | None:
    """Read OpenHands' session cookie and return ``(name, value)``.

    Accepts the new ``openhands_auth`` JWT cookie and the legacy
    ``keycloak_auth`` cookie, preferring the new one. OpenHands splits large
    ``keycloak_auth`` values across ``keycloak_auth``, ``keycloak_auth_1``,
    etc.; the chunks are reassembled here and the whole ``name=value`` pair is
    forwarded to OpenHands ``/api/v1/users/me`` so upstream sees the cookie
    under its original name.
    """
    for name in SESSION_COOKIE_NAMES:
        first = request.cookies.get(name)
        if not first:
            continue

        parts = [first]
        for index in range(1, MAX_SESSION_COOKIE_CHUNKS):
            part = request.cookies.get(f"{name}_{index}")
            if part is None:
                break
            parts.append(part)
        return name, "".join(parts)
    return None


def _extract_credential(request: Request) -> tuple[str, AuthMethod]:
    """Extract a credential and its auth method from the request.

    Priority: Authorization: Bearer → X-Session-API-Key → session cookie
    (``openhands_auth`` or ``keycloak_auth``). For cookie auth the credential
    is the full ``name=value`` pair so the original cookie name reaches
    upstream. Raises 401 if nothing usable is found.
    """
    api_key = _extract_api_key(request)
    if api_key:
        return api_key, AuthMethod.API_KEY

    cookie = _extract_session_cookie(request)
    if cookie:
        name, value = cookie
        return f"{name}={value}", AuthMethod.COOKIE

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Authentication required: provide Bearer token, "
        "X-Session-API-Key header, or session cookie",
    )


def _upstream_headers(
    credential: str, auth_method: AuthMethod, x_org_id: str | None
) -> dict[str, str]:
    headers = (
        {"Authorization": f"Bearer {credential}"}
        if auth_method == AuthMethod.API_KEY
        # For cookie auth ``credential`` is already ``name=value``; preserve
        # the caller's cookie name so upstream parses it correctly.
        else {"Cookie": credential}
    )
    if x_org_id:
        headers[X_ORG_ID_HEADER] = x_org_id
    return headers


def upstream_auth_headers(request: Request) -> dict[str, str]:
    """Headers that carry the caller's own credential to the OpenHands API."""
    settings = get_config().service
    assertion = request.headers.get(settings.trusted_identity_assertion_header, "")
    if assertion:
        _decode_trusted_identity_assertion(assertion)
        headers = {settings.trusted_identity_assertion_header: assertion}
        if x_org_id := _extract_x_org_id(request):
            headers[X_ORG_ID_HEADER] = x_org_id
        return headers
    credential, auth_method = _extract_credential(request)
    return _upstream_headers(credential, auth_method, _extract_x_org_id(request))


def _parse_users_me(
    data: dict[str, Any], auth_method: AuthMethod, credential: str
) -> AuthenticatedUser:
    """Build an AuthenticatedUser from the OpenHands /api/v1/users/me response.

    The response is validated through :class:`_UsersMe`, so an incompatible
    upstream change to a field we rely on fails fast as a 502 rather than being
    silently mis-parsed. The optional ``llm_profiles`` block stays tolerant.
    """
    try:
        parsed = _UsersMe.model_validate(data)
    except ValidationError:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="Unexpected response shape from OpenHands API",
        )

    if not parsed.id or not parsed.org_id:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="Could not determine user/org identity from OpenHands API",
        )

    try:
        user_uuid = uuid.UUID(parsed.id)
        org_uuid = uuid.UUID(parsed.org_id)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="Invalid user_id or org_id format from OpenHands API",
        )

    # Upstream types email/role/permissions as nullable; AuthenticatedUser
    # requires non-null, so coalesce here (an authenticated automation user
    # always has org context, which populates these).
    profiles = parsed.llm_profiles
    return AuthenticatedUser(
        user_id=user_uuid,
        org_id=org_uuid,
        email=parsed.email or "",
        role=parsed.role or "",
        permissions=parsed.permissions or [],
        auth_method=auth_method,
        api_key=credential if auth_method == AuthMethod.API_KEY else None,
        model_profile_names=profiles.profile_names() if profiles else None,
        active_model_profile_name=profiles.active if profiles else None,
    )


async def authenticate_request(
    request: Request,
    client: httpx.AsyncClient = Depends(get_http_client),
) -> AuthenticatedUser:
    """Authenticate via trusted ingress identity, API key, or cookie.

    Local mode: only the configured ``local_api_key`` is accepted;
    SaaS validation is skipped entirely unless an authenticated ingress supplies
    a trusted identity assertion. In that case Sandbox Server remains the
    authority for assertion validation, identity mapping, and org permissions.

    SaaS mode: credentials are verified against ``GET /api/v1/users/me``
    with retry + in-memory caching.
    """
    settings = get_config().service

    # --- Trusted ingress identity ---
    assertion = request.headers.get(settings.trusted_identity_assertion_header, "")
    if assertion:
        identity_provider, tenant_id, subject_id = _decode_trusted_identity_assertion(
            assertion
        )
        x_org_id = _extract_x_org_id(request)
        if x_org_id is None:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=(
                    f"{X_ORG_ID_HEADER} is required with a trusted identity assertion"
                ),
            )

        cache_key = _credential_cache_key(
            assertion, AuthMethod.TRUSTED_IDENTITY, x_org_id
        )
        auth_cache = _get_auth_cache()
        if cached_user := auth_cache.get(cache_key):
            return _store_authenticated_user(request, cached_user)

        headers = {
            settings.trusted_identity_assertion_header: assertion,
            X_ORG_ID_HEADER: x_org_id,
        }
        try:
            resp = await _make_auth_request_with_retry(
                client,
                f"{settings.openhands_api_base_url}/api/organizations/{x_org_id}/me",
                headers=headers,
            )
        except httpx.RequestError as e:
            logger.error("Failed to reach trusted identity authority: %s", e)
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail="Failed to reach trusted identity authority",
            ) from e

        if resp.status_code == 401:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid trusted identity assertion",
            )
        if resp.status_code == 403:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Not authorized for requested organization",
            )
        if resp.status_code == 429:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Rate limited by trusted identity authority",
            )
        if resp.status_code != 200:
            logger.error(
                "Unexpected status from trusted identity authority: %s",
                resp.status_code,
            )
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail="Unexpected response from trusted identity authority",
            )

        try:
            membership = _OrganizationMembership.model_validate(resp.json())
        except ValidationError as e:
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail="Unexpected response shape from trusted identity authority",
            ) from e
        if str(membership.org_id) != x_org_id:
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail="Trusted identity authority returned the wrong organization",
            )

        user = AuthenticatedUser(
            user_id=_trusted_identity_user_id(identity_provider, tenant_id, subject_id),
            org_id=membership.org_id,
            email="",
            role=membership.role,
            permissions=membership.permissions,
            auth_method=AuthMethod.TRUSTED_IDENTITY,
            identity_provider=identity_provider,
            identity_tenant_id=tenant_id,
            identity_subject_id=subject_id,
        )
        auth_cache[cache_key] = user
        return _store_authenticated_user(request, user)

    # --- Local-mode fast path (no network call) ---
    api_key = _extract_api_key(request)
    if api_key and settings.is_local_mode and settings.local_api_key:
        if secrets.compare_digest(api_key, settings.local_api_key):
            logger.debug("Authenticated via local API key")
            return _store_authenticated_user(request, _get_local_user())
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API key",
        )

    # --- Resolve credential (API key or cookie) ---
    credential, auth_method = _extract_credential(request)
    x_org_id = _extract_x_org_id(request)

    # --- Cache lookup ---
    cache_key = _credential_cache_key(credential, auth_method, x_org_id)
    auth_cache = _get_auth_cache()
    cached_user = auth_cache.get(cache_key)
    if cached_user is not None:
        logger.debug("Auth cache hit for user %s", cached_user.user_id)
        return _store_authenticated_user(request, cached_user)

    # --- Validate against OpenHands API ---
    logger.debug("Auth cache miss, validating with OpenHands API")
    outbound_headers = _upstream_headers(credential, auth_method, x_org_id)

    try:
        resp = await _make_auth_request_with_retry(
            client,
            f"{settings.openhands_api_base_url}/api/v1/users/me",
            headers=outbound_headers,
        )
    except httpx.RequestError as e:
        logger.error("Failed to reach OpenHands API for auth: %s", e)
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="Failed to reach OpenHands API for authentication",
        )

    if resp.status_code == 401:
        detail = (
            "Invalid or expired API key"
            if auth_method == AuthMethod.API_KEY
            else "Invalid or expired session cookie"
        )
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=detail)
    if resp.status_code == 429:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Rate limited by authentication service",
        )
    if resp.status_code != 200:
        logger.error(
            "Unexpected status from OpenHands /api/v1/users/me: %s",
            resp.status_code,
        )
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="Unexpected response from OpenHands API",
        )

    # --- Build user and cache ---
    user = _parse_users_me(resp.json(), auth_method, credential)
    auth_cache[cache_key] = user
    return _store_authenticated_user(request, user)
