"""Tests for the per-run API key mint."""

import json
import uuid
from types import SimpleNamespace
from unittest.mock import patch

import httpx
import pytest

from openhands.automation.utils.api_key import (
    APIKeyError,
    get_api_key_for_automation_run,
)


def _run(*, trusted_identity: bool = False) -> SimpleNamespace:
    return SimpleNamespace(
        id=uuid.uuid4(),
        automation=SimpleNamespace(
            user_id=uuid.uuid4(),
            org_id=uuid.uuid4(),
            run_as_identity_provider="entra" if trusted_identity else None,
            run_as_identity_tenant_id="tenant-1" if trusted_identity else None,
            run_as_identity_subject_id="object-1" if trusted_identity else None,
        ),
    )


def _serve(handler):
    """Make the mint's own `httpx.AsyncClient` talk to ``handler``."""
    real = httpx.AsyncClient
    return patch(
        "openhands.automation.utils.api_key.httpx.AsyncClient",
        lambda **kwargs: real(transport=httpx.MockTransport(handler), **kwargs),
    )


async def test_mint_returns_the_key():
    with _serve(lambda request: httpx.Response(200, json={"key": "sk-oh-1"})):
        assert await get_api_key_for_automation_run(_run()) == "sk-oh-1"  # type: ignore[arg-type]


async def test_trusted_identity_mint_uses_canonical_body():
    run = _run(trusted_identity=True)

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/api/service/automation/api-keys"
        assert request.headers["X-Service-API-Key"] == "test-service-key"
        assert request.read()
        assert request.content
        assert json.loads(request.content) == {
            "identity_provider": "entra",
            "tenant_id": "tenant-1",
            "subject_id": "object-1",
            "organization_id": str(run.automation.org_id),
            "run_id": str(run.id),
        }
        return httpx.Response(200, json={"key": "ohk_run_key"})

    with (
        patch("openhands.automation.utils.api_key.get_settings") as get_settings,
        _serve(handler),
    ):
        get_settings.return_value.openhands_api_base_url = "http://sandbox-server:3000"
        get_settings.return_value.service_key = "test-service-key"
        assert (
            await get_api_key_for_automation_run(run)  # type: ignore[arg-type]
            == "ohk_run_key"
        )


async def test_incomplete_trusted_identity_is_rejected_without_request():
    run = _run()
    run.automation.run_as_identity_provider = "entra"

    with pytest.raises(APIKeyError, match="identity is incomplete"):
        await get_api_key_for_automation_run(run)  # type: ignore[arg-type]


@pytest.mark.parametrize("status_code", [401, 403, 404, 503])
async def test_http_error_carries_the_status_code(status_code):
    with _serve(lambda request: httpx.Response(status_code, text="nope")):
        with pytest.raises(APIKeyError) as exc_info:
            await get_api_key_for_automation_run(_run())  # type: ignore[arg-type]

    assert exc_info.value.status_code == status_code


async def test_network_error_and_missing_key_have_no_status_code():
    def unreachable(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("down", request=request)

    with _serve(unreachable):
        with pytest.raises(APIKeyError) as network:
            await get_api_key_for_automation_run(_run())  # type: ignore[arg-type]
    with _serve(lambda request: httpx.Response(200, json={})):
        with pytest.raises(APIKeyError) as no_key:
            await get_api_key_for_automation_run(_run())  # type: ignore[arg-type]

    assert network.value.status_code is None
    assert no_key.value.status_code is None
