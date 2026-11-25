import pytest
from pydantic import ValidationError

from openhands.automation.draft_schemas import PromptAutomationDraftBody
from openhands.automation.plugin_specs import CreatePluginSpecAutomationRequest
from openhands.automation.preset_router import (
    CreatePluginAutomationRequest,
    CreatePromptAutomationRequest,
)
from openhands.automation.schemas import (
    CreateAutomationRequest,
    UpdateAutomationRequest,
)


EXECUTION_PROFILE_ID = "openhands-pool"
TRIGGER = {"type": "cron", "schedule": "0 9 * * *"}


@pytest.mark.parametrize(
    "model,payload",
    [
        (
            CreateAutomationRequest,
            {
                "name": "Raw",
                "trigger": TRIGGER,
                "tarball_path": "s3://bucket/code.tar.gz",
                "entrypoint": "python main.py",
            },
        ),
        (UpdateAutomationRequest, {}),
        (
            CreatePromptAutomationRequest,
            {"name": "Prompt", "prompt": "Do work", "trigger": TRIGGER},
        ),
        (
            CreatePluginAutomationRequest,
            {
                "name": "Plugin",
                "plugins": [{"source": "https://example.com/plugin.git"}],
                "prompt": "Do work",
                "trigger": TRIGGER,
            },
        ),
        (
            CreatePluginSpecAutomationRequest,
            {
                "name": "Plugin spec",
                "plugin": {"source": "https://example.com/plugin.git"},
                "trigger": TRIGGER,
            },
        ),
        (
            PromptAutomationDraftBody,
            {"name": "Draft", "prompt": "Do work", "trigger": TRIGGER},
        ),
    ],
)
def test_execution_profile_slug_is_accepted_by_every_request_model(model, payload):
    parsed = model.model_validate(
        {**payload, "execution_profile_id": EXECUTION_PROFILE_ID}
    )

    assert parsed.execution_profile_id == EXECUTION_PROFILE_ID


@pytest.mark.parametrize("execution_profile_id", ["", "   ", 123])
def test_invalid_execution_profile_ids_are_rejected(execution_profile_id):
    with pytest.raises(ValidationError):
        UpdateAutomationRequest.model_validate(
            {"execution_profile_id": execution_profile_id}
        )


def test_execution_profile_id_defaults_to_none():
    assert UpdateAutomationRequest().execution_profile_id is None
