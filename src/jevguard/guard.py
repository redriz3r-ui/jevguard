"""Classifier integration boundary. No unverified TypeSafe API is called in v0.1."""
from typing import Protocol
from .config import Settings
from .models import AgentAction, GuardAssessment
from .sandbox import SandboxViolation, validate_path


class Guard(Protocol):
    def assess(self, user_goal: str, action: AgentAction) -> GuardAssessment: ...


class MockGuard:
    """Deterministic fixture scores, not a security classifier."""
    def assess(self, user_goal: str, action: AgentAction) -> GuardAssessment:
        private = action.path.startswith("private/")
        try:
            validate_path(action.path)
            invalid_path = False
        except SandboxViolation:
            invalid_path = True
        misuse = invalid_path or action.tool != "read_file"
        suspicious = private or misuse
        return GuardAssessment(
            prompt_injection=0.05,
            goal_conflict=0.95 if suspicious else 0.05,
            tool_misuse=0.95 if misuse else 0.05,
            sensitive_data_access=0.95 if private else 0.05,
            requires_human_review=0.95 if suspicious else 0.05,
            reason="Synthetic path-based scores; no semantic classification",
            source="mock",
        )


class TypeSafeGuard:
    def __init__(self, api_key: str) -> None:
        self._api_key = api_key

    def assess(self, user_goal: str, action: AgentAction) -> GuardAssessment:
        raise NotImplementedError("Live Jev integration requires a verified API contract")


def create_guard(settings: Settings) -> Guard:
    if settings.typesafe_api_key:
        return TypeSafeGuard(settings.typesafe_api_key)
    return MockGuard()
