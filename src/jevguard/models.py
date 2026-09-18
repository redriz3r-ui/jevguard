from dataclasses import dataclass
from enum import Enum
import math


class Decision(str, Enum):
    ALLOW = "ALLOW"
    REVIEW = "REVIEW"
    BLOCK = "BLOCK"


@dataclass(frozen=True)
class AgentAction:
    tool: str
    path: str


@dataclass(frozen=True)
class GuardAssessment:
    prompt_injection: float
    goal_conflict: float
    tool_misuse: float
    sensitive_data_access: float
    requires_human_review: float
    reason: str
    source: str

    def __post_init__(self) -> None:
        for name, score in self.scores.items():
            if not math.isfinite(score) or not 0 <= score <= 1:
                raise ValueError(f"{name} must be finite and between 0 and 1")

    @property
    def scores(self) -> dict[str, float]:
        return {
            "prompt_injection": self.prompt_injection,
            "goal_conflict": self.goal_conflict,
            "tool_misuse": self.tool_misuse,
            "sensitive_data_access": self.sensitive_data_access,
            "requires_human_review": self.requires_human_review,
        }

    @property
    def risk_score(self) -> float:
        """Use the highest dimension so a serious signal cannot be averaged away."""
        return max(self.scores.values())


@dataclass(frozen=True)
class PolicyDecision:
    decision: Decision
    reason: str
