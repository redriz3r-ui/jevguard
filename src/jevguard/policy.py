from dataclasses import dataclass
import math
from .models import AgentAction, Decision, GuardAssessment, PolicyDecision
from .sandbox import SandboxViolation, validate_path


@dataclass(frozen=True)
class Policy:
    review_threshold: float = 0.4
    block_threshold: float = 0.8
    block_private: bool = True

    def __post_init__(self) -> None:
        if not (math.isfinite(self.review_threshold) and math.isfinite(self.block_threshold)
                and 0 <= self.review_threshold < self.block_threshold <= 1):
            raise ValueError("Require 0 <= review_threshold < block_threshold <= 1")

    def evaluate(self, action: AgentAction, assessment: GuardAssessment) -> PolicyDecision:
        if action.tool != "read_file":
            return PolicyDecision(Decision.BLOCK, "Unsupported tool")
        try:
            path = validate_path(action.path)
        except SandboxViolation as exc:
            return PolicyDecision(Decision.BLOCK, str(exc))
        if self.block_private and path.startswith("private/"):
            return PolicyDecision(Decision.BLOCK, "Policy prohibits private-file access")
        if assessment.risk_score >= self.block_threshold:
            return PolicyDecision(Decision.BLOCK, "Risk meets block threshold")
        if assessment.risk_score >= self.review_threshold:
            return PolicyDecision(Decision.REVIEW, "Risk meets review threshold; execution withheld")
        return PolicyDecision(Decision.ALLOW, "Risk is below review threshold")
