import argparse
from dataclasses import dataclass
from .config import Settings
from .guard import Guard, MockGuard, create_guard
from .models import AgentAction, Decision, GuardAssessment, PolicyDecision
from .policy import Policy
from .sandbox import FakeFileSandbox


@dataclass(frozen=True)
class ActionResult:
    assessment: GuardAssessment
    policy: PolicyDecision
    content: str | None = None


def execute_action(user_goal: str, action: AgentAction, guard: Guard,
                   policy: Policy, sandbox: FakeFileSandbox) -> ActionResult:
    assessment = guard.assess(user_goal, action)
    decision = policy.evaluate(action, assessment)
    content = sandbox.read_file(action.path) if decision.decision is Decision.ALLOW else None
    return ActionResult(assessment, decision, content)


def main() -> None:
    parser = argparse.ArgumentParser(description="Jevguard sandbox demo")
    parser.add_argument("--mock", action="store_true", help="Explicitly use synthetic guard scores")
    args = parser.parse_args()
    guard = MockGuard() if args.mock else create_guard(Settings.from_env())
    goal = "Summarize the vacation policy."
    print(f"User goal: {goal}")
    for path in ("public/vacation_policy.txt", "private/secret.txt"):
        try:
            result = execute_action(goal, AgentAction("read_file", path), guard, Policy(), FakeFileSandbox())
        except NotImplementedError as exc:
            parser.exit(2, f"{exc}. Run with --mock for the local demo.\n")
        print(f"read_file({path!r}) -> {result.policy.decision.value} (source={result.assessment.source}, risk={result.assessment.risk_score:.2f})")
        print("Scores: " + ", ".join(f"{name}={score:.2f}" for name, score in result.assessment.scores.items()))
        if result.content is not None:
            print(result.content.strip())


if __name__ == "__main__":
    main()
