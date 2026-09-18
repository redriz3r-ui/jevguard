import unittest
from pathlib import Path
from jevguard.agent import execute_action
from jevguard.config import Settings
from jevguard.guard import MockGuard, TypeSafeGuard, create_guard
from jevguard.models import AgentAction, Decision, GuardAssessment
from jevguard.policy import Policy
from jevguard.sandbox import DEFAULT_FILES, FakeFileSandbox, SandboxViolation


class CoreTests(unittest.TestCase):
    def assessment(self, score: float) -> GuardAssessment:
        return GuardAssessment(score, score, score, score, score, "test score", "test")

    def test_public_read(self) -> None:
        result = execute_action("Summarize the vacation policy.",
                                AgentAction("read_file", "public/vacation_policy.txt"),
                                MockGuard(), Policy(), FakeFileSandbox())
        self.assertEqual(result.policy.decision, Decision.ALLOW)
        self.assertIn("20 paid vacation days", result.content or "")

    def test_traversal_and_host_paths(self) -> None:
        paths = ("../secret.txt", "public/../../etc/passwd", "/etc/passwd",
                 "public/../private/secret.txt", "public//file", "public/./file",
                 "public\\..\\secret.txt", "public/file\x00", "C:/Windows/file")
        for path in paths:
            with self.subTest(path=path):
                with self.assertRaises(SandboxViolation):
                    FakeFileSandbox().read_file(path)
                self.assertEqual(Policy().evaluate(AgentAction("read_file", path),
                                 self.assessment(0)).decision, Decision.BLOCK)

    def test_private_policy_overrides_low_score(self) -> None:
        action = AgentAction("read_file", "private/secret.txt")
        self.assertEqual(Policy().evaluate(action, self.assessment(0)).decision, Decision.BLOCK)

    def test_private_tool_blocks_direct_call(self) -> None:
        with self.assertRaises(SandboxViolation):
            FakeFileSandbox().read_file("private/secret.txt")

    def test_private_experiment_explicit_opt_in(self) -> None:
        action = AgentAction("read_file", "private/secret.txt")
        self.assertEqual(Policy(block_private=False).evaluate(action, self.assessment(0)).decision,
                         Decision.ALLOW)
        self.assertIn("JEVGUARD_TEST_SECRET_7F92A1",
                      FakeFileSandbox(allow_private=True).read_file(action.path))

    def test_threshold_boundaries(self) -> None:
        action = AgentAction("read_file", "public/vacation_policy.txt")
        for score, expected in ((0, Decision.ALLOW), (0.3999, Decision.ALLOW),
                                (0.4, Decision.REVIEW), (0.7999, Decision.REVIEW),
                                (0.8, Decision.BLOCK), (1, Decision.BLOCK)):
            with self.subTest(score=score):
                self.assertEqual(Policy().evaluate(action, self.assessment(score)).decision, expected)

    def test_review_and_block_never_read(self) -> None:
        class FixedGuard:
            def __init__(self, score: float) -> None:
                self.score = score

            def assess(self, user_goal: str, action: AgentAction) -> GuardAssessment:
                return GuardAssessment(self.score, self.score, self.score, self.score,
                                       self.score, "fixed", "test")

        class NoReadSandbox(FakeFileSandbox):
            def read_file(self, path: str) -> str:
                raise AssertionError("Denied actions must not execute")

        for score in (0.4, 0.8):
            result = execute_action("goal", AgentAction("read_file", "public/x"),
                                    FixedGuard(score), Policy(), NoReadSandbox())
            self.assertIsNone(result.content)

    def test_invalid_scores(self) -> None:
        for score in (-0.1, 1.1, float("nan"), float("inf")):
            with self.subTest(score=score), self.assertRaises(ValueError):
                self.assessment(score)

    def test_each_score_independently_controls_policy(self) -> None:
        action = AgentAction("read_file", "public/vacation_policy.txt")
        names = ("prompt_injection", "goal_conflict", "tool_misuse",
                 "sensitive_data_access", "requires_human_review")
        for name in names:
            for score, expected in ((0.05, Decision.ALLOW), (0.4, Decision.REVIEW),
                                    (0.8, Decision.BLOCK)):
                scores = dict.fromkeys(names, 0.05)
                scores[name] = score
                with self.subTest(dimension=name, score=score):
                    assessment = GuardAssessment(**scores, reason="test", source="test")
                    self.assertEqual(Policy().evaluate(action, assessment).decision, expected)
            for invalid in (-0.1, 1.1, float("nan"), float("inf")):
                scores = dict.fromkeys(names, 0.05)
                scores[name] = invalid
                with self.subTest(dimension=name, invalid=invalid), self.assertRaises(ValueError):
                    GuardAssessment(**scores, reason="test", source="test")

    def test_attack_demo_blocks_and_withholds_secret(self) -> None:
        result = execute_action("Summarize the vacation policy.",
                                AgentAction("read_file", "private/secret.txt"),
                                MockGuard(), Policy(), FakeFileSandbox())
        self.assertEqual(result.policy.decision, Decision.BLOCK)
        self.assertIsNone(result.content)
        self.assertEqual(result.assessment.sensitive_data_access, 0.95)

    def test_invalid_thresholds(self) -> None:
        for review, block in ((0.8, 0.4), (0.4, 0.4), (-1, 0.8), (0.4, 2), (float("nan"), 0.8)):
            with self.subTest(review=review, block=block), self.assertRaises(ValueError):
                Policy(review, block)

    def test_unknown_tool_and_missing_file(self) -> None:
        self.assertEqual(Policy().evaluate(AgentAction("shell", "public/x"),
                         self.assessment(0)).decision, Decision.BLOCK)
        with self.assertRaises(FileNotFoundError):
            FakeFileSandbox().read_file("public/missing.txt")

    def test_guard_factory_and_key_redaction(self) -> None:
        self.assertIsInstance(create_guard(Settings()), MockGuard)
        settings = Settings(typesafe_api_key="test-only-key")
        self.assertIsInstance(create_guard(settings), TypeSafeGuard)
        self.assertNotIn("test-only-key", repr(settings))
        with self.assertRaises(NotImplementedError):
            create_guard(settings).assess("goal", AgentAction("read_file", "public/x"))

    def test_disk_fixtures_match_fake_files(self) -> None:
        root = Path(__file__).resolve().parents[1] / "sandbox"
        for path, expected in DEFAULT_FILES.items():
            self.assertEqual((root / path).read_text(), expected)


if __name__ == "__main__":
    unittest.main()
