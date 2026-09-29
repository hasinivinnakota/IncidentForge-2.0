from datetime import datetime, timezone
import pytest
from pydantic import ValidationError

from backend.app.models.events import NormalizedEvent
from backend.app.models.rules import DetectionMatch, DetectionRule
from backend.app.rules import get_default_rules
from backend.app.services.detection import DetectionEngine


class DummyMatchRule(DetectionRule):
    @property
    def rule_id(self) -> str:
        return "test-001"

    @property
    def rule_name(self) -> str:
        return "Test Rule"

    @property
    def description(self) -> str:
        return "Always matches"

    @property
    def severity(self) -> int:
        return 5

    @property
    def mitre_techniques(self) -> list[str]:
        return ["T1000"]

    def evaluate(self, event: NormalizedEvent) -> DetectionMatch | None:
        return DetectionMatch(
            rule_id=self.rule_id,
            rule_name=self.rule_name,
            event_id=event.event_id,
            severity=self.severity,
            description=self.description,
            mitre_techniques=self.mitre_techniques,
            evidence={"field": "test"},
        )


class DummyNeverRule(DetectionRule):
    @property
    def rule_id(self) -> str:
        return "test-002"

    @property
    def rule_name(self) -> str:
        return "Never Matches"

    @property
    def description(self) -> str:
        return "Never matches"

    @property
    def severity(self) -> int:
        return 1

    @property
    def mitre_techniques(self) -> list[str]:
        return []

    def evaluate(self, event: NormalizedEvent) -> DetectionMatch | None:
        return None


def make_event(event_id: str = "evt-1", severity: int = 3) -> NormalizedEvent:
    return NormalizedEvent(
        event_id=event_id,
        timestamp=datetime.now(timezone.utc),
        source="test",
        event_type="test_event",
        severity=severity,
        message="Test event message",
    )


def test_rule_matches_when_condition_met() -> None:
    rule = DummyMatchRule()
    event = make_event()
    match = rule.evaluate(event)
    assert match is not None
    assert match.rule_id == "test-001"
    assert match.event_id == "evt-1"
    assert match.severity == 5


def test_rule_returns_none_when_no_match() -> None:
    rule = DummyNeverRule()
    event = make_event()
    assert rule.evaluate(event) is None


def test_engine_returns_multiple_matches() -> None:
    engine = DetectionEngine([DummyMatchRule(), DummyMatchRule()])
    event = make_event()
    matches = engine.evaluate(event)
    assert len(matches) == 2


def test_engine_returns_empty_for_benign_event() -> None:
    engine = DetectionEngine([DummyNeverRule()])
    event = make_event()
    matches = engine.evaluate(event)
    assert matches == []


def test_engine_with_no_rules_returns_empty() -> None:
    engine = DetectionEngine([])
    event = make_event()
    assert engine.evaluate(event) == []


def test_detection_match_validates_fields() -> None:
    match = DetectionMatch(
        rule_id="r1",
        rule_name="Rule 1",
        event_id="e1",
        severity=8,
        description="desc",
        mitre_techniques=["T1059"],
        evidence={"key": "val"},
    )
    assert match.rule_id == "r1"
    assert match.severity == 8


def test_detection_match_rejects_invalid_severity() -> None:
    with pytest.raises(ValidationError):
        DetectionMatch(
            rule_id="r1",
            rule_name="Rule 1",
            event_id="e1",
            severity=16,
            description="desc",
        )
