from backend.app.services.normalization import NormalizationService


def test_normalization_converts_named_severity_and_preserves_extra_data() -> None:
    event = NormalizationService().normalize(
        {
            "event_id": "evt-1",
            "timestamp": "2026-01-01T00:00:00Z",
            "source": "test-source",
            "event_type": "login",
            "severity": "high",
            "message": "login observed",
            "vendor_field": "preserve-me",
        }
    )
    assert event.severity == 10
    assert event.metadata["vendor_field"] == "preserve-me"