from backend.app.adapters import FixtureAdapter, TelemetryAdapter


def test_fixture_adapter_is_deterministic_and_source_agnostic() -> None:
    first = FixtureAdapter().get_events()
    second = FixtureAdapter().get_events()
    assert first == second
    assert isinstance(FixtureAdapter(), TelemetryAdapter)