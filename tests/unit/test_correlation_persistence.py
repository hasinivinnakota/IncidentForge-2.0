from datetime import datetime, timedelta, timezone

from sqlmodel import SQLModel

from backend.app.database import init_db
from backend.app.models.correlation import Correlation, CorrelationStatus
from backend.app.persistence.repositories import CorrelationRepository


def make_correlation(
    correlation_id: str,
    correlation_type: str = "auth_attack_sequence",
    entity_key: str = "user:admin",
    alert_ids: list[str] | None = None,
    event_ids: list[str] | None = None,
    status: CorrelationStatus = CorrelationStatus.OPEN,
    last_seen: datetime | None = None,
) -> Correlation:
    now = last_seen or datetime.now(timezone.utc)
    return Correlation(
        correlation_id=correlation_id,
        correlation_type=correlation_type,
        entity_key=entity_key,
        title=f"Test Correlation {correlation_id}",
        description="Test correlation description",
        severity=10,
        status=status,
        first_seen=now - timedelta(minutes=5),
        last_seen=now,
        alert_ids=alert_ids or ["alert-001", "alert-002"],
        event_ids=event_ids or ["evt-001", "evt-002"],
        alert_count=len(alert_ids or ["alert-001", "alert-002"]),
        mitre_techniques=["T1110"],
        evidence={"entity_key": entity_key},
    )


def test_correlation_table_initializes(test_engine) -> None:
    init_db(test_engine)
    assert "correlation" in SQLModel.metadata.tables


def test_correlation_persists_and_retrieves(db_session) -> None:
    repo = CorrelationRepository(db_session)
    corr = make_correlation("corr-1")
    result = repo.create_correlation(corr)
    assert result.created is True
    assert result.correlation.id is not None

    fetched = repo.get_correlation("corr-1")
    assert fetched is not None
    assert fetched.correlation_type == "auth_attack_sequence"
    assert fetched.entity_key == "user:admin"
    assert fetched.alert_count == 2


def test_duplicate_correlation_id_returns_existing(db_session) -> None:
    repo = CorrelationRepository(db_session)
    first = repo.create_correlation(make_correlation("corr-dup"))
    second = repo.create_correlation(make_correlation("corr-dup"))
    assert first.created is True
    assert second.created is False
    assert second.correlation.id == first.correlation.id
    assert len(repo.list_correlations()) == 1


def test_update_correlation_updates_fields(db_session) -> None:
    repo = CorrelationRepository(db_session)
    initial = make_correlation("corr-update", alert_ids=["a1", "a2"])
    repo.create_correlation(initial)

    updated = make_correlation(
        "corr-update",
        alert_ids=["a1", "a2", "a3"],
        event_ids=["e1", "e2", "e3"],
    )
    rec = repo.update_correlation(updated)
    assert rec is not None
    assert rec.alert_count == 3
    assert "a3" in rec.alert_ids_json

    fetched = repo.get_correlation("corr-update")
    assert fetched is not None
    assert fetched.alert_count == 3


def test_find_open_correlation_by_type_and_entity(db_session) -> None:
    repo = CorrelationRepository(db_session)
    now = datetime.now(timezone.utc)
    corr = make_correlation(
        "corr-open-1",
        correlation_type="process_network_sequence",
        entity_key="host:srv-01",
        last_seen=now,
    )
    repo.create_correlation(corr)

    # Found within recent window
    found = repo.find_open_correlation(
        "process_network_sequence", "host:srv-01", since=now - timedelta(minutes=10)
    )
    assert found is not None
    assert found.correlation_id == "corr-open-1"

    # Not found for different entity
    assert (
        repo.find_open_correlation(
            "process_network_sequence", "host:srv-02", since=now - timedelta(minutes=10)
        )
        is None
    )

    # Not found if window cutoff is after last_seen
    assert (
        repo.find_open_correlation(
            "process_network_sequence", "host:srv-01", since=now + timedelta(minutes=10)
        )
        is None
    )


def test_list_correlations_filters(db_session) -> None:
    repo = CorrelationRepository(db_session)
    repo.create_correlation(
        make_correlation(
            "c1",
            status=CorrelationStatus.OPEN,
            alert_ids=["a100", "a101"],
            event_ids=["e100"],
        )
    )
    repo.create_correlation(
        make_correlation(
            "c2",
            status=CorrelationStatus.CLOSED,
            alert_ids=["a200"],
            event_ids=["e200"],
        )
    )

    # Status filter
    open_corrs = repo.list_correlations(status="open")
    assert len(open_corrs) == 1
    assert open_corrs[0].correlation_id == "c1"

    closed_corrs = repo.list_correlations(status="closed")
    assert len(closed_corrs) == 1
    assert closed_corrs[0].correlation_id == "c2"

    # Alert ID filter
    alert_corrs = repo.list_correlations(alert_id="a100")
    assert len(alert_corrs) == 1
    assert alert_corrs[0].correlation_id == "c1"

    # Event ID filter
    event_corrs = repo.list_correlations(event_id="e200")
    assert len(event_corrs) == 1
    assert event_corrs[0].correlation_id == "c2"
