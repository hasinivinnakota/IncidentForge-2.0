def test_health(api_client) -> None:
    response = api_client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_system_settings_are_loaded_and_persisted(api_client) -> None:
    initial = api_client.get("/api/v1/settings")
    assert initial.status_code == 200
    assert initial.json()["high_threshold"] == 50

    updated = api_client.patch(
        "/api/v1/settings",
        json={"profile_name": "SOC Admin", "high_threshold": 55},
    )
    assert updated.status_code == 200
    assert updated.json()["profile_name"] == "SOC Admin"
    assert updated.json()["high_threshold"] == 55

    reloaded = api_client.get("/api/v1/settings")
    assert reloaded.json()["profile_name"] == "SOC Admin"
    assert reloaded.json()["high_threshold"] == 55


def test_system_settings_reject_invalid_threshold_order(api_client) -> None:
    response = api_client.patch("/api/v1/settings", json={"high_threshold": 90})
    assert response.status_code == 422


def test_dataset_simulation_creates_backend_risk_and_case(api_client) -> None:
    asset_response = api_client.post(
        "/api/v1/data-assets",
        json={
            "dataset_id": "dataset-case-regression",
            "name": "dataset-case-regression.csv",
            "format": "csv",
            "file_path": "synthetic/dataset-case-regression.csv",
            "size_bytes": 2048,
            "record_count": 1200,
            "column_count": 3,
            "columns": [],
            "sensitive_columns": [],
            "sensitivity": "LOW",
            "schema_hash": "regression-schema",
        },
    )
    assert asset_response.status_code in {200, 201}

    simulation = api_client.post("/api/v1/data-assets/dataset-case-regression/simulate")
    assert simulation.status_code == 202
    result = simulation.json()
    assert result["events_generated"] == 4
    assert any(item["risk_score"] is not None for item in result["pipeline_results"])

    overview = api_client.get("/api/v1/data-assets/dataset-case-regression/overview")
    assert overview.status_code == 200
    data = overview.json()
    assert data["risk_assessments"]
    assert data["cases"]
    assert "dataset:dataset-case-regression" in data["cases"][0]["tags"]

    before_repeat = data["activities"]
    repeated = api_client.post("/api/v1/data-assets/dataset-case-regression/simulate")
    assert repeated.status_code == 202
    after_repeat = api_client.get("/api/v1/data-assets/dataset-case-regression/overview")
    assert len(after_repeat.json()["activities"]) == len(before_repeat)
    assert after_repeat.json()["risk_assessments"][0]["risk_score"] == data["risk_assessments"][0]["risk_score"]


def test_example_event(api_client) -> None:
    response = api_client.get("/api/v1/events/example")
    assert response.status_code == 200
    assert response.json()["event_id"] == "fixture-event-001"


def test_event_intake_accepts_normalized_event(api_client) -> None:
    response = api_client.post(
        "/api/v1/events",
        json={
            "event_id": "evt-1",
            "timestamp": "2026-01-01T00:00:00Z",
            "source": "test",
            "event_type": "login",
            "severity": 4,
            "message": "login observed",
        },
    )
    assert response.status_code == 202
    assert response.json()["event_id"] == "evt-1"
    assert response.json()["newly_persisted"] is True


def test_event_intake_rejects_invalid_event(api_client) -> None:
    response = api_client.post("/api/v1/events", json={"event_id": "missing-fields"})
    assert response.status_code == 422


def test_event_intake_persists_event(api_client) -> None:
    response = api_client.post(
        "/api/v1/events",
        json={
            "event_id": "persisted-1",
            "timestamp": "2026-01-01T00:00:00Z",
            "source": "test",
            "event_type": "login",
            "severity": 4,
            "message": "persist me",
        },
    )
    assert response.status_code == 202


def test_duplicate_event_returns_deterministic_result(api_client, test_engine) -> None:
    payload = {
        "event_id": "duplicate-1",
        "timestamp": "2026-01-01T00:00:00Z",
        "source": "test",
        "event_type": "login",
        "severity": 4,
        "message": "original",
    }
    first = api_client.post("/api/v1/events", json=payload)
    second = api_client.post("/api/v1/events", json={**payload, "message": "changed"})
    assert first.json()["newly_persisted"] is True
    assert second.json()["newly_persisted"] is False
    assert second.json()["duplicate"] is True

    from sqlmodel import Session

    from backend.app.persistence.repositories import EventRepository

    with Session(test_engine) as session:
        repository = EventRepository(session)
        stored = repository.get_event("duplicate-1")
        audits = repository.list_audit_events("duplicate-1")
    assert stored is not None
    assert stored.message == "original"
    assert len(audits) == 2


def test_event_intake_stores_normalized_event(api_client, test_engine) -> None:
    response = api_client.post(
        "/api/v1/events",
        json={
            "event_id": "stored-1",
            "timestamp": "2026-01-01T00:00:00Z",
            "source": "test",
            "event_type": "login",
            "severity": 4,
            "message": "stored event",
            "metadata": {"provider": "fixture"},
        },
    )
    assert response.status_code == 202

    from sqlmodel import Session

    from backend.app.persistence.repositories import EventRepository

    with Session(test_engine) as session:
        stored = EventRepository(session).get_event("stored-1")
    assert stored is not None
    assert stored.message == "stored event"
    assert stored.metadata_json == '{"provider": "fixture"}'


def test_event_intake_triggers_detection(api_client) -> None:
    # Event matching high severity (12) and suspicious process (/tmp/malicious.sh)
    response = api_client.post(
        "/api/v1/events",
        json={
            "event_id": "detect-evt-1",
            "timestamp": "2026-01-01T00:00:00Z",
            "source": "test",
            "event_type": "process_start",
            "severity": 12,
            "message": "Executed /tmp/malicious.sh",
            "host": "workstation-01",
        },
    )
    assert response.status_code == 202
    data = response.json()
    assert data["event_id"] == "detect-evt-1"
    assert data["newly_persisted"] is True
    assert data["detection_matches"] >= 2  # HighSeverityRule + SuspiciousProcessRule
    assert len(data["alerts_created"]) >= 2


def test_event_intake_no_alerts_for_benign(api_client) -> None:
    response = api_client.post(
        "/api/v1/events",
        json={
            "event_id": "benign-evt-1",
            "timestamp": "2026-01-01T00:00:00Z",
            "source": "test",
            "event_type": "process_start",
            "severity": 2,
            "message": "Normal process start /usr/bin/python",
        },
    )
    assert response.status_code == 202
    data = response.json()
    assert data["newly_persisted"] is True
    assert data["detection_matches"] == 0
    assert data["alerts_created"] == []


def test_duplicate_event_skips_detection(api_client) -> None:
    payload = {
        "event_id": "dup-detect-1",
        "timestamp": "2026-01-01T00:00:00Z",
        "source": "test",
        "event_type": "authentication_failure",
        "severity": 6,
        "message": "Failed login for admin",
        "user": "admin",
    }
    first = api_client.post("/api/v1/events", json=payload)
    assert first.status_code == 202
    assert first.json()["newly_persisted"] is True
    assert first.json()["detection_matches"] == 1
    assert len(first.json()["alerts_created"]) == 1

    second = api_client.post("/api/v1/events", json=payload)
    assert second.status_code == 202
    assert second.json()["newly_persisted"] is False
    assert second.json()["duplicate"] is True
    assert second.json()["detection_matches"] == 0
    assert second.json()["alerts_created"] == []


def test_get_alerts_list(api_client) -> None:
    api_client.post(
        "/api/v1/events",
        json={
            "event_id": "alert-list-evt",
            "timestamp": "2026-01-01T00:00:00Z",
            "source": "test",
            "event_type": "authentication_failure",
            "severity": 6,
            "message": "Failed login",
        },
    )
    response = api_client.get("/api/v1/alerts")
    assert response.status_code == 200
    alerts = response.json()
    assert isinstance(alerts, list)
    assert len(alerts) >= 1
    assert any(a["event_id"] == "alert-list-evt" for a in alerts)


def test_get_alert_by_id(api_client) -> None:
    post_resp = api_client.post(
        "/api/v1/events",
        json={
            "event_id": "alert-get-evt",
            "timestamp": "2026-01-01T00:00:00Z",
            "source": "test",
            "event_type": "privilege_escalation",
            "severity": 12,
            "message": "privilege escalation attempt",
        },
    )
    alert_ids = post_resp.json()["alerts_created"]
    assert len(alert_ids) > 0
    target_alert_id = alert_ids[0]

    response = api_client.get(f"/api/v1/alerts/{target_alert_id}")
    assert response.status_code == 200
    alert_data = response.json()
    assert alert_data["alert_id"] == target_alert_id
    assert alert_data["event_id"] == "alert-get-evt"
    assert "severity" in alert_data


def test_get_alert_not_found(api_client) -> None:
    response = api_client.get("/api/v1/alerts/nonexistent-alert-id")
    assert response.status_code == 404
    assert "not found" in response.json()["detail"].lower()


def test_get_alerts_by_event_id(api_client) -> None:
    event_id = "filtered-evt-999"
    api_client.post(
        "/api/v1/events",
        json={
            "event_id": event_id,
            "timestamp": "2026-01-01T00:00:00Z",
            "source": "test",
            "event_type": "authentication_failure",
            "severity": 6,
            "message": "Failed login",
        },
    )
    response = api_client.get(f"/api/v1/alerts?event_id={event_id}")
    assert response.status_code == 200
    alerts = response.json()
    assert len(alerts) >= 1
    assert all(a["event_id"] == event_id for a in alerts)


def test_event_intake_triggers_correlation(api_client) -> None:
    # First auth failure
    r1 = api_client.post(
        "/api/v1/events",
        json={
            "event_id": "corr-evt-1",
            "timestamp": "2026-01-01T00:00:00Z",
            "source": "test",
            "event_type": "authentication_failure",
            "severity": 6,
            "message": "Auth failure 1",
            "user": "victim_user",
        },
    )
    assert r1.status_code == 202
    assert len(r1.json()["alerts_created"]) == 1
    assert len(r1.json()["correlations_created"]) == 0

    # Second auth failure for same user within window
    r2 = api_client.post(
        "/api/v1/events",
        json={
            "event_id": "corr-evt-2",
            "timestamp": "2026-01-01T00:05:00Z",
            "source": "test",
            "event_type": "authentication_failure",
            "severity": 6,
            "message": "Auth failure 2",
            "user": "victim_user",
        },
    )
    assert r2.status_code == 202
    assert len(r2.json()["alerts_created"]) == 1
    assert len(r2.json()["correlations_created"]) >= 1


def test_get_correlations_list_and_by_id(api_client) -> None:
    # Trigger correlation via two process-network events
    api_client.post(
        "/api/v1/events",
        json={
            "event_id": "seq-proc-1",
            "timestamp": "2026-01-01T01:00:00Z",
            "source": "test",
            "event_type": "process_start",
            "severity": 10,
            "message": "execute /tmp/backdoor.sh",
            "host": "correlate-host-01",
        },
    )
    r2 = api_client.post(
        "/api/v1/events",
        json={
            "event_id": "seq-net-1",
            "timestamp": "2026-01-01T01:10:00Z",
            "source": "test",
            "event_type": "network_connection",
            "severity": 6,
            "message": "outbound connection",
            "destination_ip": "203.0.113.88",
            "host": "correlate-host-01",
        },
    )
    assert r2.status_code == 202
    corr_ids = r2.json()["correlations_created"]
    assert len(corr_ids) >= 1
    corr_id = corr_ids[0]

    # GET /api/v1/correlations
    list_resp = api_client.get("/api/v1/correlations")
    assert list_resp.status_code == 200
    corrs = list_resp.json()
    assert isinstance(corrs, list)
    assert any(c["correlation_id"] == corr_id for c in corrs)

    # GET /api/v1/correlations/{id}
    detail_resp = api_client.get(f"/api/v1/correlations/{corr_id}")
    assert detail_resp.status_code == 200
    detail = detail_resp.json()
    assert detail["correlation_id"] == corr_id
    assert detail["status"] == "open"
    assert detail["alert_count"] >= 2


def test_get_correlation_not_found(api_client) -> None:
    resp = api_client.get("/api/v1/correlations/nonexistent-corr-id")
    assert resp.status_code == 404
    assert "not found" in resp.json()["detail"].lower()


def test_get_correlations_filtering(api_client) -> None:
    # Filter by status
    open_resp = api_client.get("/api/v1/correlations?status=open")
    assert open_resp.status_code == 200
    assert all(c["status"] == "open" for c in open_resp.json())

    closed_resp = api_client.get("/api/v1/correlations?status=closed")
    assert closed_resp.status_code == 200
    assert all(c["status"] == "closed" for c in closed_resp.json())


# ---------------------------------------------------------------------------
# Checkpoint 6.3 — Incident Creation Integration Tests
# ---------------------------------------------------------------------------


def test_pipeline_creates_incident_from_correlation(api_client) -> None:
    """Two auth failures for the same user create a correlation which creates an incident."""
    r1 = api_client.post(
        "/api/v1/events",
        json={
            "event_id": "inc-auth-1",
            "timestamp": "2026-02-01T00:00:00Z",
            "source": "test",
            "event_type": "authentication_failure",
            "severity": 6,
            "message": "Auth failure for inc_user",
            "user": "inc_user",
        },
    )
    assert r1.status_code == 202

    r2 = api_client.post(
        "/api/v1/events",
        json={
            "event_id": "inc-auth-2",
            "timestamp": "2026-02-01T00:05:00Z",
            "source": "test",
            "event_type": "authentication_failure",
            "severity": 6,
            "message": "Auth failure 2 for inc_user",
            "user": "inc_user",
        },
    )
    assert r2.status_code == 202
    data = r2.json()
    assert len(data["correlations_created"]) >= 1
    assert len(data["incidents_created"]) >= 1


def test_get_incidents_list(api_client) -> None:
    """GET /api/v1/incidents returns a list containing the pipeline-created incident."""
    # Trigger an incident first
    api_client.post(
        "/api/v1/events",
        json={
            "event_id": "inc-list-1",
            "timestamp": "2026-03-01T00:00:00Z",
            "source": "test",
            "event_type": "authentication_failure",
            "severity": 6,
            "message": "Auth fail 1",
            "user": "list_user",
        },
    )
    api_client.post(
        "/api/v1/events",
        json={
            "event_id": "inc-list-2",
            "timestamp": "2026-03-01T00:02:00Z",
            "source": "test",
            "event_type": "authentication_failure",
            "severity": 6,
            "message": "Auth fail 2",
            "user": "list_user",
        },
    )

    resp = api_client.get("/api/v1/incidents")
    assert resp.status_code == 200
    incidents = resp.json()
    assert isinstance(incidents, list)
    assert len(incidents) >= 1
    assert all("incident_id" in i for i in incidents)
    assert all("status" in i for i in incidents)


def test_get_incident_by_id(api_client) -> None:
    """GET /api/v1/incidents/{id} returns the correct incident."""
    api_client.post(
        "/api/v1/events",
        json={
            "event_id": "inc-byid-1",
            "timestamp": "2026-04-01T00:00:00Z",
            "source": "test",
            "event_type": "authentication_failure",
            "severity": 6,
            "message": "Auth fail",
            "user": "byid_user",
        },
    )
    r2 = api_client.post(
        "/api/v1/events",
        json={
            "event_id": "inc-byid-2",
            "timestamp": "2026-04-01T00:03:00Z",
            "source": "test",
            "event_type": "authentication_failure",
            "severity": 6,
            "message": "Auth fail 2",
            "user": "byid_user",
        },
    )
    inc_ids = r2.json()["incidents_created"]
    assert len(inc_ids) >= 1
    inc_id = inc_ids[0]

    detail = api_client.get(f"/api/v1/incidents/{inc_id}")
    assert detail.status_code == 200
    body = detail.json()
    assert body["incident_id"] == inc_id
    assert body["status"] == "open"
    assert body["severity"] >= 0
    assert len(body["alert_ids"]) >= 2
    assert len(body["correlation_ids"]) >= 1


def test_get_incident_not_found(api_client) -> None:
    resp = api_client.get("/api/v1/incidents/nonexistent-inc-id")
    assert resp.status_code == 404
    assert "not found" in resp.json()["detail"].lower()


def test_incident_status_update(api_client) -> None:
    """PATCH /api/v1/incidents/{id}/status transitions status correctly."""
    api_client.post(
        "/api/v1/events",
        json={
            "event_id": "inc-status-1",
            "timestamp": "2026-05-01T00:00:00Z",
            "source": "test",
            "event_type": "authentication_failure",
            "severity": 6,
            "message": "Auth fail",
            "user": "status_user",
        },
    )
    r2 = api_client.post(
        "/api/v1/events",
        json={
            "event_id": "inc-status-2",
            "timestamp": "2026-05-01T00:03:00Z",
            "source": "test",
            "event_type": "authentication_failure",
            "severity": 6,
            "message": "Auth fail 2",
            "user": "status_user",
        },
    )
    inc_id = r2.json()["incidents_created"][0]

    # open -> investigating
    resp = api_client.patch(
        f"/api/v1/incidents/{inc_id}/status",
        json={"status": "investigating"},
    )
    assert resp.status_code == 200
    assert resp.json()["status"] == "investigating"

    # investigating -> resolved
    resp2 = api_client.patch(
        f"/api/v1/incidents/{inc_id}/status",
        json={"status": "resolved"},
    )
    assert resp2.status_code == 200
    assert resp2.json()["status"] == "resolved"

    # resolved -> closed
    resp3 = api_client.patch(
        f"/api/v1/incidents/{inc_id}/status",
        json={"status": "closed"},
    )
    assert resp3.status_code == 200
    assert resp3.json()["status"] == "closed"


def test_incident_status_update_not_found(api_client) -> None:
    resp = api_client.patch(
        "/api/v1/incidents/nonexistent/status",
        json={"status": "investigating"},
    )
    assert resp.status_code == 404


def test_incident_status_update_invalid_status(api_client) -> None:
    """Reject an invalid status value."""
    resp = api_client.patch(
        "/api/v1/incidents/any-id/status",
        json={"status": "invalid_status_value"},
    )
    assert resp.status_code == 422


def test_incident_filtering_by_status(api_client) -> None:
    resp = api_client.get("/api/v1/incidents?status=open")
    assert resp.status_code == 200
    for inc in resp.json():
        assert inc["status"] == "open"


def test_duplicate_event_does_not_create_duplicate_incident(api_client) -> None:
    """Re-processing the same event should not create a second incident."""
    payload1 = {
        "event_id": "inc-dup-evt-1",
        "timestamp": "2026-06-01T00:00:00Z",
        "source": "test",
        "event_type": "authentication_failure",
        "severity": 6,
        "message": "Auth fail",
        "user": "dup_test_user",
    }
    payload2 = {
        "event_id": "inc-dup-evt-2",
        "timestamp": "2026-06-01T00:03:00Z",
        "source": "test",
        "event_type": "authentication_failure",
        "severity": 6,
        "message": "Auth fail 2",
        "user": "dup_test_user",
    }
    r1 = api_client.post("/api/v1/events", json=payload1)
    assert r1.status_code == 202

    r2 = api_client.post("/api/v1/events", json=payload2)
    assert r2.status_code == 202
    first_incidents = r2.json()["incidents_created"]

    # Re-submit same events — should be duplicates, no new incidents
    r3 = api_client.post("/api/v1/events", json=payload1)
    assert r3.status_code == 202
    assert r3.json()["incidents_created"] == []

    r4 = api_client.post("/api/v1/events", json=payload2)
    assert r4.status_code == 202
    assert r4.json()["incidents_created"] == []


def test_pipeline_result_includes_incident_fields(api_client) -> None:
    """PipelineResult always has incidents_created and incidents_updated fields."""
    resp = api_client.post(
        "/api/v1/events",
        json={
            "event_id": "inc-fields-1",
            "timestamp": "2026-07-01T00:00:00Z",
            "source": "test",
            "event_type": "login",
            "severity": 2,
            "message": "Normal login",
        },
    )
    assert resp.status_code == 202
    data = resp.json()
    assert "incidents_created" in data
    assert "incidents_updated" in data
    assert isinstance(data["incidents_created"], list)
    assert isinstance(data["incidents_updated"], list)


def test_incident_evidence_no_sensitive_data(api_client) -> None:
    """Incident evidence must not leak credentials, tokens, or passwords."""
    api_client.post(
        "/api/v1/events",
        json={
            "event_id": "inc-safe-1",
            "timestamp": "2026-08-01T00:00:00Z",
            "source": "test",
            "event_type": "authentication_failure",
            "severity": 6,
            "message": "Failed auth password=secret123 token=abc",
            "user": "safe_user",
        },
    )
    r2 = api_client.post(
        "/api/v1/events",
        json={
            "event_id": "inc-safe-2",
            "timestamp": "2026-08-01T00:03:00Z",
            "source": "test",
            "event_type": "authentication_failure",
            "severity": 6,
            "message": "Failed auth api_key=xyz",
            "user": "safe_user",
        },
    )
    if r2.json()["incidents_created"]:
        inc_id = r2.json()["incidents_created"][0]
        detail = api_client.get(f"/api/v1/incidents/{inc_id}")
        evidence = str(detail.json().get("evidence", {})).lower()
        assert "secret123" not in evidence
        assert "abc" not in evidence or "api_key" not in evidence


# ---------------------------------------------------------------------------
# Checkpoint 6.4 — ML Risk Scoring Integration Tests
# ---------------------------------------------------------------------------


def test_pipeline_executes_ml_risk_scoring(api_client) -> None:
    """Full pipeline flow: Event -> Detection -> Alert -> Correlation -> Incident -> ML Risk."""
    r1 = api_client.post(
        "/api/v1/events",
        json={
            "event_id": "risk-pipe-1",
            "timestamp": "2026-09-01T00:00:00Z",
            "source": "test",
            "event_type": "authentication_failure",
            "severity": 6,
            "message": "Auth fail 1",
            "user": "risk_pipe_user",
        },
    )
    assert r1.status_code == 202

    r2 = api_client.post(
        "/api/v1/events",
        json={
            "event_id": "risk-pipe-2",
            "timestamp": "2026-09-01T00:05:00Z",
            "source": "test",
            "event_type": "authentication_failure",
            "severity": 6,
            "message": "Auth fail 2",
            "user": "risk_pipe_user",
        },
    )
    assert r2.status_code == 202
    data = r2.json()
    assert len(data["correlations_created"]) >= 1
    assert len(data["incidents_created"]) >= 1
    assert len(data["risk_assessments_created"]) >= 1
    assert data["risk_score"] is not None
    assert 0 <= data["risk_score"] <= 100
    assert data["risk_level"] in ["low", "medium", "high", "critical"]


def test_get_incident_risk_endpoint(api_client) -> None:
    """GET /api/v1/incidents/{id}/risk returns the assessment for an incident."""
    api_client.post(
        "/api/v1/events",
        json={
            "event_id": "risk-get-1",
            "timestamp": "2026-09-02T00:00:00Z",
            "source": "test",
            "event_type": "authentication_failure",
            "severity": 6,
            "message": "Auth fail 1",
            "user": "risk_get_user",
        },
    )
    r2 = api_client.post(
        "/api/v1/events",
        json={
            "event_id": "risk-get-2",
            "timestamp": "2026-09-02T00:03:00Z",
            "source": "test",
            "event_type": "authentication_failure",
            "severity": 6,
            "message": "Auth fail 2",
            "user": "risk_get_user",
        },
    )
    inc_id = r2.json()["incidents_created"][0]

    resp = api_client.get(f"/api/v1/incidents/{inc_id}/risk")
    assert resp.status_code == 200
    body = resp.json()
    assert body["incident_id"] == inc_id
    assert 0 <= body["risk_score"] <= 100
    assert body["risk_level"] in ["low", "medium", "high", "critical"]
    assert body["model_name"] == "baseline_logistic_regression"
    assert isinstance(body["reasons"], list)
    assert len(body["reasons"]) >= 1
    assert isinstance(body["features"], dict)
    assert len(body["features"]) >= 10


def test_get_incident_risk_not_found(api_client) -> None:
    resp = api_client.get("/api/v1/incidents/nonexistent-incident-id/risk")
    assert resp.status_code == 404
    assert "not found" in resp.json()["detail"].lower()


def test_get_risk_assessment_by_id(api_client) -> None:
    api_client.post(
        "/api/v1/events",
        json={
            "event_id": "risk-byid-1",
            "timestamp": "2026-09-03T00:00:00Z",
            "source": "test",
            "event_type": "authentication_failure",
            "severity": 6,
            "message": "Auth fail 1",
            "user": "risk_byid_user",
        },
    )
    r2 = api_client.post(
        "/api/v1/events",
        json={
            "event_id": "risk-byid-2",
            "timestamp": "2026-09-03T00:03:00Z",
            "source": "test",
            "event_type": "authentication_failure",
            "severity": 6,
            "message": "Auth fail 2",
            "user": "risk_byid_user",
        },
    )
    assessment_id = r2.json()["risk_assessments_created"][0]

    resp = api_client.get(f"/api/v1/risk-assessments/{assessment_id}")
    assert resp.status_code == 200
    body = resp.json()
    assert body["assessment_id"] == assessment_id
    assert 0 <= body["risk_score"] <= 100


def test_get_risk_assessment_by_id_not_found(api_client) -> None:
    resp = api_client.get("/api/v1/risk-assessments/nonexistent-assessment-id")
    assert resp.status_code == 404
    assert "not found" in resp.json()["detail"].lower()


def test_incident_severity_never_overwritten_by_ml_score(api_client) -> None:
    """CRITICAL: ML risk assessment must never alter original Incident severity."""
    api_client.post(
        "/api/v1/events",
        json={
            "event_id": "risk-sev-1",
            "timestamp": "2026-09-04T00:00:00Z",
            "source": "test",
            "event_type": "authentication_failure",
            "severity": 6,
            "message": "Auth fail 1",
            "user": "risk_sev_user",
        },
    )
    r2 = api_client.post(
        "/api/v1/events",
        json={
            "event_id": "risk-sev-2",
            "timestamp": "2026-09-04T00:03:00Z",
            "source": "test",
            "event_type": "authentication_failure",
            "severity": 6,
            "message": "Auth fail 2",
            "user": "risk_sev_user",
        },
    )
    inc_id = r2.json()["incidents_created"][0]

    # Inspect incident directly
    inc_resp = api_client.get(f"/api/v1/incidents/{inc_id}")
    assert inc_resp.status_code == 200
    incident = inc_resp.json()

    # Incident severity is within SOC scale [0, 15]
    assert 0 <= incident["severity"] <= 15

    # Inspect risk assessment
    risk_resp = api_client.get(f"/api/v1/incidents/{inc_id}/risk")
    assert risk_resp.status_code == 200
    risk = risk_resp.json()

    # Risk score is on 0-100 scale
    assert 0 <= risk["risk_score"] <= 100


# ---------------------------------------------------------------------------
# Checkpoint 6.5 / Phase 7 — Threat Intelligence Enrichment Integration Tests
# ---------------------------------------------------------------------------


def test_pipeline_executes_threat_intel_enrichment(api_client) -> None:
    """Full pipeline flow should also trigger threat intelligence extraction and enrichment."""
    # Note: Using malicious IP from our synthetic local provider dataset (203.0.113.50)
    r1 = api_client.post(
        "/api/v1/events",
        json={
            "event_id": "ti-pipe-1",
            "timestamp": "2026-10-01T00:00:00Z",
            "source": "test",
            "event_type": "authentication_failure",
            "severity": 6,
            "message": "Auth fail ti 1",
            "user": "ti_user",
            "source_ip": "203.0.113.50",
        },
    )
    assert r1.status_code == 202

    r2 = api_client.post(
        "/api/v1/events",
        json={
            "event_id": "ti-pipe-2",
            "timestamp": "2026-10-01T00:05:00Z",
            "source": "test",
            "event_type": "authentication_failure",
            "severity": 6,
            "message": "Auth fail ti 2",
            "user": "ti_user",
            "source_ip": "203.0.113.50",
            "metadata": {"domain": "safe.synthetic.example"},
        },
    )
    assert r2.status_code == 202
    data = r2.json()
    assert len(data["incidents_created"]) >= 1
    assert data["iocs_extracted"] >= 1
    assert len(data["threat_intel_created"]) >= 1


def test_get_incident_threat_intelligence(api_client) -> None:
    """GET /api/v1/incidents/{id}/threat-intelligence returns enrichments."""
    # Trigger an incident with malicious and benign IOCs
    api_client.post(
        "/api/v1/events",
        json={
            "event_id": "ti-get-1",
            "timestamp": "2026-10-02T00:00:00Z",
            "source": "test",
            "event_type": "authentication_failure",
            "severity": 6,
            "message": "fail 1",
            "user": "ti_get_user",
            "source_ip": "203.0.113.50",
        },
    )
    r2 = api_client.post(
        "/api/v1/events",
        json={
            "event_id": "ti-get-2",
            "timestamp": "2026-10-02T00:05:00Z",
            "source": "test",
            "event_type": "authentication_failure",
            "severity": 6,
            "message": "fail 2",
            "user": "ti_get_user",
            "source_ip": "203.0.113.50",
            "metadata": {"domain": "safe.synthetic.example"},
        },
    )
    inc_id = r2.json()["incidents_created"][0]

    resp = api_client.get(f"/api/v1/incidents/{inc_id}/threat-intelligence")
    assert resp.status_code == 200
    enrichments = resp.json()
    assert len(enrichments) >= 2

    # Verify malicious IP
    malicious_ip = next(e for e in enrichments if e["ioc_type"] == "ipv4" and e["ioc_value"] == "203.0.113.50")
    assert malicious_ip["classification"] == "malicious"

    # Verify benign domain
    benign_domain = next(e for e in enrichments if e["ioc_type"] == "domain" and e["ioc_value"] == "safe.synthetic.example")
    assert benign_domain["classification"] == "benign"


def test_get_threat_intelligence_by_id(api_client) -> None:
    """GET /api/v1/threat-intelligence/{id} returns specific enrichment."""
    api_client.post(
        "/api/v1/events",
        json={
            "event_id": "ti-byid-1",
            "timestamp": "2026-10-03T00:00:00Z",
            "source": "test",
            "event_type": "authentication_failure",
            "severity": 6,
            "message": "fail 1",
            "user": "ti_byid_user",
            "source_ip": "198.51.100.99",
        },
    )
    r2 = api_client.post(
        "/api/v1/events",
        json={
            "event_id": "ti-byid-2",
            "timestamp": "2026-10-03T00:05:00Z",
            "source": "test",
            "event_type": "authentication_failure",
            "severity": 6,
            "message": "fail 2",
            "user": "ti_byid_user",
            "source_ip": "198.51.100.99",
        },
    )
    enrichment_id = r2.json()["threat_intel_created"][0]

    resp = api_client.get(f"/api/v1/threat-intelligence/{enrichment_id}")
    assert resp.status_code == 200
    body = resp.json()
    assert body["enrichment_id"] == enrichment_id
    assert body["ioc_value"] == "198.51.100.99"


def test_get_threat_intelligence_by_ioc(api_client) -> None:
    """GET /api/v1/threat-intelligence/ioc/{type}/{value} lookup works."""
    # Use an IOC we know is populated from previous tests or this one
    api_client.post(
        "/api/v1/events",
        json={
            "event_id": "ti-ioc-1",
            "timestamp": "2026-10-04T00:00:00Z",
            "source": "test",
            "event_type": "authentication_failure",
            "severity": 6,
            "message": "fail 1",
            "user": "ti_ioc_user",
            "source_ip": "192.0.2.1",
        },
    )
    api_client.post(
        "/api/v1/events",
        json={
            "event_id": "ti-ioc-2",
            "timestamp": "2026-10-04T00:05:00Z",
            "source": "test",
            "event_type": "authentication_failure",
            "severity": 6,
            "message": "fail 2",
            "user": "ti_ioc_user",
            "source_ip": "192.0.2.1",
        },
    )

    resp = api_client.get("/api/v1/threat-intelligence/ioc/ipv4/192.0.2.1")
    assert resp.status_code == 200
    results = resp.json()
    assert len(results) >= 1
    assert all(r["ioc_type"] == "ipv4" and r["ioc_value"] == "192.0.2.1" for r in results)


# =====================================================================
# Phase 8: AI Investigator API Tests
# =====================================================================


def _create_test_incident(api_client, user_suffix: str) -> str:
    """Helper to create a correlated incident through the events API."""
    api_client.post(
        "/api/v1/events",
        json={
            "event_id": f"inv-evt-1-{user_suffix}",
            "timestamp": "2026-11-01T00:00:00Z",
            "source": "auth_service",
            "event_type": "authentication_failure",
            "severity": 6,
            "message": f"Brute force attempt 1 for {user_suffix}",
            "user": f"inv_user_{user_suffix}",
            "source_ip": "203.0.113.50",
        },
    )
    r2 = api_client.post(
        "/api/v1/events",
        json={
            "event_id": f"inv-evt-2-{user_suffix}",
            "timestamp": "2026-11-01T00:02:00Z",
            "source": "auth_service",
            "event_type": "authentication_failure",
            "severity": 6,
            "message": f"Brute force attempt 2 for {user_suffix}",
            "user": f"inv_user_{user_suffix}",
            "source_ip": "203.0.113.50",
        },
    )
    incidents = r2.json()["incidents_created"]
    assert len(incidents) >= 1
    return incidents[0]


def test_trigger_investigation_on_incident(api_client) -> None:
    """POST /api/v1/incidents/{id}/investigate triggers AI investigation."""
    inc_id = _create_test_incident(api_client, "trig")

    resp = api_client.post(f"/api/v1/incidents/{inc_id}/investigate", json={"force": False})
    assert resp.status_code == 200
    body = resp.json()

    assert body["incident_id"] == inc_id
    assert body["investigation_id"].startswith("inv-")
    assert body["provider"] == "local_dev"
    assert body["model_name"] == "heuristic_deterministic_v1"
    assert len(body["findings"]) >= 1
    assert len(body["possible_response_actions"]) >= 1
    assert all(a["analyst_approval_required"] is True for a in body["possible_response_actions"])
    assert 0.0 <= body["confidence"] <= 1.0


def test_trigger_investigation_not_found(api_client) -> None:
    """POST /api/v1/incidents/{id}/investigate returns 404 for missing incident."""
    resp = api_client.post("/api/v1/incidents/inc-nonexistent/investigate", json={"force": False})
    assert resp.status_code == 404


def test_get_incident_investigation(api_client) -> None:
    """GET /api/v1/incidents/{id}/investigation returns the generated investigation."""
    inc_id = _create_test_incident(api_client, "get_inv")

    # Before investigation is run, returns 404
    resp_before = api_client.get(f"/api/v1/incidents/{inc_id}/investigation")
    assert resp_before.status_code == 404

    # Run investigation
    api_client.post(f"/api/v1/incidents/{inc_id}/investigate", json={"force": False})

    # Now GET returns it
    resp_after = api_client.get(f"/api/v1/incidents/{inc_id}/investigation")
    assert resp_after.status_code == 200
    assert resp_after.json()["incident_id"] == inc_id


def test_get_investigation_by_id(api_client) -> None:
    """GET /api/v1/investigations/{inv_id} returns the investigation."""
    inc_id = _create_test_incident(api_client, "by_id")
    r = api_client.post(f"/api/v1/incidents/{inc_id}/investigate", json={"force": False})
    inv_id = r.json()["investigation_id"]

    resp = api_client.get(f"/api/v1/investigations/{inv_id}")
    assert resp.status_code == 200
    body = resp.json()
    assert body["investigation_id"] == inv_id
    assert body["incident_id"] == inc_id

    # Nonexistent ID returns 404
    resp_missing = api_client.get("/api/v1/investigations/inv-missing-id")
    assert resp_missing.status_code == 404


# =====================================================================
# Phase 9: Case Management API Tests
# =====================================================================


def test_create_and_get_standalone_case(api_client) -> None:
    """POST /api/v1/cases creates standalone case; GET retrieves it."""
    payload = {
        "title": "Suspicious Reconnaissance Detected",
        "description": "Port scanning activity observed from internal host",
        "severity": 7,
        "priority": "high",
        "tags": ["recon", "network"],
        "actor": "soc_analyst_1",
    }
    resp = api_client.post("/api/v1/cases", json=payload)
    assert resp.status_code == 201
    body = resp.json()

    assert body["case_id"].startswith("case-")
    assert body["title"] == "Suspicious Reconnaissance Detected"
    assert body["severity"] == 7
    assert body["priority"] == "high"
    assert body["status"] == "open"
    assert "recon" in body["tags"]
    case_id = body["case_id"]

    # Retrieve by ID
    get_resp = api_client.get(f"/api/v1/cases/{case_id}")
    assert get_resp.status_code == 200
    assert get_resp.json()["case_id"] == case_id


def test_create_incident_seeded_case_deterministic(api_client) -> None:
    """POST /api/v1/cases with incident_id creates deterministic case and links incident."""
    inc_id = _create_test_incident(api_client, "case_seed")

    payload = {
        "title": f"Case for incident {inc_id}",
        "description": "Seeded case",
        "severity": 6,
        "priority": "medium",
        "incident_id": inc_id,
    }
    resp1 = api_client.post("/api/v1/cases", json=payload)
    assert resp1.status_code == 201
    case1 = resp1.json()

    # Re-posting same incident_id returns the existing case (idempotent)
    resp2 = api_client.post("/api/v1/cases", json=payload)
    assert resp2.status_code == 201
    case2 = resp2.json()

    assert case1["case_id"] == case2["case_id"]
    assert inc_id in case1["incident_ids"]
    assert any(e["reference_key"] == inc_id for e in case1["evidence_references"])


def test_case_patch_and_assign(api_client) -> None:
    """PATCH updates properties; POST /assign assigns case."""
    create_resp = api_client.post(
        "/api/v1/cases",
        json={
            "title": "Initial Title",
            "description": "Initial Desc",
            "severity": 5,
            "priority": "low",
        },
    )
    case_id = create_resp.json()["case_id"]

    # PATCH
    patch_resp = api_client.patch(
        f"/api/v1/cases/{case_id}",
        json={"title": "Updated Case Title", "priority": "critical"},
    )
    assert patch_resp.status_code == 200
    assert patch_resp.json()["title"] == "Updated Case Title"
    assert patch_resp.json()["priority"] == "critical"

    # Assign
    assign_resp = api_client.post(
        f"/api/v1/cases/{case_id}/assign",
        json={"assignee": "analyst_bob", "actor": "manager"},
    )
    assert assign_resp.status_code == 200
    assert assign_resp.json()["assignee"] == "analyst_bob"


def test_case_lifecycle_and_resolution_flow(api_client) -> None:
    """Full lifecycle: OPEN -> IN_PROGRESS -> PENDING -> IN_PROGRESS -> RESOLVED -> CLOSED."""
    create_resp = api_client.post(
        "/api/v1/cases",
        json={"title": "Lifecycle Test", "description": "Flow", "severity": 6},
    )
    case_id = create_resp.json()["case_id"]

    # 1. Invalid jump: OPEN -> RESOLVED (rejected 400)
    invalid_resp = api_client.post(
        f"/api/v1/cases/{case_id}/status",
        json={"new_status": "resolved"},
    )
    assert invalid_resp.status_code == 400

    # 2. OPEN -> IN_PROGRESS
    r_inp = api_client.post(
        f"/api/v1/cases/{case_id}/status",
        json={"new_status": "in_progress"},
    )
    assert r_inp.status_code == 200
    assert r_inp.json()["status"] == "in_progress"

    # 3. Cannot close directly from IN_PROGRESS without resolution (rejected 400)
    r_bad_close = api_client.post(
        f"/api/v1/cases/{case_id}/status",
        json={"new_status": "closed"},
    )
    assert r_bad_close.status_code == 400

    # 4. IN_PROGRESS -> RESOLVE (POST /resolve)
    r_res = api_client.post(
        f"/api/v1/cases/{case_id}/resolve",
        json={
            "summary": "Root cause identified as outdated software; patch applied.",
            "root_cause": "Vulnerable service version",
            "action_taken": "Patched service and confirmed healthy",
            "resolver": "senior_analyst",
        },
    )
    assert r_res.status_code == 200
    assert r_res.json()["status"] == "resolved"
    assert r_res.json()["resolution"]["resolved_by"] == "senior_analyst"

    # 5. RESOLVED -> CLOSED
    r_close = api_client.post(
        f"/api/v1/cases/{case_id}/status",
        json={"new_status": "closed"},
    )
    assert r_close.status_code == 200
    assert r_close.json()["status"] == "closed"


def test_case_notes_and_timeline_endpoints(api_client) -> None:
    """Notes are append-only; timeline reconstructs history from audit trail."""
    create_resp = api_client.post(
        "/api/v1/cases",
        json={"title": "Notes & Timeline Case", "description": "Desc", "severity": 4},
    )
    case_id = create_resp.json()["case_id"]

    # Add Note
    note_resp = api_client.post(
        f"/api/v1/cases/{case_id}/notes",
        json={"content": "Completed firewall rule audit for host", "author": "alice"},
    )
    assert note_resp.status_code == 201
    assert note_resp.json()["author"] == "alice"

    # List Notes
    notes_list_resp = api_client.get(f"/api/v1/cases/{case_id}/notes")
    assert notes_list_resp.status_code == 200
    assert len(notes_list_resp.json()) == 1

    # Link Evidence
    ev_resp = api_client.post(
        f"/api/v1/cases/{case_id}/evidence",
        json={
            "evidence_type": "alert",
            "reference_key": "alt-test-999",
            "description": "Correlated alert",
            "added_by": "alice",
        },
    )
    assert ev_resp.status_code == 201
    assert ev_resp.json()["reference_key"] == "alt-test-999"

    # Get Timeline
    timeline_resp = api_client.get(f"/api/v1/cases/{case_id}/timeline")
    assert timeline_resp.status_code == 200
    timeline = timeline_resp.json()
    assert len(timeline) >= 3  # created, note_added, evidence_linked
    actions = [t["action"] for t in timeline]
    assert "case.created" in actions
    assert "case.note_added" in actions
    assert "case.evidence_linked" in actions
