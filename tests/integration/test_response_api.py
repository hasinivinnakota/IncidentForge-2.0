"""Integration tests for Controlled Response API endpoints."""

from datetime import datetime, timezone
import pytest

from backend.app.models.incidents import Incident as DomainIncident, IncidentStatus
from backend.app.persistence.repositories import IncidentRepository


@pytest.fixture
def seed_incident(test_engine):
    from sqlmodel import Session
    with Session(test_engine) as session:
        repo = IncidentRepository(session)
        now = datetime.now(timezone.utc)
        incident = DomainIncident(
            incident_id="inc-api-test-001",
            title="Credential Dumping Alert",
            description="LSASS memory access observed",
            severity=10,
            status=IncidentStatus.OPEN,
            created_at=now,
            updated_at=now,
        )
        repo.create_incident(incident)
    return "inc-api-test-001"


def test_create_response_action_endpoint(api_client, seed_incident):
    resp = api_client.post(
        f"/api/v1/incidents/{seed_incident}/response-actions",
        json={"action_type": "isolate_endpoint", "actor": "analyst1"},
    )
    assert resp.status_code == 201
    data = resp.json()
    assert data["incident_id"] == seed_incident
    assert data["action_type"] == "isolate_endpoint"
    assert data["status"] == "proposed"
    assert data["action_id"].startswith("resp-")


def test_create_response_action_missing_incident_returns_404(api_client):
    resp = api_client.post(
        "/api/v1/incidents/inc-nonexistent/response-actions",
        json={"action_type": "isolate_endpoint", "actor": "analyst1"},
    )
    assert resp.status_code == 404
    assert "not found" in resp.json()["detail"].lower()


def test_create_response_action_invalid_type_returns_400(api_client, seed_incident):
    resp = api_client.post(
        f"/api/v1/incidents/{seed_incident}/response-actions",
        json={"action_type": "nuke_server", "actor": "analyst1"},
    )
    assert resp.status_code == 400
    assert "unsupported response action type" in resp.json()["detail"].lower()


def test_list_and_get_response_actions_endpoints(api_client, seed_incident):
    # Create two actions
    r1 = api_client.post(
        f"/api/v1/incidents/{seed_incident}/response-actions",
        json={"action_type": "isolate_endpoint"},
    )
    r2 = api_client.post(
        f"/api/v1/incidents/{seed_incident}/response-actions",
        json={"action_type": "quarantine_file"},
    )
    action_id_1 = r1.json()["action_id"]

    # List
    list_resp = api_client.get(f"/api/v1/incidents/{seed_incident}/response-actions")
    assert list_resp.status_code == 200
    actions = list_resp.json()
    assert len(actions) == 2

    # Get single
    get_resp = api_client.get(f"/api/v1/response-actions/{action_id_1}")
    assert get_resp.status_code == 200
    assert get_resp.json()["action_id"] == action_id_1

    # Get non-existent
    bad_get = api_client.get("/api/v1/response-actions/resp-unknown")
    assert bad_get.status_code == 404


def test_full_response_action_lifecycle_api(api_client, seed_incident):
    # 1. Create proposed action
    create_resp = api_client.post(
        f"/api/v1/incidents/{seed_incident}/response-actions",
        json={"action_type": "revoke_credentials", "actor": "analyst1"},
    )
    action_id = create_resp.json()["action_id"]

    # 2. Cannot execute directly without approval (409 Conflict)
    bad_exec = api_client.post(
        f"/api/v1/response-actions/{action_id}/execute",
        json={"actor": "analyst1"},
    )
    assert bad_exec.status_code == 409
    assert "invalid response transition" in bad_exec.json()["detail"].lower()

    # 3. Approve action
    appr_resp = api_client.post(
        f"/api/v1/response-actions/{action_id}/approve",
        json={"actor": "soc_lead"},
    )
    assert appr_resp.status_code == 200
    assert appr_resp.json()["status"] == "approved"
    assert appr_resp.json()["approved_by"] == "soc_lead"

    # 4. Execute simulation
    exec_resp = api_client.post(
        f"/api/v1/response-actions/{action_id}/execute",
        json={"actor": "soc_lead"},
    )
    assert exec_resp.status_code == 200
    exec_data = exec_resp.json()
    assert exec_data["status"] == "executed"
    assert exec_data["executed_at"] is not None
    assert "SIMULATION ONLY" in exec_data["result"]

    # 5. Cannot re-approve or reject executed action (409 Conflict)
    re_appr = api_client.post(
        f"/api/v1/response-actions/{action_id}/approve",
        json={"actor": "soc_lead"},
    )
    assert re_appr.status_code == 409

    re_rej = api_client.post(
        f"/api/v1/response-actions/{action_id}/reject",
        json={"actor": "soc_lead", "reason": "Too late"},
    )
    assert re_rej.status_code == 409


def test_reject_flow_api(api_client, seed_incident):
    create_resp = api_client.post(
        f"/api/v1/incidents/{seed_incident}/response-actions",
        json={"action_type": "isolate_endpoint"},
    )
    action_id = create_resp.json()["action_id"]

    rej_resp = api_client.post(
        f"/api/v1/response-actions/{action_id}/reject",
        json={"actor": "tier2_analyst", "reason": "False positive alert confirmed."},
    )
    assert rej_resp.status_code == 200
    assert rej_resp.json()["status"] == "rejected"
    assert "False positive" in rej_resp.json()["result"]

    # Rejected action cannot execute (409 Conflict)
    exec_resp = api_client.post(
        f"/api/v1/response-actions/{action_id}/execute",
        json={"actor": "tier2_analyst"},
    )
    assert exec_resp.status_code == 409
