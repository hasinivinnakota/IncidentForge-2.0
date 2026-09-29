# IncidentForge — Architecture Document

**Last Updated:** 2026-09-03
**Status:** Approved (Phase 5 Backend Foundation complete; Checkpoints 6.1–6.4 implemented)

---

## 1. Architecture Overview

IncidentForge uses a **Hybrid Architecture**: Docker containers (via WSL2) for the Wazuh SIEM stack, with native Windows components for endpoint telemetry and application services.

### Why Hybrid?

| Concern | Decision |
|---|---|
| Wazuh is Linux-native | Runs in Docker (WSL2 backend) |
| Windows telemetry must be real | Sysmon + Wazuh Agent run natively on Windows |
| RAM is limited (16 GB) | Docker containers are lighter than full VMs |
| Development speed | Docker Compose enables single-command stack management |
| Portfolio presentation | `docker compose up` demonstrates infrastructure-as-code |

---

## 2. System Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────┐
│                        WINDOWS HOST (16 GB RAM)                 │
│                                                                 │
│  ┌──────────────────────┐     ┌───────────────────────────────┐ │
│  │   NATIVE WINDOWS     │     │   DOCKER (WSL2 Backend)       │ │
│  │                      │     │                               │ │
│  │  ┌────────────────┐  │     │  ┌─────────────────────────┐  │ │
│  │  │  Sysmon        │──┼──┐  │  │  Wazuh Manager          │  │ │
│  │  │  (Event Gen)   │  │  │  │  │  (1 GB RAM limit)       │  │ │
│  │  └────────────────┘  │  │  │  └────────────┬────────────┘  │ │
│  │                      │  │  │               │               │ │
│  │  ┌────────────────┐  │  │  │  ┌────────────▼────────────┐  │ │
│  │  │  Wazuh Agent   │──┼──┘  │  │  Wazuh Indexer          │  │ │
│  │  │  (< 200 MB)    │  │     │  │  (1.5 GB RAM limit)     │  │ │
│  │  └────────────────┘  │     │  └────────────┬────────────┘  │ │
│  │                      │     │               │               │ │
│  │  ┌────────────────┐  │     │  ┌────────────▼────────────┐  │ │
│  │  │ IncidentForge  │  │     │  │  Wazuh Dashboard        │  │ │
│  │  │  Backend       │◄─┼─────┤  │  (512 MB RAM limit)     │  │ │
│  │  │  (FastAPI)     │  │     │  └─────────────────────────┘  │ │
│  │  └───────┬────────┘  │     │                               │ │
│  │          │           │     │  Bound to 127.0.0.1 ONLY      │ │
│  │  ┌───────▼────────┐  │     └───────────────────────────────┘ │
│  │  │  SOC Dashboard │  │                                       │
│  │  │  (Vite+React)  │  │                                       │
│  │  └───────┬────────┘  │                                       │
│  │          │           │                                       │
│  │  ┌───────▼────────┐  │                                       │
│  │  │  ML Risk       │  │                                       │
│  │  │  Scoring       │  │                                       │
│  │  │  (sklearn/XGB) │  │                                       │
│  │  └───────┬────────┘  │                                       │
│  │          │           │                                       │
│  │  ┌───────▼────────┐  │                                       │
│  │  │  AI Investigator│  │                                       │
│  │  │  (API-based)   │──┼──────► External LLM API               │
│  │  └───────┬────────┘  │       (OpenAI / Gemini)               │
│  │          │           │                                       │
│  │  ┌───────▼────────┐  │                                       │
│  │  │  Response      │  │                                       │
│  │  │  Engine        │  │                                       │
│  │  └────────────────┘  │                                       │
│  └──────────────────────┘                                       │
└─────────────────────────────────────────────────────────────────┘
```

---

## 3. Data Flow

```
Sysmon (Windows Events)
    │
    ▼
Wazuh Agent (collects & forwards)
    │
    ▼  Port 1514 (TCP)
Wazuh Manager (decodes, analyzes, generates alerts)
    │
    ▼  Internal
Wazuh Indexer (stores alerts, searchable index)
    │
    ▼  Port 9200 (REST API)
IncidentForge Backend (FastAPI)
    │
    ├──► Alert Normalizer
    │       │
    │       ▼
    ├──► Threat Intel Enricher (IOC lookup)
    │       │
    │       ▼
    ├──► Incident Correlator (group related alerts)
    │       │
    │       ▼
    ├──► ML Risk Scorer (prioritize by risk)
    │       │
    │       ▼
    ├──► AI Investigator (explain & recommend)
    │       │
    │       ▼
    ├──► Response Engine (execute approved actions)
    │       │
    │       ▼
    └──► Audit Logger (record everything)
            │
            ▼
        SOC Dashboard (React — real-time view)
```

---

## 4. Component Details

### 4.1 Endpoint Telemetry (Native Windows)

| Component | Purpose | Resource Impact |
|---|---|---|
| **Sysmon** | Generates detailed Windows event telemetry (process creation, network connections, file changes, registry modifications) | < 100 MB RAM, negligible CPU |
| **Wazuh Agent** | Collects Sysmon logs + Windows Security events, forwards to Wazuh Manager | < 200 MB RAM |

### 4.2 Wazuh SIEM Stack (Docker)

| Container | Purpose | RAM Limit | Port |
|---|---|---|---|
| **Wazuh Manager** | Receives agent data, applies detection rules, generates alerts | 1 GB | 1514, 1515, 55000 |
| **Wazuh Indexer** | Stores and indexes alerts (OpenSearch-based) | 1.5 GB | 9200 |
| **Wazuh Dashboard** | Web UI for Wazuh (OpenSearch Dashboards) | 512 MB | 443 |

### 4.3 IncidentForge Application (Native Windows)

| Component | Technology | Purpose |
|---|---|---|
| **Backend API** | Python / FastAPI | Central orchestrator — normalizes, correlates, scores, investigates |
| **ML Risk Scoring** | scikit-learn, XGBoost | Lightweight CPU-based alert risk scoring |
| **AI Investigator** | External API (OpenAI/Gemini) | LLM-powered incident analysis and explanation |
| **Response Engine** | Python | Playbook-driven automated/approved response |
| **SOC Dashboard** | Vite + React | Real-time security operations interface |

---

## 5. RAM Budget

| Component | Allocation |
|---|---|
| Windows OS + background | ~4 GB |
| Wazuh Manager (Docker) | 1 GB (capped) |
| Wazuh Indexer (Docker) | 1.5 GB (capped) |
| Wazuh Dashboard (Docker) | 512 MB (capped) |
| Docker/WSL2 overhead | ~500 MB |
| IncidentForge Backend | ~300 MB |
| ML Component | ~500 MB |
| SOC Dashboard (dev server) | ~200 MB |
| IDE + development tools | ~1.5 GB |
| **Total** | **~10 GB** |
| **Remaining buffer** | **~6 GB** |

> **Strategy:** Non-essential components (ML training, AI investigation) run on-demand only. Wazuh containers have hard memory limits.

---

## 6. Network Architecture

```
All services bound to 127.0.0.1 (localhost only)

Port Map:
  1514  → Wazuh Manager  (agent communication)
  1515  → Wazuh Manager  (agent enrollment)
  514   → Wazuh Manager  (syslog)
  443   → Wazuh Dashboard (HTTPS web UI)
  9200  → Wazuh Indexer  (REST API)
  55000 → Wazuh API      (management)
    8000  → IncidentForge Backend (FastAPI)
  5173  → SOC Dashboard  (Vite dev server)
```

**No services are exposed to external networks.**

---

## 7. Security Boundaries

1. **Docker network isolation** — Wazuh containers communicate on an internal Docker bridge network
2. **Localhost binding** — All ports bound to `127.0.0.1`, not `0.0.0.0`
3. **Analyst approval gates** — Automated response requires human confirmation for destructive actions
4. **No real malware** — All simulations use benign Atomic Red Team–style artifacts
5. **Secrets management** — `.env` files excluded from Git; `.env.example` contains only placeholders
6. **Audit trail** — All actions logged for accountability

---

## 8. Storage Layout

All project data resides on **D: drive** (195 GB free):

```
D:\IncidentForge\          → Project code & configuration
D:\IncidentForge\datasets\ → Sample data, simulation artifacts
D:\DockerData\            → Docker Desktop data root (configured in Phase 1)
```

**C: drive** (12.7 GB free) is NOT used for project or Docker data.

## 9. Wazuh Ingestion Compatibility Note

Phase 2F is complete with a known ingestion compatibility limitation. The Wazuh Manager and its embedded Filebeat use Filebeat 7.10.2, which produces legacy `_type` metadata in Elasticsearch bulk requests. OpenSearch 2.13 rejects this metadata, so continuous indexing of new Wazuh alerts is currently blocked.

The Wazuh Manager, Indexer, Dashboard, Manager API, TLS, and persistent storage infrastructure is operational. The existing Wazuh alert index and its 195 alert documents are preserved. Wazuh 4.9.2 was inspected and retains Filebeat 7.10.2, so it does not resolve this issue. The official `compatibility.override_main_response_version` response override was tested and rejected because it breaks Dashboard compatibility. No unsupported workaround was implemented; this remains a documented infrastructure limitation rather than a silently masked failure.

In Phase 13, IncidentForge resolves this limitation cleanly via `WazuhAlertAdapter` (`backend/app/adapters/wazuh.py`). By consuming Wazuh alert JSON payloads directly (e.g. from `/var/ossec/logs/alerts/alerts.json` or the Wazuh Manager API `GET /alerts`) and mapping them into canonical `NormalizedEvent` records, IncidentForge completely bypasses the broken Filebeat `_type` bulk indexing path to OpenSearch without altering Docker or indexer configuration.

## 10. Phase 5 Backend Foundation

The initial IncidentForge backend foundation is implemented in Python with FastAPI, Pydantic, and Uvicorn. Telemetry enters through a source-agnostic adapter contract and is converted by a deterministic normalization service into the canonical event model.

Canonical models now define normalized events, alerts, incidents, investigation results, response actions, and audit events.

### 10.1 Implemented Components

The following components of the Phase 5 backend foundation are now implemented:

| Component | Status | Responsibility |
|---|---|---|
| Ingestion adapter boundary | Implemented | Source-agnostic adapter contract (current: `FixtureAdapter` for deterministic development/testing). Real Wazuh ingestion is not implemented. |
| Event normalization | Implemented | Deterministic conversion of raw telemetry into the canonical `NormalizedEvent` model via `NormalizationService`. |
| Event processing service | Implemented | Orchestrates persistence and audit for each accepted event via `EventProcessingService`. |
| Repository / persistence layer | Implemented | `EventRepository` owns all database persistence operations against the SQLite-backed SQLModel store. |
| SQLite persistence | Implemented | Local SQLite database is the current development persistence layer. |

### 10.2 Current Event Flow

The currently implemented event intake flow is:

```
Request
    │
    ▼
Pydantic validation  (NormalizedEvent)
    │
    ▼
NormalizationService
    │
    ▼
EventProcessingService
    │
    ▼
EventRepository
    │
    ▼
SQLite persistence  (Event / AuditEvent rows)
    │
    ▼
AuditEvent  (recorded for "created" and "duplicate" outcomes)
    │
    ▼
EventProcessingResult
    │
    ▼
HTTP response
```

Key properties of the current implementation:

- **Event intake is persistent.** Accepted events are stored in the SQLite-backed `Event` table.
- **SQLite is the current development persistence layer.** It is not a production store; production-grade persistence (e.g. PostgreSQL / cloud-managed) is a future migration.
- **`EventRepository` owns database persistence operations.** The processing service never speaks to the session directly.
- **`EventProcessingService` owns event-processing orchestration.** It calls the repository for both event persistence and audit-event creation.
- **Duplicate event IDs are handled deterministically.** A re-submitted `event_id` is matched against the existing row by `EventRepository`.
- **Duplicates do not create another `Event` row.** The repository returns the existing row and a `created=False` flag.
- **Duplicates do not overwrite the original event.** The existing row is preserved unchanged.
- **Audit records are generated for meaningful processing outcomes.** An `AuditEvent` is written for both the `event.created` and `event.duplicate` actions.
- **Persistence is already implemented.** It is not deferred.

### 10.3 Architectural Boundaries

The current backend preserves these architectural boundaries, and future layers plug in behind them without changing earlier layers:

1. **Ingestion adapter boundary** — `FixtureAdapter` is the current deterministic development/test adapter. Real Wazuh ingestion is not implemented.
2. **Event normalization** — `NormalizationService` produces the canonical `NormalizedEvent`.
3. **Event processing service** — `EventProcessingService` orchestrates persistence and audit.
4. **Repository / persistence layer** — `EventRepository` encapsulates SQLite access for events and audit events.
5. **Detection / correlation** — Future layer.
6. **Threat-intelligence enrichment** — Future layer.
7. **AI investigation** — Future layer.
8. **Controlled response engine** — Future layer; response actions remain data-only at this stage and no commands or automated actions are executed.

### 10.4 Wazuh Compatibility Constraint (Reminder)

The Wazuh → Filebeat → OpenSearch `_type` metadata limitation documented in Section 9 remains a known infrastructure limitation. The adapter boundary intentionally isolates the backend from that path so the Filebeat-to-OpenSearch ingestion block does not block development. The current `FixtureAdapter` is the deterministic development/test ingestion adapter; real Wazuh ingestion is not implemented in this phase.

### 10.5 Future Persistence Evolution

SQLite is used as the current development persistence layer. A future migration to a production-grade store (for example PostgreSQL or a managed cloud database) is part of the planned evolution of the persistence layer, not part of "future database persistence," which is already implemented.

---

## 11. Phase 6 Detection & Correlation Pipeline

The Phase 6 pipeline extends the backend with rule-based detection (Checkpoint 6.1) and alert correlation (Checkpoint 6.2) sitting upstream of incident creation.

### 11.1 Detection Engine (Checkpoint 6.1)

- **`DetectionRule` (ABC)**: Abstract interface for detection rules evaluated against `NormalizedEvent`.
- **`DetectionEngine`**: Stateless service matching events against registered detection rules.
- **Built-in Rules**: `builtin-001` (High Severity), `builtin-002` (Suspicious Process), `builtin-003` (Authentication Failure), `builtin-004` (Network Connection Anomaly), `builtin-005` (Privilege Escalation Indicator).
- **`AlertService`**: Generates deterministic `alert_id` values (`alert-SHA256(event_id:rule_id)[:16]`) and records audit trails.
- **`AlertRepository`**: Manages SQLite persistence for alerts.

### 11.2 Correlation Engine (Checkpoint 6.2)

- **`CorrelationRule` (ABC)**: Extensible interface inspecting incoming `CorrelatableAlert` instances against a bounded historical window.
- **Built-in Rules**:
  - `AuthenticationAttackSequenceRule` (`corr-rule-001`): Multiple authentication failures against same user/source IP within 15-minute window.
  - `ProcessNetworkSequenceRule` (`corr-rule-002`): Suspicious process execution followed by a network connection on the same host within 30-minute window.
  - `PrivilegeEscalationSequenceRule` (`corr-rule-003`): Suspicious process or authentication activity coupled with privilege escalation on the same host/user within 30-minute window.
  - `SameEntityCorrelationRule` (`corr-rule-004`): Multiple distinct security alerts observed on the same host or user within 30-minute window.
- **`CorrelationEngine`**: Stateful lifecycle manager matching alerts, generating deterministic `correlation_id` values (`corr-SHA256(type:entity:founding_alert)[:16]`), creating/updating open correlations, and logging audit records.
- **`CorrelationRepository`**: Manages SQLite persistence for correlated security activities (`Correlation` table).

### 11.3 Incident Creation (Checkpoint 6.3)

- **`IncidentService`**: Creates or updates `Incident` records from correlated security activity. One active incident per correlation (idempotent).
  - **Deterministic Incident ID**: `inc-SHA256("incident:" + correlation_id)[:16]`.
  - **Severity**: Derived directly from `Correlation.severity`, clamped to `[0, 15]`. Kept separate from future ML risk scoring.
  - **Summary/Description**: Deterministic structured text from correlation type, entity, alert count, time range, MITRE techniques, and severity. No LLM or AI.
  - **Evidence**: Bounded dictionary with only operational fields (`correlation_type`, `entity_key`, `alert_count`). No credentials, tokens, passwords, API keys, or unrestricted raw metadata.
  - **Audit Trail**: `incident.created`, `incident.updated`, `incident.duplicate`, `incident.status_updated` events via `EventRepository.create_audit_event`.
- **`IncidentRepository`**: Manages SQLite persistence for incidents (`Incident` table with `correlation_ids_json`, `alert_ids_json`, `event_ids_json`, `mitre_techniques_json`, `evidence_json`, `first_seen`, `last_seen`).
- **Incident Status Lifecycle**: `open` → `investigating` → `resolved` → `closed` (SOC standard).
- **API Endpoints**:
  - `GET /api/v1/incidents` — List with filters (`status`, `correlation_id`, `severity`, `limit`).
  - `GET /api/v1/incidents/{incident_id}` — Retrieve by ID (404 if not found).
  - `PATCH /api/v1/incidents/{incident_id}/status` — Status update with audit trail.

### 11.4 ML Risk Scoring (Checkpoint 6.4)

- **`RiskScoringService`**: Enriches `Incident` records with an ML-computed risk assessment following incident creation.
  - **Architectural Isolation**:
    $$\text{Detection Rule Severity} \ne \text{Incident Severity} \ne \text{ML Risk Score} \ne \text{Future AI Investigation}$$
    The ML risk score enriches the incident but **never** modifies or overwrites the incident's original severity.
  - **Risk Scale & Levels**:
    - `risk_score`: 0–100 integer.
    - `risk_level`: `low` (0–24), `medium` (25–49), `high` (50–74), `critical` (75–100).
  - **Feature Extraction (`v1.0`)**: 12 deterministic, bounded numeric features:
    1. `incident_severity` [0–15]
    2. `correlation_severity` [0–15]
    3. `alert_count`
    4. `event_count`
    5. `correlation_count`
    6. `mitre_count`
    7. `has_auth_attack` (0 or 1)
    8. `has_suspicious_process` (0 or 1)
    9. `has_network_activity` (0 or 1)
    10. `has_privilege_escalation` (0 or 1)
    11. `time_span_seconds` (>= 0)
    12. `entity_diversity` (distinct tags/entities)
    *Strict Security Guarantee*: Excludes passwords, tokens, API keys, credentials, and unrestricted raw metadata.
  - **Baseline Model (`baseline_logistic_regression`, `v1.0`)**:
    - Calibrated logistic regression scoring with sigmoid probability mapping.
    - Zero-dependency runtime fallback with exact standardization, coefficients, and intercept.
    - Persisted artifact: `backend/app/ml/artifacts/model_metadata_v1.json`.
  - **Explainability**: Deterministic reason codes based on feature contributions (`AUTHENTICATION_ATTACK`, `PRIVILEGE_ESCALATION`, `SUSPICIOUS_PROCESS_ACTIVITY`, `NETWORK_ACTIVITY`, `MULTIPLE_MITRE_TECHNIQUES`, `HIGH_ALERT_VOLUME`, `HIGH_CORRELATION_SEVERITY`, `HIGH_INCIDENT_SEVERITY`).
  - **Dataset Note**: Current training data is synthetic development data for development/testing only; it does not represent production accuracy.
  - **Persistence & API**:
    - `RiskAssessment` SQLModel table and `RiskAssessmentRepository`.
    - `GET /api/v1/incidents/{incident_id}/risk`
    - `GET /api/v1/risk-assessments/{assessment_id}`

### 11.5 Threat Intelligence Enrichment (Checkpoint 6.5 / Phase 7)

- **`IOCExtractor`**: Safely extracts Indicators of Compromise (IOCs) from structured evidence.
  - **Supported Types**: IPv4, IPv6, Domain, URL, SHA256, SHA1, MD5.
  - **Security Guarantee**: Excludes passwords, API keys, credentials, and tokens using regex boundaries.
  - **Normalization**: Standardizes formats (e.g., uppercasing hashes, lowercasing domains) and deduplicates.
- **`ThreatIntelProvider` (ABC)**: Abstract interface for TI lookups.
  - **`LocalDevThreatIntelProvider`**: Deterministic synthetic data provider used for development (no external network calls). Uses RFC 5737 and `.example` TLDs.
- **`ThreatIntelligenceService`**: Orchestrates extraction and enrichment.
  - **Idempotency**: Uses deterministic enrichment IDs: `ti-SHA256(incident_id:ioc_normalized)[:16]`.
  - **Architectural Isolation**: Never modifies incident severity or ML risk scores.
  - **Audit Trail**: `threat_intelligence.enrichment_created`, `threat_intelligence.enrichment_updated` events.
- **Persistence & API**:
  - `ThreatIntelEnrichment` SQLModel table and `ThreatIntelRepository`.
  - `GET /api/v1/incidents/{incident_id}/threat-intelligence`
  - `GET /api/v1/threat-intelligence/{enrichment_id}`
  - `GET /api/v1/threat-intelligence/ioc/{ioc_type}/{ioc_value}`

### 11.6 Pipeline Flow

```
NormalizedEvent
      │
      ▼
EventProcessingService (persist Event + Audit)
      │
      ▼ (if newly persisted)
DetectionEngine (evaluate rules)
      │
      ▼ (if matches found)
AlertService (persist Alert + Audit)
      │
      ▼ (if alerts generated)
CorrelationEngine (correlate alerts within bounded window)
      │
      ▼ (if correlations created/updated)
IncidentService (create/update Incident + Audit)
      │
      ▼ (if incidents created/updated)
RiskScoringService (ML risk score + level + explainability + Audit)
      │
      ▼ (if incidents created/updated)
ThreatIntelligenceService (IOC extraction + synthetic provider lookup + Audit)
      │
      ▼
persisted / updated ThreatIntelEnrichment + Audit
```

---

## 13. Phase 8: AI Investigator

### 13.1 Design Principles & Security Guardrails

The AI Investigator operates as an evidence-grounded, advisory-only decision support system for SOC analysts:
1. **Advisory-Only**: The AI Investigator generates findings, hypothesis analysis, timelines, and response suggestions. It NEVER triggers active containment, remediation, or endpoint code execution.
2. **Human-in-the-Loop**: All response actions produced have `analyst_approval_required = True` and `inert_proposed_only = True`.
3. **Immutability of Ground Truth**: The AI layer CANNOT overwrite, re-score, or mutate `Incident.severity` or ML `RiskAssessment.risk_score`.
4. **Zero-Trust Telemetry Handling**: Raw telemetry strings (command lines, file paths, process names) are sanitized, length-bounded, and redacted of credentials/tokens (`[REDACTED]`) before context assembly.
5. **Provider-Agnostic Abstraction**: Uses `LLMProvider` ABC enabling zero-cost deterministic mock development (`LocalDevLLMProvider`) without live external cloud API calls or API keys.

### 13.2 Core Components

- **`LLMContext`**: Structured domain payload containing bounded incident metadata, alert summaries, mapped MITRE ATT&CK techniques, risk assessment scores, threat intelligence summaries, and timeline events.
- **`LLMProvider` (ABC)**:
  - `investigate(context: LLMContext, investigation_id: str) -> InvestigationResult`
  - `provider_name: str`
  - `model_name: str`
- **`LocalDevLLMProvider`**:
  - Deterministic implementation deriving structured findings from evidence.
  - Categorizes findings into:
    - `OBSERVED`: Grounded facts directly observable in alerts, entities, and threat intelligence.
    - `INFERRED`: Analytical hypotheses and correlation patterns (e.g. MITRE technique alignment).
    - `RECOMMENDED`: Immediate analyst attention areas.
  - Proposes inert containment recommendations (`isolate_endpoint`, `quarantine_file`, `revoke_credentials`).
  - Estimates investigation confidence based on evidence completeness (0.0 to 1.0).
- **`AIInvestigatorService`**:
  - Orchestrates context extraction, sanitization/redaction, LLM provider invocation, persistence, and audit logging.
  - Deterministic investigation ID: `inv-SHA256("inv:" + incident_id)[:16]`.
  - Idempotent: Repeated calls without `force=True` return existing records; `force=True` triggers re-investigation.
  - Emits audit events: `investigation.requested`, `investigation.completed`, `investigation.failed`.
- **`InvestigationRepository` & `Investigation` SQLModel**:
  - Stores full structured JSON for findings, timeline, MITRE techniques, threat intelligence summary, investigation gaps, next steps, and proposed response actions.

### 13.3 API Endpoints

- `POST /api/v1/incidents/{incident_id}/investigate` — Trigger or retrieve AI investigation (`force: bool = False`)
- `GET /api/v1/incidents/{incident_id}/investigation` — Retrieve latest investigation for incident
- `GET /api/v1/investigations/{investigation_id}` — Retrieve specific investigation by ID

---

## 14. Phase 9: SOC Case Management

### 14.1 Purpose & Separation of Concerns

Case Management represents the human operational layer of IncidentForge, positioned downstream of the detection, correlation, incident creation, ML risk scoring, threat intelligence enrichment, and AI investigation stages:
- **Incident vs. Case Distinction**:
  - An **Incident** is an automated, machine-correlated cluster of alerts and security events sharing an entity or attack signature.
  - A **Case** is a human-governed operational record managed by SOC analysts to coordinate investigation, track hypotheses, record notes, link multi-source evidence, and achieve audited resolution.
- **Aggregation**: A single Case may contain multiple Incident IDs (e.g., related incidents spanning multiple hosts or lateral movement stages).
- **Evidence Referencing**: Cases store lightweight, strongly typed reference pointers (`evidence_type`, `reference_key`, `description`, `added_by`, `added_at`) rather than duplicating bulky telemetry payloads.

### 14.2 AI Advisory Isolation & Immutability Guarantees

1. **Advisory Isolation**: AI investigations and suggestions remain strictly advisory. AI cannot close cases, modify case priority, approve response actions, or transition case statuses.
2. **ML Risk & Telemetry Immutability**: Managing, updating, or resolving a case does not overwrite `Incident.severity`, ML `RiskAssessment.risk_score`, `Alert`, or `Event` telemetry.
3. **Analyst Attribution**: All state transitions, assignments, resolutions, notes, and evidence links require actor attribution that is permanently recorded in the audit trail.
4. **Secret Redaction**: Analyst-provided titles, descriptions, and notes are automatically sanitized using regex pattern matching (`[REDACTED]`) to strip passwords, tokens, API keys, and credentials before persistence.

### 14.3 Case Lifecycle State Machine

Cases adhere to a strict finite state machine with deterministic transitions:

```
      ┌────────────────────────┐
      │          OPEN          │
      └───────────┬────────────┘
                  │ (start work)
                  ▼
      ┌────────────────────────┐◄──────────┐ (reopen)
      │      IN_PROGRESS       │           │
      └───┬───────────────▲────┴───────┐   │
          │ (need info)   │            │   │
          ▼               │ (resume)   │   │
      ┌───────────────────┴────┐       │   │
      │        PENDING         │       │   │
      └───┬────────────────────┘       │   │
          │ (resolve)                  │ (resolve)
          ▼                            │   │
      ┌────────────────────────────────▼───┴┐
      │              RESOLVED               │
      └───────────────────┬─────────────────┘
                          │ (close)
                          ▼
      ┌─────────────────────────────────────┐
      │               CLOSED                │
      └─────────────────────────────────────┘
```

- **Allowed Transitions**:
  - `OPEN` → `IN_PROGRESS`
  - `IN_PROGRESS` → `PENDING`, `RESOLVED`, `OPEN`
  - `PENDING` → `IN_PROGRESS`, `RESOLVED`
  - `RESOLVED` → `CLOSED`, `IN_PROGRESS`
  - `CLOSED` → `IN_PROGRESS`
- **Enforced Constraints**:
  - Direct transitions from `OPEN` to `RESOLVED` or `CLOSED` are rejected (HTTP 400).
  - Resolving a case requires an explicit resolution summary (`POST /api/v1/cases/{id}/resolve`).
  - Closing a case requires that it has already been resolved.

### 14.4 Normalized Persistence Schema

To ensure scalability and performance, case notes and evidence references are stored in dedicated normalized tables rather than nested JSON in the `Case` row:
- **`Case` table**: Core metadata, status, priority, severity, assignee, timestamps, and JSON-encoded lists of linked IDs (`incident_ids_json`, `investigation_ids_json`, `tags_json`) and structured `resolution_json`.
- **`CaseNoteRecord` table**: Append-only analyst notes (`note_id`, `case_id`, `author`, `content`, `created_at`, `updated_at`).
- **`EvidenceReferenceRecord` table**: Deduplicated evidence references (`evidence_id`, `case_id`, `evidence_type`, `reference_key`, `description`, `added_by`, `added_at`).

### 14.5 Deterministic & Collision-Safe Identifiers

- **Incident-Seeded Cases**: `case-SHA256("case:" + incident_id)[:16]` guarantees idempotent case creation when seeding from an incident.
- **Standalone Cases**: `case-UUID4[:16]` provides collision safety for manual threat-hunting cases.
- **Notes**: `note-UUID4[:16]`.
- **Evidence References**: `evref-SHA256(case_id + ":" + evidence_type + ":" + reference_key)[:16]`.

### 14.6 Audit Trail & Timeline

Every case lifecycle event generates a corresponding immutable audit event:
- `case.created`, `case.updated`, `case.assigned`, `case.status_changed`, `case.incident_linked`, `case.investigation_linked`, `case.evidence_linked`, `case.note_added`, `case.resolved`, `case.closed`.
- Chronological case timeline (`GET /api/v1/cases/{case_id}/timeline`) is dynamically derived from these audit records, avoiding duplicate or desynchronized timeline stores.

### 14.7 API Endpoints

- `POST /api/v1/cases` — Create case (standalone or incident-seeded)
- `GET /api/v1/cases` — List cases with filtering (`status`, `priority`, `assignee`, `limit`)
- `GET /api/v1/cases/{case_id}` — Retrieve case details
- `PATCH /api/v1/cases/{case_id}` — Update general case properties
- `POST /api/v1/cases/{case_id}/assign` — Assign/reassign case
- `POST /api/v1/cases/{case_id}/status` — Transition status
- `POST /api/v1/cases/{case_id}/resolve` — Resolve case with required summary
- `POST /api/v1/cases/{case_id}/notes` — Add append-only analyst note
- `GET /api/v1/cases/{case_id}/notes` — List case notes
- `POST /api/v1/cases/{case_id}/evidence` — Link evidence pointer
- `GET /api/v1/cases/{case_id}/timeline` — Retrieve audit-derived chronological timeline

### 14.8 Deferred Items

- **Phase 11**: Interactive SOC web console and dashboard.
- **Phase 12**: RBAC, JWT tokens, and multi-tenant authentication.
- **Phase 14**: External ticketing webhooks (Jira, ServiceNow, TheHive).

---

## 15. Controlled Response Architecture (Phase 10)

### 15.1 Defensive Principles & Safety Guarantees

IncidentForge strictly operates as a defensive, safe SOC platform.

All response execution in this phase is **simulation-only**. Under no circumstances will any live host, network interface, file system, credential, directory service, or cloud API be modified or interrupted:
- **No host or network changes**: The system never isolates real machines, configures firewalls, or alters routing tables.
- **No filesystem modifications**: The system never deletes, moves, or alters files on any endpoint.
- **No account / identity changes**: The system never disables real accounts, changes passwords, or revokes live authentication tokens.
- **No subshell or external API calls**: Response execution is purely local, deterministic simulation without subprocess execution or external network calls.
- **AI is strictly advisory**: AI investigator recommendations are informational and proposed-only; the AI agent cannot approve or execute response actions.

### 15.2 Response State Machine & Analyst Control

Response actions follow a strict state machine requiring explicit human-in-the-loop analyst intervention:

```
          ┌─────────────┐
          │  PROPOSED   │
          └──────┬──────┘
                 │
       ┌─────────┴─────────┐
       ▼                   ▼
┌─────────────┐     ┌─────────────┐
│  APPROVED   │     │  REJECTED   │ (terminal)
└──────┬──────┘     └─────────────┘
       │
 ┌─────┴─────┐
 ▼           ▼
┌───────────┐ ┌────────┐
│ EXECUTED  │ │ FAILED │ (terminal)
└───────────┘ └────────┘
```

- **Approval Gate**: Execution (`POST /api/v1/response-actions/{id}/execute`) strictly requires `status == APPROVED`. Attempting to execute proposed, rejected, or executed actions fails with HTTP 409 Conflict.
- **Terminal States**: `EXECUTED`, `FAILED`, and `REJECTED` cannot be transitioned or re-executed.

### 15.3 Allowlisted Simulated Actions

Actions are restricted to an explicit allowlist:
1. `isolate_endpoint`: Simulates endpoint network containment.
2. `quarantine_file`: Simulates suspicious binary isolation.
3. `revoke_credentials`: Simulates account session invalidation and credential reset.

### 15.4 Auditing & Credential Redaction

- Every lifecycle change generates an immutable `AuditEvent`:
  - `response_action.proposed`
  - `response_action.approved`
  - `response_action.rejected`
  - `response_action.execution_started` (`simulation_only: True`)
  - `response_action.executed` (`simulation_only: True`)
- Rejection reasons, actor names, and results are sanitized and redacted for sensitive tokens, passwords, session cookies, and API keys before persistence and auditing.

### 15.5 API Endpoints

- `POST /api/v1/incidents/{incident_id}/response-actions` — Create proposed action (HTTP 201)
- `GET /api/v1/incidents/{incident_id}/response-actions` — List actions for an incident (HTTP 200)
- `GET /api/v1/response-actions/{action_id}` — Retrieve response action by ID (HTTP 200)
- `POST /api/v1/response-actions/{action_id}/approve` — Analyst approves action (HTTP 200)
- `POST /api/v1/response-actions/{action_id}/reject` — Analyst rejects action with reason (HTTP 200)
- `POST /api/v1/response-actions/{action_id}/execute` — Run safe deterministic simulation (HTTP 200)

---

## 16. End-to-End Pipeline & Next.js SOC Dashboard (Phases 11–13)

### 16.1 Comprehensive Data Pipeline

The completed end-to-end telemetry and analysis pipeline operates as follows:

```
Wazuh Manager / Sysmon / Synthetic JSON
       │
       ▼
WazuhAlertAdapter (backend/app/adapters/wazuh.py)
       │
       ▼
NormalizationService (canonical NormalizedEvent model)
       │
       ▼
EventPipeline
       ├──► EventProcessingService (Persist event + Audit record)
       │
       ├──► DetectionEngine (Built-in detection rules: T1059, T1110, etc.)
       │       │
       │       ▼
       ├──► AlertService (Deterministic alert creation + Audit trail)
       │       │
       │       ▼
       ├──► CorrelationEngine (Time-window attack sequence correlation)
       │       │
       │       ▼
       ├──► IncidentService (Incident lifecycle management)
       │       │
       │       ▼
       ├──► ML Risk Scoring (Scikit-learn logistic regression / heuristics)
       │       │
       │       ▼
       ├──► Threat Intelligence Service (IOC extraction & provider enrichment)
       │
       ├──► AI Investigator (On-demand advisory LLM analysis & gap detection)
       │
       ├──► Case Management (SOC analyst collaboration, notes, & evidence)
       │
       └──► Controlled Response (Simulation-only analyst-gated containment)
```

### 16.2 Modern SOC Web Console

The frontend is implemented with Next.js (App Router), TypeScript, and Tailwind CSS.
- **Operations Overview**: Real-time KPI summary (Active Alerts, Incidents, Critical Thresholds, Cases), interactive threat activity charts, MITRE ATT&CK coverage widget, and live alert streams.
- **Incident Workspace**: 8-tab deep inspection console:
  1. *Overview* — High-level telemetry, correlation link badges, and ML/AI summaries.
  2. *Timeline* — Chronological event sequence derived from forensic investigation.
  3. *Evidence* — Raw, bounded evidence JSON dictionary payloads.
  4. *ML Risk* — 0-100 risk score, risk level badge, and feature contribution breakdown.
  5. *AI Investigation* — Structured advisory findings (`OBSERVED`, `INFERRED`, `RECOMMENDED`), investigation gaps, and next steps.
  6. *Threat Intelligence* — Table of enriched IOCs, confidence ratings, and reputation classifications.
  7. *Case* — SOC case tracking and assigned analyst status.
  8. *Response* — Controlled response action proposal, approval gating, and simulation execution.
- **Resilience & Safety**: Per-widget error isolation via `Promise.allSettled`, zero client-side data fabrication, and prominent visual labeling of simulation and advisory boundaries.

---

## 17. Dataset Security Operations (IncidentForge v2)

IncidentForge v2 introduces a parallel data plane for monitoring, analyzing, and responding to activity against sensitive datasets. It integrates completely with the existing IncidentForge v1 SOC pipeline without redesigning the core SIEM components.

### 17.1 Unified Telemetry Pipeline
Dataset Activity bypasses Wazuh and Sysmon. It enters the system via the `DatasetActivityAdapter`, which is responsible for normalizing structured dataset access and modification operations into the canonical `NormalizedEvent` model.

```
Wazuh / Sysmon                    Dataset Activity
      │                                  │
      ▼                                  ▼
WazuhAlertAdapter             DatasetActivityAdapter
      │                                  │
      └──────────────┬───────────────────┘
                     ▼
              NormalizedEvent
                     ▼
              EventPipeline
```

### 17.2 Domain & Persistence Models
- **`DatasetAsset`**: Represents a registered dataset profile (e.g., CSV, JSON, Parquet) with column metadata, sensitivity classifications, and row/column counts.
- **`DatasetActivity`**: Tracks access and modification activities, mapping actors, host IPs, dataset IDs, and the volume of records modified or accessed.

### 17.3 Dataset Analysis Extensions
- **Detection & Correlation**: `dataset_builtin.py` introduces specific detection rules (e.g., PII Export, Mass Deletion, Unauthorized Actor), and `dataset_correlation.py` introduces time-window sequence attack rules.
- **ML Risk Features**: v2.0 ML features track dataset interactions (`has_pii_access`, `has_mass_export`, `has_schema_alteration`). The Baseline Logistic Risk Model is extended with dataset-specific weights.
- **AI Investigator**: The LLM Context includes a bounded `dataset_context` for dataset metadata and activity summaries. The AI provides dataset-aware hypothesis generation and recommends `restrict_dataset_access`.
- **Response**: The `restrict_dataset_access` action is registered in the Controlled Response pipeline. As with all v1 responses, this action is strictly simulation-only.

### 17.4 Dashboard Views
The Next.js dashboard is extended with:
- **Dataset Catalog View**: Interactive table of registered dataset assets, sensitivities, formats, and structural characteristics.
- **Dataset Activity Stream**: Real-time chronological table of dataset operations.
- **Incident Workspace**: Added Dataset Security Context panel rendering actor, sensitivity, and column telemetry dynamically when an incident is related to dataset compromise.
