/**
 * IncidentForge Domain Types
 * Derived strictly from backend Pydantic models in backend/app/models/
 */

// ---------------------------------------------------------------------------
// Common & Health
// ---------------------------------------------------------------------------

export interface HealthResponse {
  status: string
  service: string
}

// ---------------------------------------------------------------------------
// Alerts (backend/app/models/alerts.py)
// ---------------------------------------------------------------------------

export type AlertStatus = "new" | "acknowledged" | "closed"

export interface Alert {
  alert_id: string
  event_id: string
  timestamp: string
  rule_id: string
  rule_name: string
  severity: number // 0-15
  description: string
  source: string
  evidence: Record<string, unknown>
  mitre_techniques: string[]
  status: AlertStatus
}

// ---------------------------------------------------------------------------
// Correlations (backend/app/models/correlation.py)
// ---------------------------------------------------------------------------

export type CorrelationStatus = "active" | "escalated" | "resolved"

export interface Correlation {
  correlation_id: string
  correlation_type: string
  entity_key: string
  title: string
  description: string
  severity: number // 0-15
  status: CorrelationStatus
  first_seen: string
  last_seen: string
  alert_ids: string[]
  event_ids: string[]
  alert_count: number
  mitre_techniques: string[]
  evidence: Record<string, unknown>
}

// ---------------------------------------------------------------------------
// Incidents (backend/app/models/incidents.py)
// ---------------------------------------------------------------------------

export type IncidentStatus = "open" | "investigating" | "resolved" | "closed"

export interface Incident {
  incident_id: string
  title: string
  description: string
  severity: number // 0-15
  status: IncidentStatus
  created_at: string
  updated_at: string
  correlation_ids: string[]
  alert_ids: string[]
  event_ids: string[]
  first_seen?: string | null
  last_seen?: string | null
  mitre_techniques: string[]
  evidence: Record<string, unknown>
  tags: string[]
}

export interface IncidentStatusUpdate {
  status: IncidentStatus
}

// ---------------------------------------------------------------------------
// Risk Scoring (backend/app/models/risk.py)
// ---------------------------------------------------------------------------

export type RiskLevel = "low" | "medium" | "high" | "critical"

export interface RiskAssessment {
  assessment_id: string
  incident_id: string
  risk_score: number // 0-100
  risk_level: RiskLevel
  model_name: string
  model_version: string
  feature_version: string
  scored_at: string
  features: Record<string, number>
  reasons: string[]
  feature_contributions: Record<string, number>
}

// ---------------------------------------------------------------------------
// Threat Intelligence (backend/app/models/threat_intel.py)
// ---------------------------------------------------------------------------

export type IOCType = "ipv4" | "ipv6" | "domain" | "url" | "sha256" | "sha1" | "md5"

export type ThreatClassification = "malicious" | "benign" | "suspicious" | "unknown"

export interface ThreatIntelResult {
  enrichment_id: string
  incident_id: string
  ioc_type: IOCType
  ioc_value: string
  classification: ThreatClassification
  confidence: number // 0-100
  reputation: string
  threat_category: string
  provider: string
  source_count: number
  first_seen?: string | null
  last_seen?: string | null
  tags: string[]
  explanation: string
  lookup_timestamp: string
}

// ---------------------------------------------------------------------------
// AI Investigator (backend/app/models/investigation.py)
// ---------------------------------------------------------------------------

export type FindingType = "OBSERVED" | "INFERRED" | "RECOMMENDED"

export interface FindingItem {
  finding_type: FindingType
  description: string
  evidence: string[]
}

export interface InvestigationTimelineItem {
  timestamp: string
  event_type: string
  description: string
  source_entity?: string | null
}

export interface RecommendedAction {
  action_type: string
  description: string
  target_entity: string
  analyst_approval_required: boolean
  inert_proposed_only: boolean
}

export interface InvestigationResult {
  investigation_id: string
  incident_id: string
  summary: string
  confidence: number // 0.0 - 1.0
  findings: FindingItem[]
  timeline: InvestigationTimelineItem[]
  mitre_techniques: string[]
  threat_intel_summary: Record<string, unknown>
  investigation_gaps: string[]
  recommended_next_steps: string[]
  possible_response_actions: RecommendedAction[]
  provider: string
  model_name: string
  generated_at: string
}

export interface InvestigateRequest {
  force?: boolean
}

// ---------------------------------------------------------------------------
// Case Management (backend/app/models/cases.py)
// ---------------------------------------------------------------------------

export type CaseStatus = "open" | "in_progress" | "pending" | "resolved" | "closed"
export type CasePriority = "critical" | "high" | "medium" | "low"
export type EvidenceType = "event" | "alert" | "correlation" | "incident" | "investigation" | "threat_intel" | "artifact"

export interface EvidenceReference {
  evidence_id: string
  case_id: string
  evidence_type: EvidenceType
  reference_key: string
  description: string
  added_by: string
  added_at: string
}

export interface CaseNote {
  note_id: string
  case_id: string
  author: string
  content: string
  created_at: string
  updated_at: string
}

export interface CaseResolution {
  summary: string
  root_cause: string
  action_taken: string
  resolved_by: string
  resolved_at: string
}

export interface CaseTimelineEntry {
  timestamp: string
  action: string
  actor: string
  description: string
  metadata: Record<string, string>
}

export interface Case {
  case_id: string
  title: string
  description: string
  severity: number // 0-15
  priority: CasePriority
  status: CaseStatus
  assignee?: string | null
  created_at: string
  updated_at: string
  first_seen?: string | null
  last_seen?: string | null
  incident_ids: string[]
  investigation_ids: string[]
  tags: string[]
  notes: CaseNote[]
  evidence_references: EvidenceReference[]
  resolution?: CaseResolution | null
}

export interface CaseCreateRequest {
  title: string
  description: string
  severity: number
  priority?: CasePriority
  incident_id?: string | null
  tags?: string[]
  actor?: string
}

export interface CaseUpdateRequest {
  title?: string
  description?: string
  priority?: CasePriority
  tags?: string[]
  actor?: string
}

export interface CaseAssignRequest {
  assignee?: string | null
  actor?: string
}

export interface CaseStatusTransitionRequest {
  new_status: CaseStatus
  reason?: string | null
  actor?: string
}

export interface CaseResolveRequest {
  summary: string
  root_cause?: string
  action_taken?: string
  resolver?: string
}

export interface CaseNoteCreateRequest {
  content: string
  author?: string
}

export interface EvidenceLinkRequest {
  evidence_type: EvidenceType
  reference_key: string
  description?: string
  added_by?: string
}

// ---------------------------------------------------------------------------
// Controlled Response (backend/app/models/response.py)
// ---------------------------------------------------------------------------

export type ResponseActionStatus = "proposed" | "approved" | "executed" | "failed" | "rejected"

export type ResponseActionType = "isolate_endpoint" | "quarantine_file" | "revoke_credentials" | "restrict_dataset_access"

export interface ResponseAction {
  action_id: string
  incident_id: string
  action_type: string
  status: ResponseActionStatus
  requested_at: string
  approved_by?: string | null
  executed_at?: string | null
  result?: string | null
}

export interface CreateResponseActionRequest {
  action_type: string
  actor?: string
}

export interface ResponseActorRequest {
  actor: string
}

export interface RejectResponseActionRequest {
  actor: string
  reason?: string | null
}

// ---------------------------------------------------------------------------
// Dataset Security (backend/app/models/dataset.py)
// ---------------------------------------------------------------------------

export type DataFormat = "csv" | "json" | "parquet"
export type SensitivityLevel = "LOW" | "MEDIUM" | "HIGH" | "CRITICAL"
export type PIIType = "NONE" | "EMAIL" | "PHONE" | "CREDIT_CARD" | "SSN" | "CUSTOM"

export interface ColumnProfile {
  name: string
  data_type: string
  is_nullable: boolean
  is_sensitive: boolean
  pii_type: PIIType
  sensitivity: SensitivityLevel
  distinct_values?: number | null
  metadata: Record<string, unknown>
}

export interface DatasetAsset {
  dataset_id: string
  name: string
  format: DataFormat
  file_path: string
  size_bytes: number
  record_count: number
  column_count: number
  columns: ColumnProfile[]
  sensitive_columns: string[]
  sensitivity: SensitivityLevel
  schema_hash?: string | null
  created_at: string
  updated_at: string
  metadata: Record<string, unknown>
}

export interface DatasetActivity {
  activity_id: string
  timestamp: string
  dataset_id: string
  dataset_name: string
  operation: string
  actor: string
  actor_host?: string | null
  source_ip?: string | null
  destination_ip?: string | null
  records_accessed: number
  records_modified: number
  sensitive_columns: string[]
  export_size_bytes: number
  export_destination?: string | null
  context: Record<string, unknown>
}

// ---------------------------------------------------------------------------
// Dataset Security Assessment (v2.0)
// ---------------------------------------------------------------------------

export type FindingSeverity = "INFO" | "LOW" | "MEDIUM" | "HIGH" | "CRITICAL"

export interface DatasetFinding {
  finding_id: string
  severity: FindingSeverity
  title: string
  description: string
  affected_columns: string[]
  recommendation: string
  evidence_summary: string
}

export interface SecurityCheckResult {
  check_name: string
  passed: boolean
  severity: FindingSeverity
  detail: string
}

export interface DatasetSecurityScore {
  score: number // 0-100
  risk_level: string // LOW / MEDIUM / HIGH / CRITICAL
  contributing_factors: string[]
}

export interface DatasetSecurityAssessment {
  assessment_id: string
  dataset_id: string
  dataset_name: string
  asset: DatasetAsset
  findings: DatasetFinding[]
  security_score: DatasetSecurityScore
  checks_performed: SecurityCheckResult[]
  critical_findings: number
  high_findings: number
  medium_findings: number
  low_findings: number
  info_findings: number
  assessed_at: string
  disclaimer: string
}

export interface DatasetUploadResult {
  success: boolean
  dataset_id: string
  assessment: DatasetSecurityAssessment
  registered: boolean
  temp_file_cleaned: boolean
  message: string
}

export interface DatasetSimulationResult {
  dataset_id: string
  dataset_name: string
  events_generated: number
  alerts_created: number
  correlations_created: number
  incidents_created: number
  simulation_actor: string
  simulated_at: string
  pipeline_results: Record<string, unknown>[]
}

export interface SystemSettings {
  profile_name: string
  profile_email: string
  tariff_rates: Record<string, unknown>[]
  shifts: Record<string, unknown>[]
  high_threshold: number
  critical_threshold: number
  updated_at: string
}

export interface SettingsUpdate {
  profile_name?: string
  profile_email?: string
  tariff_rates?: Record<string, unknown>[]
  shifts?: Record<string, unknown>[]
  high_threshold?: number
  critical_threshold?: number
}
