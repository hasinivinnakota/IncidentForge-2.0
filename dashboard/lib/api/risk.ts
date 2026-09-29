import { apiClient } from "./client"
import type { RiskAssessment } from "./types"

export async function getIncidentRisk(incidentId: string): Promise<RiskAssessment> {
  return apiClient<RiskAssessment>(`/api/v1/incidents/${encodeURIComponent(incidentId)}/risk`)
}

export async function getRiskAssessment(assessmentId: string): Promise<RiskAssessment> {
  return apiClient<RiskAssessment>(`/api/v1/risk-assessments/${encodeURIComponent(assessmentId)}`)
}
