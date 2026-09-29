import { apiClient } from "./client"
import type { InvestigationResult, InvestigateRequest } from "./types"

export async function triggerInvestigation(
  incidentId: string,
  request?: InvestigateRequest
): Promise<InvestigationResult> {
  return apiClient<InvestigationResult>(
    `/api/v1/incidents/${encodeURIComponent(incidentId)}/investigate`,
    {
      method: "POST",
      body: request || {},
      timeoutMs: 30000,
    }
  )
}

export async function getIncidentInvestigation(
  incidentId: string
): Promise<InvestigationResult> {
  return apiClient<InvestigationResult>(
    `/api/v1/incidents/${encodeURIComponent(incidentId)}/investigation`
  )
}

export async function getInvestigationById(
  investigationId: string
): Promise<InvestigationResult> {
  return apiClient<InvestigationResult>(
    `/api/v1/investigations/${encodeURIComponent(investigationId)}`
  )
}
