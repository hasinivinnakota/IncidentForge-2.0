import { apiClient } from "./client"
import type { Incident, IncidentStatus, IncidentStatusUpdate } from "./types"

export async function listIncidents(options?: {
  status?: IncidentStatus | string
  correlationId?: string
  severity?: number
  limit?: number
}): Promise<Incident[]> {
  return apiClient<Incident[]>("/api/v1/incidents", {
    params: {
      status: options?.status,
      correlation_id: options?.correlationId,
      severity: options?.severity,
      limit: options?.limit,
    },
  })
}

export async function getIncident(incidentId: string): Promise<Incident> {
  return apiClient<Incident>(`/api/v1/incidents/${encodeURIComponent(incidentId)}`)
}

export async function updateIncidentStatus(
  incidentId: string,
  newStatus: IncidentStatus
): Promise<Incident> {
  const body: IncidentStatusUpdate = { status: newStatus }
  return apiClient<Incident>(`/api/v1/incidents/${encodeURIComponent(incidentId)}/status`, {
    method: "PATCH",
    body,
  })
}
