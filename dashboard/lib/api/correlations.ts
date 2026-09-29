import { apiClient } from "./client"
import type { Correlation } from "./types"

export async function listCorrelations(options?: {
  status?: string
  alertId?: string
  eventId?: string
  limit?: number
}): Promise<Correlation[]> {
  return apiClient<Correlation[]>("/api/v1/correlations", {
    params: {
      status: options?.status,
      alert_id: options?.alertId,
      event_id: options?.eventId,
      limit: options?.limit,
    },
  })
}

export async function getCorrelation(correlationId: string): Promise<Correlation> {
  return apiClient<Correlation>(`/api/v1/correlations/${encodeURIComponent(correlationId)}`)
}
