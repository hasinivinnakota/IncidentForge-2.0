import { apiClient } from "./client"
import type { Alert } from "./types"

export async function listAlerts(options?: {
  limit?: number
  eventId?: string
}): Promise<Alert[]> {
  return apiClient<Alert[]>("/api/v1/alerts", {
    params: {
      limit: options?.limit,
      event_id: options?.eventId,
    },
  })
}

export async function getAlert(alertId: string): Promise<Alert> {
  return apiClient<Alert>(`/api/v1/alerts/${encodeURIComponent(alertId)}`)
}
