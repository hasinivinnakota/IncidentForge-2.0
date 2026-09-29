import { apiClient } from "./client"
import type { HealthResponse } from "./types"

export async function checkHealth(): Promise<HealthResponse> {
  return apiClient<HealthResponse>("/health", { timeoutMs: 5000 })
}
