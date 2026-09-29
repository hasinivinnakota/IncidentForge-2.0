import { apiClient } from "./client"
import type { ThreatIntelResult, IOCType } from "./types"

export async function getIncidentThreatIntel(incidentId: string): Promise<ThreatIntelResult[]> {
  return apiClient<ThreatIntelResult[]>(
    `/api/v1/incidents/${encodeURIComponent(incidentId)}/threat-intelligence`
  )
}

export async function getThreatIntelById(enrichmentId: string): Promise<ThreatIntelResult> {
  return apiClient<ThreatIntelResult>(
    `/api/v1/threat-intelligence/${encodeURIComponent(enrichmentId)}`
  )
}

export async function getThreatIntelByIoc(
  iocType: IOCType | string,
  iocValue: string
): Promise<ThreatIntelResult[]> {
  return apiClient<ThreatIntelResult[]>(
    `/api/v1/threat-intelligence/ioc/${encodeURIComponent(iocType)}/${encodeURIComponent(iocValue)}`
  )
}
