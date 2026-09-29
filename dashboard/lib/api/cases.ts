import { apiClient } from "./client"
import type {
  Case,
  CaseCreateRequest,
  CaseUpdateRequest,
  CaseAssignRequest,
  CaseStatusTransitionRequest,
  CaseResolveRequest,
  CaseNote,
  CaseNoteCreateRequest,
  EvidenceReference,
  EvidenceLinkRequest,
  CaseTimelineEntry,
  CaseStatus,
  CasePriority,
} from "./types"

export async function listCases(options?: {
  status?: CaseStatus | string
  priority?: CasePriority | string
  assignee?: string
  limit?: number
}): Promise<Case[]> {
  return apiClient<Case[]>("/api/v1/cases", {
    params: {
      status: options?.status,
      priority: options?.priority,
      assignee: options?.assignee,
      limit: options?.limit,
    },
  })
}

export async function getCase(caseId: string): Promise<Case> {
  return apiClient<Case>(`/api/v1/cases/${encodeURIComponent(caseId)}`)
}

export async function createCase(data: CaseCreateRequest): Promise<Case> {
  return apiClient<Case>("/api/v1/cases", {
    method: "POST",
    body: data,
  })
}

export async function updateCase(caseId: string, data: CaseUpdateRequest): Promise<Case> {
  return apiClient<Case>(`/api/v1/cases/${encodeURIComponent(caseId)}`, {
    method: "PATCH",
    body: data,
  })
}

export async function assignCase(caseId: string, data: CaseAssignRequest): Promise<Case> {
  return apiClient<Case>(`/api/v1/cases/${encodeURIComponent(caseId)}/assign`, {
    method: "POST",
    body: data,
  })
}

export async function transitionCaseStatus(
  caseId: string,
  data: CaseStatusTransitionRequest
): Promise<Case> {
  return apiClient<Case>(`/api/v1/cases/${encodeURIComponent(caseId)}/status`, {
    method: "POST",
    body: data,
  })
}

export async function resolveCase(caseId: string, data: CaseResolveRequest): Promise<Case> {
  return apiClient<Case>(`/api/v1/cases/${encodeURIComponent(caseId)}/resolve`, {
    method: "POST",
    body: data,
  })
}

export async function addCaseNote(caseId: string, data: CaseNoteCreateRequest): Promise<CaseNote> {
  return apiClient<CaseNote>(`/api/v1/cases/${encodeURIComponent(caseId)}/notes`, {
    method: "POST",
    body: data,
  })
}

export async function listCaseNotes(caseId: string, limit?: number): Promise<CaseNote[]> {
  return apiClient<CaseNote[]>(`/api/v1/cases/${encodeURIComponent(caseId)}/notes`, {
    params: { limit },
  })
}

export async function linkCaseEvidence(
  caseId: string,
  data: EvidenceLinkRequest
): Promise<EvidenceReference> {
  return apiClient<EvidenceReference>(`/api/v1/cases/${encodeURIComponent(caseId)}/evidence`, {
    method: "POST",
    body: data,
  })
}

export async function getCaseTimeline(caseId: string): Promise<CaseTimelineEntry[]> {
  return apiClient<CaseTimelineEntry[]>(`/api/v1/cases/${encodeURIComponent(caseId)}/timeline`)
}
