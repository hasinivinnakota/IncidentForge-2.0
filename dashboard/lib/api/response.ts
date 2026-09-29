import { apiClient } from "./client"
import type {
  ResponseAction,
  CreateResponseActionRequest,
  ResponseActorRequest,
  RejectResponseActionRequest,
} from "./types"

export async function listResponseActions(incidentId: string): Promise<ResponseAction[]> {
  return apiClient<ResponseAction[]>(
    `/api/v1/incidents/${encodeURIComponent(incidentId)}/response-actions`
  )
}

export async function createResponseAction(
  incidentId: string,
  data: CreateResponseActionRequest
): Promise<ResponseAction> {
  return apiClient<ResponseAction>(
    `/api/v1/incidents/${encodeURIComponent(incidentId)}/response-actions`,
    {
      method: "POST",
      body: data,
    }
  )
}

export async function getResponseAction(actionId: string): Promise<ResponseAction> {
  return apiClient<ResponseAction>(`/api/v1/response-actions/${encodeURIComponent(actionId)}`)
}

export async function approveResponseAction(
  actionId: string,
  data: ResponseActorRequest = { actor: "analyst" }
): Promise<ResponseAction> {
  return apiClient<ResponseAction>(
    `/api/v1/response-actions/${encodeURIComponent(actionId)}/approve`,
    {
      method: "POST",
      body: data,
    }
  )
}

export async function rejectResponseAction(
  actionId: string,
  data: RejectResponseActionRequest
): Promise<ResponseAction> {
  return apiClient<ResponseAction>(
    `/api/v1/response-actions/${encodeURIComponent(actionId)}/reject`,
    {
      method: "POST",
      body: data,
    }
  )
}

export async function executeResponseAction(
  actionId: string,
  data: ResponseActorRequest = { actor: "analyst" }
): Promise<ResponseAction> {
  return apiClient<ResponseAction>(
    `/api/v1/response-actions/${encodeURIComponent(actionId)}/execute`,
    {
      method: "POST",
      body: data,
    }
  )
}
