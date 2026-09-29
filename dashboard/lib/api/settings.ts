import { apiClient } from "./client"
import type { SystemSettings, SettingsUpdate } from "./types"

export async function get(): Promise<SystemSettings> {
  return apiClient<SystemSettings>("/api/v1/settings")
}

export async function update(payload: SettingsUpdate): Promise<SystemSettings> {
  return apiClient<SystemSettings>("/api/v1/settings", {
    method: "PATCH",
    body: payload,
  })
}

export const settingsApi = {
  get,
  update,
}
