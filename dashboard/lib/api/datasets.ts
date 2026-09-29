/**
 * IncidentForge Dataset Security API client
 *
 * Provides typed access to all dataset-related endpoints:
 *  - List, get, register datasets
 *  - Upload + security assessment (multipart)
 *  - Re-run security assessment
 *  - Per-dataset attack simulation
 *  - Dataset activity log
 */

import { getApiBaseUrl, ApiError } from "./client"
import type {
  DatasetAsset,
  DatasetActivity,
  DatasetUploadResult,
  DatasetSecurityAssessment,
  DatasetSimulationResult,
} from "./types"

const DEFAULT_TIMEOUT_MS = 60_000 // upload can take up to 60s

// ---------------------------------------------------------------------------
// Helper: raw fetch for multipart uploads (cannot use JSON client)
// ---------------------------------------------------------------------------

async function fetchWithTimeout(url: string, options: RequestInit, timeoutMs = DEFAULT_TIMEOUT_MS): Promise<Response> {
  const controller = new AbortController()
  const timer = setTimeout(() => controller.abort(), timeoutMs)
  try {
    return await fetch(url, { ...options, signal: controller.signal })
  } catch (err) {
    if (err instanceof Error && err.name === "AbortError") {
      throw new ApiError(`Upload timed out after ${timeoutMs / 1000}s`, 408)
    }
    throw new ApiError(
      err instanceof Error ? err.message : "Network error or API offline",
      0
    )
  } finally {
    clearTimeout(timer)
  }
}

async function parseErrorBody(response: Response): Promise<string> {
  try {
    const data = await response.json()
    if (data && typeof data.detail === "string") return data.detail
    if (data && Array.isArray(data.detail)) return data.detail.map((e: any) => e.msg).join("; ")
    return response.statusText || `HTTP ${response.status}`
  } catch {
    return response.statusText || `HTTP ${response.status}`
  }
}

// ---------------------------------------------------------------------------
// Typed API client methods
// ---------------------------------------------------------------------------

/**
 * List all registered datasets.
 */
export async function listDatasets(limit = 100): Promise<DatasetAsset[]> {
  const url = `${getApiBaseUrl()}/api/v1/data-assets?limit=${limit}`
  const resp = await fetchWithTimeout(url, { method: "GET", headers: { Accept: "application/json" } })
  if (!resp.ok) throw new ApiError(await parseErrorBody(resp), resp.status)
  return resp.json()
}

/**
 * Get a specific registered dataset by ID.
 */
export async function getDataset(assetId: string): Promise<DatasetAsset> {
  const url = `${getApiBaseUrl()}/api/v1/data-assets/${encodeURIComponent(assetId)}`
  const resp = await fetchWithTimeout(url, { method: "GET", headers: { Accept: "application/json" } })
  if (!resp.ok) throw new ApiError(await parseErrorBody(resp), resp.status)
  return resp.json()
}

/**
 * Get the detailed column schema profile for a registered dataset.
 * Does NOT return raw row data.
 */
export async function getDatasetProfile(assetId: string): Promise<Record<string, unknown>> {
  const url = `${getApiBaseUrl()}/api/v1/data-assets/${encodeURIComponent(assetId)}/profile`
  const resp = await fetchWithTimeout(url, { method: "GET", headers: { Accept: "application/json" } })
  if (!resp.ok) throw new ApiError(await parseErrorBody(resp), resp.status)
  return resp.json()
}

/**
 * List recent activity events for a dataset.
 */
export async function getDatasetActivity(assetId: string, limit = 50): Promise<DatasetActivity[]> {
  const url = `${getApiBaseUrl()}/api/v1/data-assets/${encodeURIComponent(assetId)}/activity?limit=${limit}`
  const resp = await fetchWithTimeout(url, { method: "GET", headers: { Accept: "application/json" } })
  if (!resp.ok) throw new ApiError(await parseErrorBody(resp), resp.status)
  return resp.json()
}

/**
 * Upload a dataset file (CSV, JSON, or Parquet) for security assessment.
 *
 * The raw file is processed temporarily on the backend and immediately deleted
 * after profiling. Only sanitized metadata is registered.
 *
 * @param file         - File object selected by the user
 * @param displayName  - Optional human-readable name for the dataset
 * @returns            - Full DatasetUploadResult with assessment and findings
 */
export async function uploadDataset(
  file: File,
  displayName?: string
): Promise<DatasetUploadResult> {
  // Validate extension client-side before sending (fast feedback)
  const allowedExtensions = new Set(["csv", "json", "jsonl", "parquet"])
  const ext = file.name.split(".").pop()?.toLowerCase() ?? ""
  if (!allowedExtensions.has(ext)) {
    throw new ApiError(
      `Unsupported file format ".${ext}". Allowed: CSV, JSON, JSONL, Parquet`,
      415
    )
  }

  // Client-side size guard (50 MB) — server also enforces this
  const MAX_BYTES = 50 * 1024 * 1024
  if (file.size > MAX_BYTES) {
    throw new ApiError(`File exceeds the 50 MB upload limit (${(file.size / 1024 / 1024).toFixed(1)} MB)`, 413)
  }

  if (file.size === 0) {
    throw new ApiError("File is empty. Please select a valid dataset file.", 400)
  }

  const formData = new FormData()
  formData.append("file", file)
  if (displayName?.trim()) {
    formData.append("display_name", displayName.trim())
  }

  const url = `${getApiBaseUrl()}/api/v1/data-assets/upload`
  const resp = await fetchWithTimeout(
    url,
    { method: "POST", body: formData, headers: { Accept: "application/json" } },
    DEFAULT_TIMEOUT_MS
  )

  if (!resp.ok) {
    const msg = await parseErrorBody(resp)
    throw new ApiError(msg, resp.status)
  }

  return resp.json()
}

/**
 * Re-run the security assessment on a registered dataset.
 * Uses only stored metadata — no raw file needed.
 */
export async function assessDataset(assetId: string): Promise<DatasetSecurityAssessment> {
  const url = `${getApiBaseUrl()}/api/v1/data-assets/${encodeURIComponent(assetId)}/assess`
  const resp = await fetchWithTimeout(url, {
    method: "POST",
    headers: { Accept: "application/json", "Content-Type": "application/json" },
  })
  if (!resp.ok) throw new ApiError(await parseErrorBody(resp), resp.status)
  return resp.json()
}

/**
 * Simulate a suspicious dataset access attack for a registered dataset.
 * Generates synthetic telemetry through the existing SOC pipeline.
 * All data is clearly synthetic.
 */
export async function simulateDatasetAttack(assetId: string): Promise<DatasetSimulationResult> {
  const url = `${getApiBaseUrl()}/api/v1/data-assets/${encodeURIComponent(assetId)}/simulate`
  const resp = await fetchWithTimeout(url, {
    method: "POST",
    headers: { Accept: "application/json", "Content-Type": "application/json" },
  })
  if (!resp.ok) throw new ApiError(await parseErrorBody(resp), resp.status)
  return resp.json()
}

/**
 * Run the global expo demo simulation (original endpoint, dataset-agnostic).
 */
export async function simulateDemoAttack(): Promise<unknown[]> {
  const url = `${getApiBaseUrl()}/api/v1/data-assets/simulate`
  const resp = await fetchWithTimeout(url, {
    method: "POST",
    headers: { Accept: "application/json", "Content-Type": "application/json" },
  })
  if (!resp.ok) throw new ApiError(await parseErrorBody(resp), resp.status)
  return resp.json()
}
