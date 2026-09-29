/**
 * IncidentForge centralized API client
 */

export class ApiError extends Error {
  public status: number
  public details?: unknown

  constructor(message: string, status: number, details?: unknown) {
    super(message)
    this.name = "ApiError"
    this.status = status
    this.details = details
  }
}

const DEFAULT_BASE_URL = ""

export function getApiBaseUrl(): string {
  if (typeof process !== "undefined" && process.env.NEXT_PUBLIC_API_BASE_URL) {
    return process.env.NEXT_PUBLIC_API_BASE_URL.replace(/\/+$/, "")
  }
  // Use relative URLs to go through Next.js rewrites proxy (avoids CORS)
  if (typeof window !== "undefined") {
    return ""
  }
  return "http://127.0.0.1:8000"
}

interface RequestOptions extends Omit<RequestInit, "body"> {
  params?: Record<string, string | number | boolean | undefined | null>
  body?: unknown
  timeoutMs?: number
}

export async function apiClient<T>(endpoint: string, options: RequestOptions = {}): Promise<T> {
  const { params, body, headers, timeoutMs = 15000, ...fetchOptions } = options
  const baseUrl = getApiBaseUrl()

  let url = `${baseUrl}${endpoint.startsWith("/") ? endpoint : `/${endpoint}`}`

  if (params) {
    const searchParams = new URLSearchParams()
    for (const [key, value] of Object.entries(params)) {
      if (value !== undefined && value !== null) {
        searchParams.append(key, String(value))
      }
    }
    const queryString = searchParams.toString()
    if (queryString) {
      url += (url.includes("?") ? "&" : "?") + queryString
    }
  }

  const controller = new AbortController()
  const timer = setTimeout(() => controller.abort(), timeoutMs)

  try {
    const response = await fetch(url, {
      ...fetchOptions,
      headers: {
        "Content-Type": "application/json",
        Accept: "application/json",
        ...headers,
      },
      body: body !== undefined ? JSON.stringify(body) : undefined,
      signal: controller.signal,
    })

    if (!response.ok) {
      let errorData: unknown
      try {
        errorData = await response.json()
      } catch {
        errorData = await response.text()
      }

      const errorMessage =
        (typeof errorData === "object" && errorData && "detail" in errorData
          ? String((errorData as { detail: unknown }).detail)
          : response.statusText) || `Request failed with status ${response.status}`

      throw new ApiError(errorMessage, response.status, errorData)
    }

    // Handle 204 No Content
    if (response.status === 204) {
      return {} as T
    }

    return (await response.json()) as T
  } catch (err: unknown) {
    if (err instanceof ApiError) {
      throw err
    }
    if (err instanceof Error && err.name === "AbortError") {
      throw new ApiError(`Request timeout after ${timeoutMs}ms`, 408)
    }
    throw new ApiError(
      err instanceof Error ? err.message : "Network error or API server unavailable",
      0
    )
  } finally {
    clearTimeout(timer)
  }
}
