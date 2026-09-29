import type { OverviewData } from "../store/types"

const delay = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms))

const mockOverviewData: OverviewData = {
  kpis: {
    totalConsumption: { value: 12456, trend: 2.5 },
    peakDemand: { value: 876, trend: -1.2 },
    energyCost: { value: 1494.72, trend: 2.5 },
    co2Emissions: { value: 6228, trend: 2.5 },
  },
  energyTrend: {
    "24h": Array.from({ length: 24 }, (_, i) => ({
      time: `${i.toString().padStart(2, "0")}:00`,
      consumption: 450 + Math.random() * 200 + (i > 8 && i < 20 ? i * 15 : 0),
    })),
    "7d": Array.from({ length: 7 }, (_, i) => ({
      date: new Date(Date.now() - (6 - i) * 86400000).toLocaleDateString("en-US", { weekday: "short" }),
      consumption: 11000 + Math.random() * 3000,
    })),
    "30d": Array.from({ length: 30 }, (_, i) => ({
      date: new Date(Date.now() - (29 - i) * 86400000).toLocaleDateString("en-US", {
        month: "short",
        day: "numeric",
      }),
      consumption: 10000 + Math.random() * 4000,
    })),
  },
  peakUsage: Array.from({ length: 24 }, (_, i) => ({
    hour: `${i.toString().padStart(2, "0")}`,
    consumption: 100 + Math.random() * 100 + (i > 10 && i < 18 ? Math.random() * 200 : 0),
  })),
  consumptionBreakdown: [
    { name: "Production", value: 45, color: "hsl(var(--chart-1))" },
    { name: "HVAC", value: 25, color: "hsl(var(--chart-2))" },
    { name: "Lighting", value: 15, color: "hsl(var(--chart-3))" },
    { name: "Office", value: 10, color: "hsl(var(--chart-4))" },
    { name: "Other", value: 5, color: "hsl(var(--chart-5))" },
  ],
  periodComparison: {
    consumption: { change: 5.2, period: "vs last week" },
    cost: { change: 4.8, period: "vs last week" },
    demand: { change: -2.1, period: "vs last week" },
  },
  alerts: [
    { id: "1", message: "Critical voltage drop on Main Feeder 2", severity: "critical", timestamp: "2m ago" },
    { id: "2", message: "Phase B current approaching limit", severity: "warning", timestamp: "15m ago" },
    { id: "3", message: "HVAC system efficiency below threshold", severity: "warning", timestamp: "45m ago" },
    { id: "4", message: "Network connection to MTR-004 restored", severity: "info", timestamp: "1h ago" },
  ],
}

export const overviewApi = {
  async fetchOverviewData(): Promise<OverviewData> {
    await delay(1000)
    if (Math.random() < 0.03) {
      throw new Error("Failed to fetch overview data")
    }
    return JSON.parse(JSON.stringify(mockOverviewData)) // Deep copy
  },
}
