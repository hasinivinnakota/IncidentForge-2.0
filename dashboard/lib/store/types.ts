export interface User {
  id: string
  name: string
  email: string
  role: "admin" | "user"
  createdAt: string
}

export interface UsersState {
  users: User[]
  loading: boolean
  error: string | null
}

export interface MeterData {
  id: string
  name: string
  location: string
  type: string
  status: "online" | "offline" | "maintenance"
  lastReading: string
  timestamp?: string
  currentLoad: number
  efficiency: number
  kpiData: {
    voltage: { l1: string; l2: string; l3: string }
    current: { l1: string; l2: string; l3: string }
    activePower: string
    powerFactor: string
    frequency: string
    energyToday: string
    costToday: string
    temperature: string
  }
  powerProfile: number[]
  loadDistribution: { l1: number; l2: number; l3: number }
  monthlyConsumption: number[]
  powerQuality: {
    voltageStability: number
    frequencyStability: number
    powerFactor: number
    harmonicDistortion: number
  }
  comparison: {
    current: number
    previous: number
    efficiency: number
    cost: number
    trend: "up" | "down"
  }
  alerts: Array<{
    id: string
    message: string
    severity: "success" | "info" | "warning" | "error"
    timestamp: string
    parameter: string
    value: string
    threshold: string
  }>
  hourlyBreakdown: { hour: string; base: number; peak: number; auxiliary: number }[]
  powerSpikes: { time: string; rate: number }[]
}

export interface MetersState {
  meters: MeterData[]
  selectedMeterId: string | null
  selectedMeterData: MeterData | null
  loading: boolean
  error: string | null
}

export interface OverviewData {
  kpis: {
    totalConsumption: { value: number; trend: number }
    peakDemand: { value: number; trend: number }
    energyCost: { value: number; trend: number }
    co2Emissions: { value: number; trend: number }
  }
  energyTrend: {
    "24h": { time: string; consumption: number }[]
    "7d": { date: string; consumption: number }[]
    "30d": { date: string; consumption: number }[]
  }
  peakUsage: { hour: string; consumption: number }[]
  consumptionBreakdown: { name: string; value: number; color: string }[]
  periodComparison: {
    consumption: { change: number; period: string }
    cost: { change: number; period: string }
    demand: { change: number; period: string }
  }
  alerts: Array<{
    id: string
    message: string
    severity: "critical" | "warning" | "info"
    timestamp: string
  }>
}

export interface OverviewState {
  data: OverviewData | null
  loading: boolean
  error: string | null
}
