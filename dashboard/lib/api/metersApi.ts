import type { MeterData } from "../store/types"

const delay = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms))

const mockMeterDatabase: Record<string, MeterData> = {
  "MTR-001": {
    id: "MTR-001",
    name: "Main Distribution Panel",
    location: "Building A - Ground Floor",
    type: "3-Phase Digital",
    status: "online",
    lastReading: "2 min ago",
    currentLoad: 85,
    efficiency: 94,
    kpiData: {
      voltage: { l1: "220.5", l2: "224.7", l3: "218.6" },
      current: { l1: "98.2", l2: "113.5", l3: "100.1" },
      activePower: "21.6",
      powerFactor: "0.92",
      frequency: "50.0",
      energyToday: "518",
      costToday: "$62.16",
      temperature: "42°C",
    },
    powerProfile: [15, 18, 16, 22, 19, 25, 14, 17, 21, 26, 32, 38, 42, 40, 35, 33, 45, 38, 28, 29, 22, 24, 20, 17],
    loadDistribution: { l1: 33.3, l2: 32.9, l3: 33.8 },
    monthlyConsumption: Array.from({ length: 30 }, () => 400 + Math.random() * 200),
    powerQuality: {
      voltageStability: 98.5,
      frequencyStability: 99.2,
      powerFactor: 92.0,
      harmonicDistortion: 96.2,
    },
    comparison: {
      current: 21.6,
      previous: 19.8,
      efficiency: 94,
      cost: 259.2,
      trend: "up",
    },
    alerts: [
      {
        id: "1",
        message: "Voltage within normal operating range",
        severity: "success",
        timestamp: "1 min ago",
        parameter: "Voltage L1",
        value: "220.5V",
        threshold: "220V ±5%",
      },
      {
        id: "2",
        message: "Current imbalance detected between phases",
        severity: "error",
        timestamp: "12 min ago",
        parameter: "Phase Imbalance",
        value: "8.2%",
        threshold: "< 5%",
      },
    ],
    hourlyBreakdown: Array.from({ length: 24 }, (_, i) => ({
      hour: `${i.toString().padStart(2, "0")}:00`,
      base: 10 + Math.random() * 5,
      peak: i > 8 && i < 20 ? Math.random() * 15 : 0,
      auxiliary: 2 + Math.random() * 3,
    })),
    powerSpikes: Array.from({ length: 168 }, (_, i) => ({
      time: new Date(Date.now() - i * 60 * 60 * 1000).toISOString(),
      rate: 0.001 + Math.random() * 0.0015 + (Math.random() > 0.95 ? Math.random() * 0.005 : 0),
    })),
  },
  "MTR-002": {
    id: "MTR-002",
    name: "HVAC System Meter",
    location: "Building A - Roof",
    type: "Single Phase",
    status: "online",
    lastReading: "1 min ago",
    currentLoad: 67,
    efficiency: 89,
    kpiData: {
      voltage: { l1: "230.2", l2: "0", l3: "0" },
      current: { l1: "45.8", l2: "0", l3: "0" },
      activePower: "10.5",
      powerFactor: "0.88",
      frequency: "50.1",
      energyToday: "252",
      costToday: "$30.24",
      temperature: "38°C",
    },
    powerProfile: [8, 9, 8, 10, 9, 12, 15, 18, 22, 25, 28, 30, 32, 30, 28, 26, 24, 20, 18, 15, 12, 10, 9, 8],
    loadDistribution: { l1: 100, l2: 0, l3: 0 },
    monthlyConsumption: Array.from({ length: 30 }, () => 200 + Math.random() * 150),
    powerQuality: {
      voltageStability: 97.8,
      frequencyStability: 98.9,
      powerFactor: 88.0,
      harmonicDistortion: 94.5,
    },
    comparison: {
      current: 10.5,
      previous: 12.1,
      efficiency: 89,
      cost: 126.0,
      trend: "down",
    },
    alerts: [
      {
        id: "1",
        message: "HVAC system operating efficiently",
        severity: "success",
        timestamp: "3 min ago",
        parameter: "System Status",
        value: "Normal",
        threshold: "Optimal Range",
      },
      {
        id: "2",
        message: "Power factor below optimal threshold",
        severity: "warning",
        timestamp: "5 min ago",
        parameter: "Power Factor",
        value: "0.88",
        threshold: "> 0.90",
      },
    ],
    hourlyBreakdown: Array.from({ length: 24 }, (_, i) => ({
      hour: `${i.toString().padStart(2, "0")}:00`,
      base: 10 + Math.random() * 5,
      peak: i > 8 && i < 20 ? Math.random() * 15 : 0,
      auxiliary: 2 + Math.random() * 3,
    })),
    powerSpikes: Array.from({ length: 168 }, (_, i) => ({
      time: new Date(Date.now() - i * 60 * 60 * 1000).toISOString(),
      rate: 0.001 + Math.random() * 0.0015 + (Math.random() > 0.95 ? Math.random() * 0.005 : 0),
    })),
  },
}

export const metersApi = {
  async fetchAllMeters(): Promise<MeterData[]> {
    await delay(800)
    if (Math.random() < 0.05) {
      throw new Error("Failed to fetch meters data")
    }
    return Object.values(mockMeterDatabase)
  },

  async fetchMeterById(meterId: string): Promise<MeterData> {
    await delay(500)
    const meter = mockMeterDatabase[meterId]
    if (!meter) {
      throw new Error(`Meter with ID ${meterId} not found`)
    }
    const updatedMeter = {
      ...meter,
      lastReading: "Just now",
      timestamp: new Date().toISOString(),
      currentLoad: Math.max(0, meter.currentLoad + (Math.random() - 0.5) * 10),
      kpiData: {
        ...meter.kpiData,
        activePower: (Number.parseFloat(meter.kpiData.activePower) + (Math.random() - 0.5) * 2).toFixed(1),
      },
    }
    return updatedMeter
  },

  async createMeter(meterData: Omit<MeterData, "id">): Promise<MeterData> {
    await delay(600)
    const newId = `MTR-${String(Object.keys(mockMeterDatabase).length + 1).padStart(3, "0")}`
    const newMeter: MeterData = { ...meterData, id: newId }
    mockMeterDatabase[newId] = newMeter
    return newMeter
  },

  async updateMeter(meterId: string, updates: Partial<MeterData>): Promise<MeterData> {
    await delay(600)
    const meter = mockMeterDatabase[meterId]
    if (!meter) {
      throw new Error(`Meter with ID ${meterId} not found`)
    }
    const updatedMeter = { ...meter, ...updates }
    mockMeterDatabase[meterId] = updatedMeter
    return updatedMeter
  },

  async deleteMeter(meterId: string): Promise<{ id: string }> {
    await delay(600)
    if (!mockMeterDatabase[meterId]) {
      throw new Error("Meter not found")
    }
    delete mockMeterDatabase[meterId]
    return { id: meterId }
  },

  async fetchRealtimeData(meterId: string): Promise<Partial<MeterData>> {
    await delay(200)
    const meter = mockMeterDatabase[meterId]
    if (!meter) {
      throw new Error(`Meter with ID ${meterId} not found`)
    }
    return {
      currentLoad: Math.max(0, meter.currentLoad + (Math.random() - 0.5) * 5),
      lastReading: "Just now",
      timestamp: new Date().toISOString(),
      kpiData: {
        ...meter.kpiData,
        activePower: (Number.parseFloat(meter.kpiData.activePower) + (Math.random() - 0.5) * 1).toFixed(1),
        current: {
          l1: (Number.parseFloat(meter.kpiData.current.l1) + (Math.random() - 0.5) * 5).toFixed(1),
          l2: (Number.parseFloat(meter.kpiData.current.l2) + (Math.random() - 0.5) * 5).toFixed(1),
          l3: (Number.parseFloat(meter.kpiData.current.l3) + (Math.random() - 0.5) * 5).toFixed(1),
        },
      },
    }
  },
}
