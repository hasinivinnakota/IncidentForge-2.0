export interface Meter {
  id: string
  name: string
  type: string
  location: string
  status: "active" | "inactive" | "maintenance"
  lastReading: number
  unit: string
  installDate: string
}

export const demoMeters: Meter[] = [
  {
    id: "MTR-001",
    name: "Main Building - Floor 1",
    type: "Electric",
    location: "Building A - Floor 1",
    status: "active",
    lastReading: 1250.5,
    unit: "kWh",
    installDate: "2023-01-15",
  },
  {
    id: "MTR-002",
    name: "Main Building - Floor 2",
    type: "Electric",
    location: "Building A - Floor 2",
    status: "active",
    lastReading: 980.3,
    unit: "kWh",
    installDate: "2023-01-15",
  },
  {
    id: "MTR-003",
    name: "Main Building - Floor 3",
    type: "Electric",
    location: "Building A - Floor 3",
    status: "active",
    lastReading: 1100.7,
    unit: "kWh",
    installDate: "2023-01-15",
  },
  {
    id: "MTR-004",
    name: "Warehouse - East Wing",
    type: "Electric",
    location: "Warehouse - East",
    status: "active",
    lastReading: 2150.8,
    unit: "kWh",
    installDate: "2023-02-10",
  },
  {
    id: "MTR-005",
    name: "Warehouse - West Wing",
    type: "Electric",
    location: "Warehouse - West",
    status: "maintenance",
    lastReading: 1890.2,
    unit: "kWh",
    installDate: "2023-02-10",
  },
  {
    id: "MTR-006",
    name: "Parking Garage - Level 1",
    type: "Electric",
    location: "Parking - L1",
    status: "active",
    lastReading: 450.6,
    unit: "kWh",
    installDate: "2023-03-05",
  },
  {
    id: "MTR-007",
    name: "Parking Garage - Level 2",
    type: "Electric",
    location: "Parking - L2",
    status: "active",
    lastReading: 380.9,
    unit: "kWh",
    installDate: "2023-03-05",
  },
  {
    id: "MTR-008",
    name: "HVAC System - North",
    type: "Electric",
    location: "Rooftop - North",
    status: "active",
    lastReading: 3200.4,
    unit: "kWh",
    installDate: "2023-01-20",
  },
  {
    id: "MTR-009",
    name: "HVAC System - South",
    type: "Electric",
    location: "Rooftop - South",
    status: "active",
    lastReading: 3150.7,
    unit: "kWh",
    installDate: "2023-01-20",
  },
  {
    id: "MTR-010",
    name: "Data Center - Server Room",
    type: "Electric",
    location: "Basement - Server Room",
    status: "active",
    lastReading: 5500.2,
    unit: "kWh",
    installDate: "2023-01-10",
  },
  {
    id: "MTR-011",
    name: "Cafeteria - Kitchen",
    type: "Electric",
    location: "Building A - Cafeteria",
    status: "active",
    lastReading: 850.3,
    unit: "kWh",
    installDate: "2023-02-15",
  },
  {
    id: "MTR-012",
    name: "Emergency Lighting",
    type: "Electric",
    location: "Building A - Emergency",
    status: "active",
    lastReading: 120.5,
    unit: "kWh",
    installDate: "2023-01-25",
  },
]

export const getMeterById = (id: string): Meter | undefined => {
  return demoMeters.find((meter) => meter.id === id)
}

export const getMetersByType = (type: string): Meter[] => {
  return demoMeters.filter((meter) => meter.type === type)
}

export const getActiveMeter = (): Meter[] => {
  return demoMeters.filter((meter) => meter.status === "active")
}
