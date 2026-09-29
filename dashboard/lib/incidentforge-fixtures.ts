export type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW"

export const metrics = [
  { label: "Active Alerts", value: "247", delta: "+12.4%", detail: "vs. previous 24h", tone: "orange", icon: "activity" },
  { label: "Active Incidents", value: "18", delta: "+3", detail: "requiring investigation", tone: "amber", icon: "shield" },
  { label: "Critical Incidents", value: "04", delta: "2 new", detail: "in the last hour", tone: "red", icon: "alert" },
  { label: "Open Cases", value: "31", delta: "-8.1%", detail: "vs. previous 7d", tone: "emerald", icon: "briefcase" },
] as const

export const activity = [
  { time: "00:00", alerts: 32, incidents: 3, correlations: 12 }, { time: "02:00", alerts: 21, incidents: 2, correlations: 9 },
  { time: "04:00", alerts: 26, incidents: 2, correlations: 14 }, { time: "06:00", alerts: 39, incidents: 4, correlations: 19 },
  { time: "08:00", alerts: 56, incidents: 6, correlations: 27 }, { time: "10:00", alerts: 47, incidents: 5, correlations: 24 },
  { time: "12:00", alerts: 68, incidents: 8, correlations: 34 }, { time: "14:00", alerts: 61, incidents: 7, correlations: 31 },
  { time: "16:00", alerts: 77, incidents: 9, correlations: 42 }, { time: "18:00", alerts: 54, incidents: 6, correlations: 26 },
  { time: "20:00", alerts: 81, incidents: 10, correlations: 46 }, { time: "22:00", alerts: 73, incidents: 8, correlations: 39 },
]

export const severityDistribution = [
  { name: "Critical", value: 4, color: "#ef4444" }, { name: "High", value: 18, color: "#f97316" },
  { name: "Medium", value: 76, color: "#f59e0b" }, { name: "Low", value: 149, color: "#34d399" },
]

export const incidents = [
  { id: "INC-8F42A1", severity: "CRITICAL" as Severity, title: "Authentication attack", detection: "Brute Force / MFA Fatigue", risk: 92, status: "INVESTIGATING", firstSeen: "21:32:08", entity: "ENG-LT-042" },
  { id: "INC-8F419C", severity: "HIGH" as Severity, title: "Suspicious process execution", detection: "EDR Behavioral", risk: 81, status: "CONTAINED", firstSeen: "20:58:44", entity: "FIN-SRV-07" },
  { id: "INC-8F3E20", severity: "HIGH" as Severity, title: "Network connection anomaly", detection: "NDR / DNS", risk: 74, status: "INVESTIGATING", firstSeen: "19:44:12", entity: "DMZ-WEB-03" },
  { id: "INC-8F3D0A", severity: "MEDIUM" as Severity, title: "Privilege escalation", detection: "Identity Analytics", risk: 63, status: "OPEN", firstSeen: "18:21:36", entity: "CORP-DC-01" },
  { id: "INC-8F3A88", severity: "MEDIUM" as Severity, title: "Multi-stage attack", detection: "Correlation Engine", risk: 58, status: "OPEN", firstSeen: "17:08:51", entity: "MKT-LT-119" },
]

export const liveAlerts = [
  ["21:42:18", "CRITICAL", "Authentication attack detected", "ENG-LT-042"],
  ["21:41:52", "HIGH", "Suspicious process execution", "FIN-SRV-07"],
  ["21:40:31", "MEDIUM", "Network anomaly detected", "DMZ-WEB-03"],
  ["21:39:09", "LOW", "Unusual DNS query pattern", "CORP-LT-221"],
  ["21:38:44", "HIGH", "Impossible travel detected", "user@acme.io"],
] as const

export const timeline = [
  { time: "21:32:08", type: "EVENT", title: "Multiple failed authentication attempts", description: "47 failed sign-in attempts from 185.220.101.14 against 6 identities.", severity: "HIGH" },
  { time: "21:33:14", type: "ALERT", title: "Authentication attack detected", description: "Detection rule AUTH-042 matched credential stuffing and MFA fatigue signals.", severity: "CRITICAL" },
  { time: "21:34:02", type: "CORRELATION", title: "Related endpoint activity correlated", description: "Suspicious PowerShell execution observed on ENG-LT-042 within 90 seconds.", severity: "HIGH" },
  { time: "21:35:47", type: "INCIDENT", title: "Incident created by correlation engine", description: "Multi-signal incident INC-8F42A1 opened for analyst investigation.", severity: "CRITICAL" },
  { time: "21:36:12", type: "ML RISK", title: "Risk score calculated: 92/100", description: "Model confidence 96%. Multiple MITRE techniques increased risk score.", severity: "CRITICAL" },
  { time: "21:38:26", type: "THREAT INTEL", title: "IOC reputation enriched", description: "185.220.101.14 matched 4 threat intelligence sources.", severity: "HIGH" },
]

export const iocs = [
  { value: "185.220.101.14", type: "IPv4", reputation: "MALICIOUS", confidence: "98%", source: "AbuseIPDB · 4 feeds", firstSeen: "21:32:08" },
  { value: "auth-sync[.]cloud", type: "Domain", reputation: "SUSPICIOUS", confidence: "87%", source: "VirusTotal · 2 feeds", firstSeen: "21:34:11" },
  { value: "b7e3c1...4a09f2", type: "SHA256", reputation: "UNKNOWN", confidence: "—", source: "Internal sandbox", firstSeen: "21:35:02" },
]

export const pipeline = ["EVENT", "DETECTION", "ALERT", "CORRELATION", "INCIDENT", "ML RISK", "THREAT INTEL", "AI INVESTIGATION", "CASE", "RESPONSE"]

export const commandItems = ["Go to Overview", "Search incidents", "Open AI Investigator", "View threat intelligence", "Open response queue"]

export const mitreTechniques = [
  { name: "Credential Access", value: 84 }, { name: "Execution", value: 68 }, { name: "Discovery", value: 53 },
  { name: "Persistence", value: 41 }, { name: "Defense Evasion", value: 36 }, { name: "Lateral Movement", value: 24 },
]

export const incidentStatus = [
  { name: "Open", value: 7, color: "#f59e0b" }, { name: "Investigating", value: 6, color: "#ff6a00" },
  { name: "Resolved", value: 3, color: "#34d399" }, { name: "Closed", value: 2, color: "#64748b" },
]

export const affectedHosts = [
  ["ENG-LT-042", "42", "3", "92"], ["FIN-SRV-07", "31", "2", "81"], ["DMZ-WEB-03", "24", "1", "74"], ["CORP-DC-01", "18", "1", "63"],
] as const

export const investigationQueue = [
  ["INC-8F42A1", "92", "AI analyzing", "A. Morgan"], ["INC-8F419C", "81", "Pending review", "J. Patel"], ["INC-8F3E20", "74", "Evidence gap", "Unassigned"],
] as const
