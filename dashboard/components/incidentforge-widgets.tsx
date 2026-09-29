"use client"

import { useState, type ReactNode } from "react"
import { Activity, Bot, CheckCircle2, CircleDot, Database, ShieldAlert, ShieldCheck, TriangleAlert, Wifi } from "lucide-react"
import { Cell, Line, LineChart, Pie, PieChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts"
import type { Incident, Alert, Case } from "@/lib/api/types"

type PanelProps = { title: string; subtitle?: string; children: ReactNode; className?: string }
export function Panel({ title, subtitle, children, className = "" }: PanelProps) {
  return (
    <section className={`min-w-0 rounded-xl border border-white/[0.08] bg-[#111111] shadow-[0_12px_32px_rgba(0,0,0,.18)] transition-colors duration-200 ${className}`}>
      <div className="border-b border-white/[0.07] px-4 py-3">
        <h2 className="text-[11px] font-bold uppercase tracking-[0.16em] text-white">{title}</h2>
        {subtitle && <p className="mt-1 text-[10px] text-zinc-500">{subtitle}</p>}
      </div>
      {children}
    </section>
  )
}

export function MitrePanel({ incidents = [], alerts = [] }: { incidents?: Incident[]; alerts?: Alert[] }) {
  // Aggregate techniques from live incidents & alerts
  const techniqueCounts: Record<string, number> = {}
  for (const inc of incidents) {
    for (const t of inc.mitre_techniques || []) {
      techniqueCounts[t] = (techniqueCounts[t] || 0) + 1
    }
  }
  for (const al of alerts) {
    for (const t of al.mitre_techniques || []) {
      techniqueCounts[t] = (techniqueCounts[t] || 0) + 1
    }
  }

  const items = Object.entries(techniqueCounts)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 6)
    .map(([name, count]) => ({ name, value: count }))

  return (
    <Panel title="MITRE ATT&CK ACTIVITY" subtitle="Technique activity across monitored infrastructure">
      <div className="space-y-2 p-4">
        {items.length === 0 ? (
          <div className="flex h-28 items-center justify-center text-[10px] text-zinc-500">
            No active MITRE ATT&CK techniques detected
          </div>
        ) : (
          items.map((item, index) => {
            const maxVal = Math.max(...items.map((i) => i.value), 1)
            const pct = Math.round((item.value / maxVal) * 100)
            return (
              <div key={item.name} className="grid grid-cols-[140px_1fr_28px] items-center gap-3 text-[10px]">
                <span className="truncate text-zinc-400" title={item.name}>
                  {item.name}
                </span>
                <div className="h-2 bg-black">
                  <div
                    className="h-full bg-[#ff6500]"
                    style={{ width: `${pct}%`, opacity: 0.58 + index * 0.06 }}
                  />
                </div>
                <span className="text-right font-mono text-orange-200">{item.value}</span>
              </div>
            )
          })
        )}
      </div>
    </Panel>
  )
}

export function IncidentStatusPanel({ incidents = [] }: { incidents?: Incident[] }) {
  const counts = {
    Critical: 0,
    High: 0,
    Medium: 0,
    Low: 0,
  }

  for (const inc of incidents) {
    if (inc.severity >= 12) counts.Critical += 1
    else if (inc.severity >= 8) counts.High += 1
    else if (inc.severity >= 4) counts.Medium += 1
    else counts.Low += 1
  }

  const incidentStatusData = [
    { name: "Critical", value: counts.Critical, color: "#ef4444" },
    { name: "High", value: counts.High, color: "#f97316" },
    { name: "Medium", value: counts.Medium, color: "#f59e0b" },
    { name: "Low", value: counts.Low, color: "#34d399" },
  ]

  const total = incidents.length

  return (
    <Panel title="INCIDENT SEVERITY" subtitle="Current distribution by severity">
      <div className="grid grid-cols-[140px_1fr] items-center gap-2 p-3">
        <div className="h-[132px]">
          {total === 0 ? (
            <div className="flex h-full items-center justify-center text-[10px] text-zinc-600">
              0 Incidents
            </div>
          ) : (
            <ResponsiveContainer width="100%" height="100%">
              <PieChart className="rounded-[24px]">
                <Pie
                  data={incidentStatusData.filter((d) => d.value > 0)}
                  dataKey="value"
                  innerRadius={38}
                  outerRadius={58}
                  paddingAngle={3}
                  stroke="none"
                >
                  {incidentStatusData.map((item) => (
                    <Cell key={item.name} fill={item.color} />
                  ))}
                </Pie>
              </PieChart>
            </ResponsiveContainer>
          )}
        </div>
        <div className="space-y-2">
          {incidentStatusData.map((item) => (
            <div key={item.name} className="flex items-center justify-between text-[10px]">
              <span className="flex items-center gap-2 text-zinc-400">
                <i className="h-2 w-2 rounded-full" style={{ background: item.color }} />
                {item.name}
              </span>
              <span className="font-mono text-white">{item.value}</span>
            </div>
          ))}
        </div>
      </div>
    </Panel>
  )
}

export function SystemStatusPanel({ isOnline = false }: { isOnline?: boolean }) {
  const rows = [
    ["Detection engine", ShieldCheck],
    ["Event pipeline", Activity],
    ["Threat intel", Database],
    ["AI investigator", Bot],
  ] as const

  return (
    <Panel title="SYSTEM STATUS">
      <div className="divide-y divide-white/[0.06]">
        {rows.map(([label, Icon]) => (
          <div key={label} className="flex items-center justify-between px-4 py-3 text-[10px]">
            <span className="flex items-center gap-2 text-zinc-400">
              <Icon size={13} className="text-orange-400" />
              {label}
            </span>
            <span className={`flex items-center gap-1 ${isOnline ? "text-emerald-400" : "text-amber-400"}`}>
              <i className={`h-1.5 w-1.5 rounded-full ${isOnline ? "bg-emerald-400 shadow-[0_0_8px_#34d399]" : "bg-amber-400"}`} />
              {isOnline ? "ONLINE" : "STANDBY"}
            </span>
          </div>
        ))}
      </div>
    </Panel>
  )
}

export function InvestigationQueuePanel({
  cases = [],
  openIncident,
}: {
  cases?: Case[]
  openIncident?: (id: string) => void
}) {
  return (
    <Panel title="INVESTIGATION QUEUE" subtitle="Cases requiring analyst attention">
      <div className="divide-y divide-white/[0.06]">
        {cases.length === 0 ? (
          <div className="flex h-36 items-center justify-center text-[10px] text-zinc-500">
            No open cases in investigation queue
          </div>
        ) : (
          cases.slice(0, 4).map((c) => {
            const riskPct = Math.min(100, Math.round((c.severity / 15) * 100))
            const targetIncident = c.incident_ids && c.incident_ids[0]
            return (
              <div
                key={c.case_id}
                onClick={() => targetIncident && openIncident?.(targetIncident)}
                className={`grid grid-cols-[1fr_40px] gap-2 px-4 py-3 transition hover:bg-white/[0.02] ${targetIncident ? "cursor-pointer" : ""}`}
              >
                <div>
                  <div className="flex justify-between text-[10px]">
                    <span className="font-mono text-orange-200">{c.title || c.case_id}</span>
                    <span className="text-zinc-600">{c.assignee || "Unassigned"}</span>
                  </div>
                  <div className="mt-1 flex items-center gap-2 text-[10px] text-zinc-500">
                    <span className="h-1.5 flex-1 bg-black">
                      <span className="block h-full bg-orange-600" style={{ width: `${riskPct}%` }} />
                    </span>
                    <span className="uppercase">{c.status}</span>
                  </div>
                </div>
                <span className="font-mono text-right text-orange-200">{riskPct}</span>
              </div>
            )
          })
        )}
      </div>
    </Panel>
  )
}

export function RiskCurvePanel({
  data,
  currentRisk = 0,
  peakRisk = 0,
}: {
  data: Array<{ time: string; risk: number; threshold: number }>
  currentRisk?: number
  peakRisk?: number
}) {
  return (
    <Panel title="INCIDENT RISK CURVE" subtitle="Risk score distribution over timeline">
      <div className="h-[190px] p-3">
        <ResponsiveContainer width="100%" height="100%">
          <LineChart data={data}>
            <XAxis dataKey="time" tick={{ fill: "#71717a", fontSize: 9 }} axisLine={false} tickLine={false} />
            <YAxis domain={[0, 100]} tick={{ fill: "#71717a", fontSize: 9 }} axisLine={false} tickLine={false} width={24} />
            <Tooltip contentStyle={{ background: "#0b0b0b", border: "1px solid #4b210c", fontSize: 10 }} />
            <Line type="monotone" dataKey="threshold" stroke="#7c3f1b" strokeDasharray="4 4" dot={false} />
            <Line type="monotone" dataKey="risk" stroke="#ff6500" strokeWidth={2} dot={false} />
          </LineChart>
        </ResponsiveContainer>
      </div>
      <div className="grid grid-cols-3 gap-2 border-t border-white/[0.06] p-3 text-center text-[9px]">
        <div>
          <b className="block font-mono text-orange-200">{currentRisk}</b>Current Risk
        </div>
        <div>
          <b className="block font-mono text-orange-100">{peakRisk}</b>Peak Risk
        </div>
        <div>
          <b className="block font-mono text-zinc-500">65</b>Threshold
        </div>
      </div>
    </Panel>
  )
}

export const StatusIcon = { online: Wifi, healthy: CheckCircle2, alert: ShieldAlert } as const
