"use client"

import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card"
import { AlertTriangle, Info, AlertCircle, Bell } from "lucide-react"
import { useOverviewData } from "@/lib/store/hooks"

const getSeverityConfig = (severity: "critical" | "warning" | "info") => {
  switch (severity) {
    case "critical":
      return { icon: AlertCircle, color: "text-red-400", bg: "bg-red-600/10" }
    case "warning":
      return { icon: AlertTriangle, color: "text-orange-400", bg: "bg-orange-600/10" }
    case "info":
      return { icon: Info, color: "text-blue-400", bg: "bg-blue-600/10" }
  }
}

export function SystemAlertsWidget() {
  const data = useOverviewData()

  if (!data) {
    return <div className="h-[200px] bg-[#1B1B1B] border border-[#2A2A2A] rounded-lg animate-pulse" />
  }

  const criticalCount = data.alerts.filter((alert) => alert.severity === "critical").length
  const warningCount = data.alerts.filter((alert) => alert.severity === "warning").length
  const infoCount = data.alerts.filter((alert) => alert.severity === "info").length
  const totalAlerts = data.alerts.length

  return (
    <Card className="bg-[#1B1B1B] border-[#2A2A2A] text-[#EDEDED]">
      <CardHeader>
        <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
          <div>
            <CardTitle className="flex items-center gap-2">
              <Bell className="h-5 w-5 text-[#FF6B00]" />
              Active System Alerts
            </CardTitle>
            <CardDescription className="text-[#9A9A9A] mt-1">
              Real-time system notifications and status updates across all meters.
            </CardDescription>
          </div>
          <div className="flex items-center gap-4 text-sm">
            <div className="bg-red-600/10 px-3 py-2 rounded-lg text-center">
              <div className="text-lg font-bold text-red-400">{criticalCount}</div>
              <div className="text-xs text-[#9A9A9A]">Critical</div>
            </div>
            <div className="bg-orange-600/10 px-3 py-2 rounded-lg text-center">
              <div className="text-lg font-bold text-orange-400">{warningCount}</div>
              <div className="text-xs text-[#9A9A9A]">Warning</div>
            </div>
            <div className="bg-blue-600/10 px-3 py-2 rounded-lg text-center">
              <div className="text-lg font-bold text-blue-400">{infoCount}</div>
              <div className="text-xs text-[#9A9A9A]">Info</div>
            </div>
          </div>
        </div>
      </CardHeader>
      <CardContent>
        {/* Alert List - Horizontal Layout */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
          {data.alerts.map((alert) => {
            const { icon: Icon, color, bg } = getSeverityConfig(alert.severity)
            return (
              <div
                key={alert.id}
                className={`flex items-start gap-3 p-4 rounded-lg ${bg} transition-all hover:scale-[1.02]`}
              >
                <Icon className={`h-4 w-4 mt-0.5 flex-shrink-0 ${color}`} />
                <div className="flex-1 min-w-0">
                  <p className="text-sm text-[#EDEDED] leading-tight font-medium">{alert.message}</p>
                  <p className="text-xs text-[#9A9A9A] mt-1">{alert.timestamp}</p>
                </div>
              </div>
            )
          })}
        </div>

        {/* Summary Stats */}
        <div className="mt-6 pt-4 border-t border-[#2A2A2A]">
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
            <div className="bg-[#0E0E0E]/50 p-3 rounded-lg text-center">
              <div className="text-lg font-bold text-[#FF6B00]">{criticalCount + warningCount}</div>
              <div className="text-xs text-[#9A9A9A]">Needs Action</div>
            </div>
            <div className="bg-[#0E0E0E]/50 p-3 rounded-lg text-center">
              <div className="text-lg font-bold text-[#EDEDED]">{totalAlerts}</div>
              <div className="text-xs text-[#9A9A9A]">Total Alerts</div>
            </div>
            <div className="bg-[#0E0E0E]/50 p-3 rounded-lg text-center">
              <div className="text-lg font-bold text-green-400">{((infoCount / totalAlerts) * 100).toFixed(0)}%</div>
              <div className="text-xs text-[#9A9A9A]">Informational</div>
            </div>
            <div className="bg-[#0E0E0E]/50 p-3 rounded-lg text-center">
              <div className="text-lg font-bold text-[#EDEDED]">
                {data.alerts.filter((a) => a.timestamp.includes("min")).length}
              </div>
              <div className="text-xs text-[#9A9A9A]">Recent</div>
            </div>
          </div>
        </div>
      </CardContent>
    </Card>
  )
}
