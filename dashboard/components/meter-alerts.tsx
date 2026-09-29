import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { AlertTriangle, CheckCircle, Info, AlertCircle, XCircle, Clock } from "lucide-react"
import { useSelectedMeter } from "@/lib/store/hooks"

interface MeterAlert {
  id: string
  message: string
  severity: "success" | "info" | "warning" | "error"
  timestamp: string
  parameter: string
  value: string
  threshold: string
}

interface MeterAlertsProps {
  selectedMeterId: string
}

const getSeverityConfig = (severity: string) => {
  switch (severity) {
    case "success":
      return {
        bg: "bg-green-600/20",
        border: "border-green-600/30",
        icon: CheckCircle,
        iconColor: "text-green-400",
        textColor: "text-green-100",
      }
    case "info":
      return {
        bg: "bg-blue-600/20",
        border: "border-blue-600/30",
        icon: Info,
        iconColor: "text-blue-400",
        textColor: "text-blue-100",
      }
    case "warning":
      return {
        bg: "bg-orange-600/20",
        border: "border-orange-600/30",
        icon: AlertCircle,
        iconColor: "text-orange-400",
        textColor: "text-orange-100",
      }
    case "error":
      return {
        bg: "bg-red-600/20",
        border: "border-red-600/30",
        icon: XCircle,
        iconColor: "text-red-400",
        textColor: "text-red-100",
      }
    default:
      return {
        bg: "bg-gray-600/20",
        border: "border-gray-600/30",
        icon: AlertTriangle,
        iconColor: "text-gray-400",
        textColor: "text-gray-100",
      }
  }
}

export function MeterAlerts() {
  const selectedMeter = useSelectedMeter()

  if (!selectedMeter) {
    return <div className="text-[#9A9A9A]">No meter selected</div>
  }

  const meterAlerts = selectedMeter.alerts
  const criticalCount = meterAlerts.filter((alert) => alert.severity === "error").length
  const warningCount = meterAlerts.filter((alert) => alert.severity === "warning").length

  return (
    <Card className="bg-[#1B1B1B] border-[#2A2A2A] text-[#EDEDED] h-full flex flex-col">
      <CardHeader className="pb-3 pt-4 px-4 sm:px-6">
        <CardTitle className="flex items-center justify-between text-lg font-semibold text-[#EDEDED]">
          <div className="flex items-center gap-3">
            <AlertTriangle className="h-5 w-5 text-[#FF6B00]" />
            Meter Alerts
            {criticalCount > 0 && (
              <span className="bg-red-600 text-white text-xs px-2 py-0.5 rounded-full font-medium">
                {criticalCount} Critical
              </span>
            )}
          </div>
          <div className="hidden sm:flex items-center gap-2 text-sm font-normal text-[#9A9A9A]">
            <Clock className="h-4 w-4" />
            {selectedMeter.id}
          </div>
        </CardTitle>
      </CardHeader>

      <CardContent className="px-4 sm:px-6 pb-4 flex-1 flex flex-col min-h-0">
        <div className="space-y-2 flex-1 overflow-y-auto pr-2 -mr-2">
          {meterAlerts.map((alert) => {
            const config = getSeverityConfig(alert.severity)
            const IconComponent = config.icon

            return (
              <div
                key={alert.id}
                className={`flex items-start gap-2 p-2 rounded-lg border ${config.bg} ${config.border}`}
              >
                <div className="flex-shrink-0 mt-0.5">
                  <IconComponent className={`h-4 w-4 ${config.iconColor}`} />
                </div>

                <div className="flex-1 min-w-0">
                  <div className={`text-sm ${config.textColor} leading-tight mb-1 font-medium`}>{alert.message}</div>

                  <div className="flex items-center justify-between text-xs text-[#9A9A9A]">
                    <span>
                      {alert.parameter}: <span className={`font-semibold ${config.textColor}`}>{alert.value}</span>
                    </span>
                    <span>{alert.timestamp}</span>
                  </div>
                </div>
              </div>
            )
          })}
        </div>

        {/* Alert summary */}
        <div className="mt-3 pt-3 border-t border-[#2A2A2A] grid grid-cols-2 sm:grid-cols-4 gap-2">
          <div className="text-center p-2 bg-[#0E0E0E]/30 rounded-lg">
            <div className="text-base font-bold text-red-400">{criticalCount}</div>
            <div className="text-xs text-[#9A9A9A]">Critical</div>
          </div>
          <div className="text-center p-2 bg-[#0E0E0E]/30 rounded-lg">
            <div className="text-base font-bold text-orange-400">{warningCount}</div>
            <div className="text-xs text-[#9A9A9A]">Warning</div>
          </div>
          <div className="text-center p-2 bg-[#0E0E0E]/30 rounded-lg">
            <div className="text-base font-bold text-blue-400">
              {meterAlerts.filter((alert) => alert.severity === "info").length}
            </div>
            <div className="text-xs text-[#9A9A9A]">Info</div>
          </div>
          <div className="text-center p-2 bg-[#0E0E0E]/30 rounded-lg">
            <div className="text-base font-bold text-green-400">
              {meterAlerts.filter((alert) => alert.severity === "success").length}
            </div>
            <div className="text-xs text-[#9A9A9A]">Normal</div>
          </div>
        </div>
      </CardContent>
    </Card>
  )
}
