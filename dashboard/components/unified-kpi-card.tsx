import React from "react"
import type { ReactNode } from "react"
import { Card, CardContent, CardHeader } from "@/components/ui/card"
import { TrendingUp, TrendingDown, Activity } from "lucide-react"

interface UnifiedKpiCardProps {
  title: string
  value: string
  unit?: string
  trend?: {
    direction: "up" | "down" | "neutral"
    percentage: string
    period: string
  }
  icon: ReactNode
  emphasis?: "primary" | "secondary" | "tertiary"
  progress?: number
  sparklineData?: number[]
}

export function UnifiedKpiCard({
  title,
  value,
  unit,
  trend,
  icon,
  emphasis = "secondary",
  progress,
  sparklineData,
}: UnifiedKpiCardProps) {
  const getEmphasisStyles = () => {
    switch (emphasis) {
      case "primary":
        return {
          background: "bg-gradient-to-br from-[#FF6B00] to-[#E55A00]",
          iconBg: "bg-white/25",
          progressBg: "bg-white/20",
          progressFill: "bg-white",
          sparkline: "bg-white/30 hover:bg-white/40",
          shadow: "shadow-[#FF6B00]/20",
        }
      case "secondary":
        return {
          background: "bg-gradient-to-br from-[#FF6B00]/85 to-[#E55A00]/85",
          iconBg: "bg-white/20",
          progressBg: "bg-white/15",
          progressFill: "bg-white/90",
          sparkline: "bg-white/25 hover:bg-white/35",
          shadow: "shadow-[#FF6B00]/15",
        }
      case "tertiary":
        return {
          background: "bg-gradient-to-br from-[#FF6B00]/70 to-[#E55A00]/70",
          iconBg: "bg-white/15",
          progressBg: "bg-white/10",
          progressFill: "bg-white/80",
          sparkline: "bg-white/20 hover:bg-white/30",
          shadow: "shadow-[#FF6B00]/10",
        }
      default:
        return {
          background: "bg-gradient-to-br from-[#FF6B00]/85 to-[#E55A00]/85",
          iconBg: "bg-white/20",
          progressBg: "bg-white/15",
          progressFill: "bg-white/90",
          sparkline: "bg-white/25 hover:bg-white/35",
          shadow: "shadow-[#FF6B00]/15",
        }
    }
  }

  const styles = getEmphasisStyles()

  const getTrendIcon = () => {
    if (!trend) return null

    switch (trend.direction) {
      case "up":
        return <TrendingUp className="h-3 w-3 text-white/90" />
      case "down":
        return <TrendingDown className="h-3 w-3 text-white/90" />
      default:
        return <Activity className="h-3 w-3 text-white/90" />
    }
  }

  return (
    <Card
      className={`${styles.background} text-white border-0 shadow-lg ${styles.shadow} hover:shadow-xl transition-all duration-300 group hover:scale-[1.02] backdrop-blur-sm`}
    >
      <CardHeader className="pb-2 pt-4 px-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div
              className={`p-2 ${styles.iconBg} rounded-xl backdrop-blur-sm group-hover:bg-white/30 transition-colors`}
            >
              {React.cloneElement(icon as React.ReactElement, {
                className: "h-4 w-4 text-white",
              })}
            </div>
            <h3 className="text-sm font-semibold text-white/90">{title}</h3>
          </div>

          {trend && (
            <div className="flex items-center gap-1 bg-white/15 px-2 py-1 rounded-full backdrop-blur-sm">
              {getTrendIcon()}
              <span className="text-xs font-medium text-white/90">{trend.percentage}</span>
            </div>
          )}
        </div>
      </CardHeader>

      <CardContent className="px-4 pb-4">
        <div className="space-y-3">
          {/* Main value */}
          <div className="flex items-baseline gap-2">
            <span className="text-2xl font-bold text-white leading-none">{value}</span>
            {unit && <span className="text-sm text-white/70 font-medium">{unit}</span>}
          </div>

          {/* Progress bar */}
          {progress !== undefined && (
            <div className="space-y-1">
              <div className="flex justify-between text-xs text-white/70">
                <span>Progress</span>
                <span>{progress}%</span>
              </div>
              <div className={`w-full ${styles.progressBg} rounded-full h-2`}>
                <div
                  className={`${styles.progressFill} h-2 rounded-full transition-all duration-700 ease-out`}
                  style={{ width: `${progress}%` }}
                />
              </div>
            </div>
          )}

          {/* Sparkline */}
          {sparklineData && (
            <div className="h-8 flex items-end justify-between gap-0.5">
              {sparklineData.map((value, index) => (
                <div
                  key={index}
                  className={`${styles.sparkline} rounded-sm flex-1 transition-all duration-300`}
                  style={{
                    height: `${Math.max(4, (value / Math.max(...sparklineData)) * 24)}px`,
                  }}
                />
              ))}
            </div>
          )}

          {/* Trend info */}
          {trend && (
            <div className="text-xs text-white/70">
              <span>{trend.direction === "up" ? "↗" : trend.direction === "down" ? "↘" : "→"}</span>
              <span className="ml-1">{trend.period}</span>
            </div>
          )}
        </div>
      </CardContent>
    </Card>
  )
}
