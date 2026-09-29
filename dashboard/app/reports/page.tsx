"use client"

import { useState, useEffect } from "react"
import { DashboardLayout } from "@/components/dashboard-layout"
import { ReportGenerator } from "@/components/reports/report-generator"
import { PeakUsageTable } from "@/components/reports/peak-usage-table"
import { EnergyConsumptionChart } from "@/components/reports/energy-consumption-chart"
import { ReportSummary } from "@/components/reports/report-summary"
import { useAppDispatch } from "@/lib/store/hooks"
import { fetchMetersRequest } from "@/lib/store/slices/metersSlice"
import { fetchOverviewDataRequest } from "@/lib/store/slices/overviewSlice"

export type ReportTimeRange = "24h" | "7d" | "30d" | "90d" | "1y"
export type ReportType = "consumption" | "peak-analysis" | "efficiency" | "cost-analysis"

export interface ReportFilters {
  timeRange: ReportTimeRange
  reportType: ReportType
  meterIds: string[]
  dateFrom?: string
  dateTo?: string
}

export default function ReportsPage() {
  const dispatch = useAppDispatch()
  const [reportFilters, setReportFilters] = useState<ReportFilters>({
    timeRange: "7d",
    reportType: "consumption",
    meterIds: [],
  })
  const [isGenerating, setIsGenerating] = useState(false)
  const [reportGenerated, setReportGenerated] = useState(false)

  useEffect(() => {
    // Fetch required data when component mounts
    dispatch(fetchMetersRequest())
    dispatch(fetchOverviewDataRequest())
  }, [dispatch])

  const handleGenerateReport = async (filters: ReportFilters) => {
    setIsGenerating(true)
    setReportFilters(filters)

    // Simulate report generation delay
    await new Promise((resolve) => setTimeout(resolve, 2000))

    setIsGenerating(false)
    setReportGenerated(true)
  }

  return (
    <DashboardLayout>
      <div className="space-y-4 sm:space-y-6">
        {/* Page Header */}
        <div className="px-1">
          <h1 className="text-xl sm:text-2xl font-bold text-[#EDEDED]">Reports</h1>
          <p className="text-sm sm:text-base text-[#9A9A9A] mt-1">
            Generate comprehensive energy consumption and performance reports
          </p>
        </div>

        {/* Report Generator */}
        <div className="w-full">
          <ReportGenerator onGenerateReport={handleGenerateReport} isGenerating={isGenerating} />
        </div>

        {/* Report Results */}
        {reportGenerated && !isGenerating && (
          <div className="space-y-4 sm:space-y-6">
            {/* Report Summary */}
            <div className="w-full">
              <ReportSummary filters={reportFilters} />
            </div>

            {/* Peak Usage Table and Energy Consumption Chart */}
            <div className="grid grid-cols-1 xl:grid-cols-2 gap-4 sm:gap-6">
              <div className="w-full min-w-0">
                <PeakUsageTable timeRange={reportFilters.timeRange} />
              </div>
              <div className="w-full min-w-0">
                <EnergyConsumptionChart timeRange={reportFilters.timeRange} reportType={reportFilters.reportType} />
              </div>
            </div>
          </div>
        )}

        {/* Loading State */}
        {isGenerating && (
          <div className="space-y-4 sm:space-y-6">
            <div className="h-24 sm:h-32 bg-[#1B1B1B] border border-[#2A2A2A] rounded-lg animate-pulse" />
            <div className="grid grid-cols-1 xl:grid-cols-2 gap-4 sm:gap-6">
              <div className="h-64 sm:h-96 bg-[#1B1B1B] border border-[#2A2A2A] rounded-lg animate-pulse" />
              <div className="h-64 sm:h-96 bg-[#1B1B1B] border border-[#2A2A2A] rounded-lg animate-pulse" />
            </div>
          </div>
        )}
      </div>
    </DashboardLayout>
  )
}
