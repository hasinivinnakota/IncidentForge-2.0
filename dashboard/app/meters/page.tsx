"use client"

import { useEffect } from "react"
import { DashboardLayout } from "@/components/dashboard-layout"
import { MeterDropdownSelector } from "@/components/meter-dropdown-selector"
import { MeterInsights } from "@/components/meter-insights"
import { useAppDispatch, useSelectedMeterId } from "@/lib/store/hooks"
import { fetchMetersRequest } from "@/lib/store/slices/metersSlice"

export default function MetersPage() {
  const dispatch = useAppDispatch()
  const selectedMeterId = useSelectedMeterId()

  useEffect(() => {
    // Fetch meters data when component mounts
    dispatch(fetchMetersRequest())
  }, [dispatch])

  return (
    <DashboardLayout>
      <div className="space-y-6">
        {/* Meter Selection */}
        <MeterDropdownSelector />

        {/* Meter Insights */}
        {selectedMeterId && <MeterInsights />}
      </div>
    </DashboardLayout>
  )
}
