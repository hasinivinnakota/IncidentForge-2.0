"use client"

import type React from "react"

import { useState, useEffect } from "react"
import { Responsive, WidthProvider, type Layouts } from "react-grid-layout"
import { useMediaQuery } from "@/hooks/use-media-query"

const ResponsiveGridLayout = WidthProvider(Responsive)

const initialLayouts: Layouts = {
  lg: [
    { i: "kpis", x: 0, y: 0, w: 12, h: 1.5, static: true },
    { i: "trend", x: 0, y: 1.5, w: 8, h: 4 },
    { i: "breakdown", x: 8, y: 1.5, w: 4, h: 4 },
    { i: "load-curve", x: 0, y: 5.5, w: 12, h: 4.5 },
    { i: "heatmap", x: 0, y: 10, w: 12, h: 4.5 },
    { i: "peak-analysis", x: 0, y: 14.5, w: 8, h: 3.5 },
    { i: "alerts", x: 8, y: 14.5, w: 4, h: 3.5 },
  ],
  md: [
    { i: "kpis", x: 0, y: 0, w: 10, h: 1.5, static: true },
    { i: "trend", x: 0, y: 1.5, w: 10, h: 4 },
    { i: "load-curve", x: 0, y: 5.5, w: 10, h: 4.5 },
    { i: "heatmap", x: 0, y: 10, w: 10, h: 4.5 },
    { i: "breakdown", x: 0, y: 14.5, w: 5, h: 4 },
    { i: "peak-analysis", x: 5, y: 14.5, w: 5, h: 3.5 },
    { i: "alerts", x: 0, y: 18.5, w: 10, h: 3.5 },
  ],
  sm: [
    { i: "kpis", x: 0, y: 0, w: 6, h: 3, static: true },
    { i: "trend", x: 0, y: 3, w: 6, h: 4 },
    { i: "load-curve", x: 0, y: 7, w: 6, h: 4.5 },
    { i: "heatmap", x: 0, y: 11.5, w: 6, h: 4.5 },
    { i: "breakdown", x: 0, y: 16, w: 6, h: 4 },
    { i: "peak-analysis", x: 0, y: 20, w: 6, h: 3.5 },
    { i: "alerts", x: 0, y: 23.5, w: 6, h: 3.5 },
  ],
}

interface DraggableDashboardLayoutProps {
  children: React.ReactNode[]
}

export function DraggableDashboardLayout({ children }: DraggableDashboardLayoutProps) {
  const [layouts, setLayouts] = useState<Layouts>(initialLayouts)
  const [isMounted, setIsMounted] = useState(false)
  const isMobile = useMediaQuery("(max-width: 768px)")

  useEffect(() => {
    setIsMounted(true)
  }, [])

  const onLayoutChange = (_: any, newLayouts: Layouts) => {
    setLayouts(newLayouts)
  }

  if (!isMounted) {
    return (
      <div className="space-y-6">
        <div className="h-36 bg-[#1B1B1B] border border-[#2A2A2A] rounded-lg animate-pulse" />
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          <div className="lg:col-span-2 h-96 bg-[#1B1B1B] border border-[#2A2A2A] rounded-lg animate-pulse" />
          <div className="lg:col-span-1 h-96 bg-[#1B1B1B] border border-[#2A2A2A] rounded-lg animate-pulse" />
        </div>
      </div>
    )
  }

  return (
    <ResponsiveGridLayout
      layouts={layouts}
      onLayoutChange={onLayoutChange}
      breakpoints={{ lg: 1200, md: 996, sm: 768, xs: 480, xxs: 0 }}
      cols={{ lg: 12, md: 10, sm: 6, xs: 4, xxs: 2 }}
      rowHeight={80}
      isDraggable={!isMobile}
      isResizable={!isMobile}
      containerPadding={[0, 0]}
      margin={[24, 24]}
    >
      {children}
    </ResponsiveGridLayout>
  )
}
