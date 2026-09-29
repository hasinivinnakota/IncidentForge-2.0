"use client"

import { usePathname } from "next/navigation"
import { SidebarTrigger } from "@/components/ui/sidebar"

export function DashboardHeader() {
  const pathname = usePathname()

  const getPageTitle = () => {
    switch (pathname) {
      case "/":
        return "Overview"
      case "/meters":
        return "Meters"
      case "/reports":
        return "Reports"
      case "/settings":
        return "Settings"
      default:
        return "Dashboard"
    }
  }

  return (
    <header className="flex items-center gap-4 border-b border-[#2A2A2A] bg-[#1B1B1B] px-6 py-4">
      <SidebarTrigger className="text-[#EDEDED] hover:bg-[#FF6B00]/20" />
      <h1 className="text-xl font-semibold text-[#EDEDED]">{getPageTitle()}</h1>
    </header>
  )
}
