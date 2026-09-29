"use client"

import { usePathname } from "next/navigation"
import { Home, Activity, Settings, User, FileText } from "lucide-react"
import {
  Sidebar,
  SidebarContent,
  SidebarFooter,
  SidebarGroup,
  SidebarGroupContent,
  SidebarHeader,
  SidebarMenu,
  SidebarMenuButton,
  SidebarMenuItem,
} from "@/components/ui/sidebar"

const menuItems = [
  {
    title: "Overview",
    url: "/",
    icon: Home,
  },
  {
    title: "Meters",
    url: "/meters",
    icon: Activity,
  },
  {
    title: "Reports",
    url: "/reports",
    icon: FileText,
  },
  {
    title: "Settings",
    url: "/settings",
    icon: Settings,
  },
]

export function AppSidebar() {
  const pathname = usePathname()

  return (
    <Sidebar className="border-r border-[#2A2A2A] bg-[#1B1B1B]">
      <SidebarHeader className="p-6">
        <div className="flex items-center justify-center w-full h-16 bg-[#FF6B00] rounded-lg">
          <span className="text-black font-bold text-lg">LOGO</span>
        </div>
      </SidebarHeader>

      <SidebarContent>
        <SidebarGroup>
          <SidebarGroupContent>
            <SidebarMenu>
              {menuItems.map((item) => (
                <SidebarMenuItem key={item.title}>
                  <SidebarMenuButton
                    asChild
                    isActive={pathname === item.url}
                    className="data-[active=true]:bg-[#FF6B00] data-[active=true]:text-black hover:bg-[#FF6B00]/20"
                  >
                    <a href={item.url} className="flex items-center gap-3 px-3 py-2">
                      <item.icon className="h-4 w-4" />
                      <span>{item.title}</span>
                    </a>
                  </SidebarMenuButton>
                </SidebarMenuItem>
              ))}
            </SidebarMenu>
          </SidebarGroupContent>
        </SidebarGroup>
      </SidebarContent>

      <SidebarFooter className="p-6">
        <div className="flex items-center gap-3 text-[#9A9A9A]">
          <User className="h-4 w-4" />
          <span className="text-sm">user: admin</span>
        </div>
      </SidebarFooter>
    </Sidebar>
  )
}
