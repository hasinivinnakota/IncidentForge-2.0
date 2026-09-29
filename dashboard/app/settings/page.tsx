"use client"

import { DashboardLayout } from "@/components/dashboard-layout"
import { Button } from "@/components/ui/button"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { UserManagement } from "@/components/settings/user-management"
import { MeterManagement } from "@/components/settings/meter-management"
import { OperationSettings } from "@/components/settings/operation-settings"
import { ProfileSettings } from "@/components/settings/profile-settings"
import { useAuth } from "@/hooks/use-auth"
import { User, UserCog, Settings, Zap } from "lucide-react"

export default function SettingsPage() {
  const { user, isAdmin, toggleRole } = useAuth()

  return (
    <DashboardLayout>
      <div className="space-y-4 sm:space-y-6">
        {/* Page Header */}
        <div className="flex flex-col gap-4">
          <div className="px-1">
            <h1 className="text-xl sm:text-2xl font-bold text-[#EDEDED]">Settings</h1>
            <p className="text-sm sm:text-base text-[#9A9A9A] mt-1">Manage your system and profile settings.</p>
          </div>

          {/* User Info Card - Mobile Optimized */}
          <div className="p-3 sm:p-4 bg-[#1B1B1B] border border-[#2A2A2A] rounded-lg">
            <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3">
              <div className="flex items-center gap-3 min-w-0 flex-1">
                <div className="w-10 h-10 sm:w-12 sm:h-12 bg-[#FF6B00] rounded-full flex items-center justify-center flex-shrink-0">
                  <User className="h-5 w-5 sm:h-6 sm:w-6 text-black" />
                </div>
                <div className="min-w-0 flex-1">
                  <div className="font-medium text-[#EDEDED] text-sm sm:text-base truncate">{user.name}</div>
                  <div className="text-xs sm:text-sm text-[#9A9A9A]">
                    Role: <span className="capitalize font-medium">{user.role}</span>
                  </div>
                </div>
              </div>
              <Button
                onClick={toggleRole}
                variant="outline"
                size="sm"
                className="border-[#FF6B00]/50 text-[#FF6B00] hover:bg-[#FF6B00]/10 hover:text-[#FF6B00] bg-transparent h-9 px-4 text-xs sm:text-sm touch-manipulation w-full sm:w-auto"
              >
                Toggle Role
              </Button>
            </div>
          </div>
        </div>

        {/* Tabs - Mobile Optimized */}
        <Tabs defaultValue="profile" className="w-full">
          <TabsList className="grid w-full grid-cols-2 sm:grid-cols-4 bg-[#1B1B1B] border border-[#2A2A2A] h-auto p-1">
            <TabsTrigger
              value="profile"
              className="flex flex-col sm:flex-row items-center gap-1 sm:gap-2 py-2 sm:py-2.5 px-2 sm:px-4 text-xs sm:text-sm data-[state=active]:bg-[#FF6B00] data-[state=active]:text-black"
            >
              <User className="w-3 h-3 sm:w-4 sm:h-4" />
              <span className="hidden sm:inline">Profile</span>
              <span className="sm:hidden">Profile</span>
            </TabsTrigger>
            <TabsTrigger
              value="users"
              className="flex flex-col sm:flex-row items-center gap-1 sm:gap-2 py-2 sm:py-2.5 px-2 sm:px-4 text-xs sm:text-sm data-[state=active]:bg-[#FF6B00] data-[state=active]:text-black"
            >
              <UserCog className="w-3 h-3 sm:w-4 sm:h-4" />
              <span className="hidden sm:inline">Users</span>
              <span className="sm:hidden">Users</span>
            </TabsTrigger>
            <TabsTrigger
              value="meters"
              className="flex flex-col sm:flex-row items-center gap-1 sm:gap-2 py-2 sm:py-2.5 px-2 sm:px-4 text-xs sm:text-sm data-[state=active]:bg-[#FF6B00] data-[state=active]:text-black"
            >
              <Zap className="w-3 h-3 sm:w-4 sm:h-4" />
              <span className="hidden sm:inline">Meters</span>
              <span className="sm:hidden">Meters</span>
            </TabsTrigger>
            <TabsTrigger
              value="operation"
              className="flex flex-col sm:flex-row items-center gap-1 sm:gap-2 py-2 sm:py-2.5 px-2 sm:px-4 text-xs sm:text-sm data-[state=active]:bg-[#FF6B00] data-[state=active]:text-black"
            >
              <Settings className="w-3 h-3 sm:w-4 sm:h-4" />
              <span className="hidden sm:inline">Operation</span>
              <span className="sm:hidden">Ops</span>
            </TabsTrigger>
          </TabsList>

          <TabsContent value="profile" className="mt-4 sm:mt-6">
            <ProfileSettings user={user} />
          </TabsContent>
          <TabsContent value="users" className="mt-4 sm:mt-6">
            <UserManagement isAdmin={isAdmin} />
          </TabsContent>
          <TabsContent value="meters" className="mt-4 sm:mt-6">
            <MeterManagement isAdmin={isAdmin} />
          </TabsContent>
          <TabsContent value="operation" className="mt-4 sm:mt-6">
            <OperationSettings isAdmin={isAdmin} />
          </TabsContent>
        </Tabs>
      </div>
    </DashboardLayout>
  )
}
