"use client"

import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import type { AuthUser } from "@/hooks/use-auth"
import { settingsApi } from "@/lib/api"
import { useEffect, useState } from "react"

interface ProfileSettingsProps {
  user: AuthUser
}

export function ProfileSettings({ user }: ProfileSettingsProps) {
  const [name, setName] = useState(user.name)
  const [email, setEmail] = useState(user.email)
  const [status, setStatus] = useState<string | null>(null)

  useEffect(() => {
    settingsApi.get().then((settings) => {
      setName(settings.profile_name)
      setEmail(settings.profile_email)
    }).catch(() => setStatus("Unable to load saved profile settings."))
  }, [])

  const saveProfile = async () => {
    try {
      await settingsApi.update({ profile_name: name, profile_email: email })
      setStatus("Profile settings saved.")
    } catch {
      setStatus("Unable to save profile settings.")
    }
  }

  return (
    <Card className="bg-[#1B1B1B] border-[#2A2A2A] text-[#EDEDED]">
      <CardHeader className="pb-4 sm:pb-6">
        <CardTitle className="text-base sm:text-lg">My Profile</CardTitle>
        <CardDescription className="text-[#9A9A9A] text-sm">Update your personal information.</CardDescription>
      </CardHeader>
      <CardContent className="space-y-4 sm:space-y-6">
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 sm:gap-6">
          <div className="space-y-2">
            <Label htmlFor="name" className="text-sm font-medium">
              Name
            </Label>
            <Input id="name" value={name} onChange={(event) => setName(event.target.value)} className="bg-[#0E0E0E] border-[#2A2A2A] h-10 sm:h-11" />
          </div>
          <div className="space-y-2">
            <Label htmlFor="email" className="text-sm font-medium">
              Email
            </Label>
            <Input
              id="email"
              type="email"
              value={email}
              onChange={(event) => setEmail(event.target.value)}
              className="bg-[#0E0E0E] border-[#2A2A2A] h-10 sm:h-11"
            />
          </div>
        </div>
        <div className="space-y-2">
          <Label htmlFor="password" className="text-sm font-medium">
            New Password
          </Label>
          <Input
            id="password"
            type="password"
            placeholder="••••••••"
            className="bg-[#0E0E0E] border-[#2A2A2A] h-10 sm:h-11"
          />
        </div>
        <div className="flex justify-end pt-4 border-t border-[#2A2A2A]">
          <Button onClick={saveProfile} className="bg-[#FF6B00] hover:bg-[#E55A00] text-black h-10 sm:h-11 px-6 touch-manipulation w-full sm:w-auto">
            Update Profile
          </Button>
        </div>
        {status && <p className="text-right text-xs text-[#9A9A9A]">{status}</p>}
      </CardContent>
    </Card>
  )
}
