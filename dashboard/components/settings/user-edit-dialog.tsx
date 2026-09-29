"use client"

import type React from "react"

import { useState, useEffect } from "react"
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
  DialogFooter,
} from "@/components/ui/dialog"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { useAppDispatch, useUsersLoading } from "@/lib/store/hooks"
import { createUserRequest, updateUserRequest } from "@/lib/store/slices/usersSlice"
import type { User } from "@/lib/store/types"

interface UserEditDialogProps {
  isOpen: boolean
  setIsOpen: (open: boolean) => void
  user: User | null
}

export function UserEditDialog({ isOpen, setIsOpen, user }: UserEditDialogProps) {
  const dispatch = useAppDispatch()
  const loading = useUsersLoading()
  const [name, setName] = useState("")
  const [email, setEmail] = useState("")
  const [role, setRole] = useState<"admin" | "user">("user")

  useEffect(() => {
    if (user) {
      setName(user.name)
      setEmail(user.email)
      setRole(user.role)
    } else {
      setName("")
      setEmail("")
      setRole("user")
    }
  }, [user, isOpen])

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault()
    if (user) {
      dispatch(updateUserRequest({ id: user.id, data: { name, email, role } }))
    } else {
      dispatch(createUserRequest({ name, email, role }))
    }
    setIsOpen(false)
  }

  return (
    <Dialog open={isOpen} onOpenChange={setIsOpen}>
      <DialogContent className="bg-[#1B1B1B] border-[#2A2A2A] text-[#EDEDED] sm:max-w-[425px]">
        <DialogHeader>
          <DialogTitle>{user ? "Edit User" : "Add New User"}</DialogTitle>
          <DialogDescription className="text-[#9A9A9A]">
            {user ? "Update the user's details." : "Create a new user account."}
          </DialogDescription>
        </DialogHeader>
        <form onSubmit={handleSubmit}>
          <div className="grid gap-4 py-4">
            <div className="grid grid-cols-4 items-center gap-4">
              <Label htmlFor="name" className="text-right text-[#9A9A9A]">
                Name
              </Label>
              <Input
                id="name"
                value={name}
                onChange={(e) => setName(e.target.value)}
                className="col-span-3 bg-[#0E0E0E] border-[#2A2A2A]"
              />
            </div>
            <div className="grid grid-cols-4 items-center gap-4">
              <Label htmlFor="email" className="text-right text-[#9A9A9A]">
                Email
              </Label>
              <Input
                id="email"
                type="email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                className="col-span-3 bg-[#0E0E0E] border-[#2A2A2A]"
              />
            </div>
            <div className="grid grid-cols-4 items-center gap-4">
              <Label htmlFor="role" className="text-right text-[#9A9A9A]">
                Role
              </Label>
              <Select value={role} onValueChange={(value: "admin" | "user") => setRole(value)}>
                <SelectTrigger className="col-span-3 bg-[#0E0E0E] border-[#2A2A2A]">
                  <SelectValue placeholder="Select a role" />
                </SelectTrigger>
                <SelectContent className="bg-[#1B1B1B] border-[#2A2A2A] text-[#EDEDED]">
                  <SelectItem value="user" className="cursor-pointer hover:!bg-[#2A2A2A]">
                    User
                  </SelectItem>
                  <SelectItem value="admin" className="cursor-pointer hover:!bg-[#2A2A2A]">
                    Admin
                  </SelectItem>
                </SelectContent>
              </Select>
            </div>
          </div>
          <DialogFooter>
            <Button type="submit" disabled={loading} className="bg-[#FF6B00] hover:bg-[#E55A00] text-black">
              {loading ? "Saving..." : "Save Changes"}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}
