"use client"

import { useState, useCallback } from "react"

export type UserRole = "admin" | "user"

export interface AuthUser {
  id: string
  name: string
  email: string
  role: UserRole
}

// Mock user data
const mockUsers: Record<UserRole, AuthUser> = {
  admin: {
    id: "user-admin-01",
    name: "Admin User",
    email: "admin@edms.com",
    role: "admin",
  },
  user: {
    id: "user-regular-02",
    name: "Regular User",
    email: "user@edms.com",
    role: "user",
  },
}

/**
 * Mock authentication hook. In a real app, this would be replaced
 * with a proper authentication context provider.
 */
export function useAuth() {
  const [currentUser, setCurrentUser] = useState<AuthUser>(mockUsers.admin)

  const toggleRole = useCallback(() => {
    setCurrentUser((prevUser) => (prevUser.role === "admin" ? mockUsers.user : mockUsers.admin))
  }, [])

  const isAdmin = currentUser.role === "admin"

  return { user: currentUser, isAdmin, toggleRole }
}
