import type { User } from "../store/types"

const delay = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms))

let mockUsersDatabase: User[] = [
  {
    id: "user-admin-01",
    name: "Admin User",
    email: "admin@edms.com",
    role: "admin",
    createdAt: new Date("2023-01-15T09:30:00Z").toISOString(),
  },
  {
    id: "user-regular-02",
    name: "Regular User",
    email: "user@edms.com",
    role: "user",
    createdAt: new Date("2023-02-20T14:00:00Z").toISOString(),
  },
  {
    id: "user-jane-doe-03",
    name: "Jane Doe",
    email: "jane.doe@example.com",
    role: "user",
    createdAt: new Date("2023-05-10T11:45:00Z").toISOString(),
  },
]

export const usersApi = {
  async fetchAllUsers(): Promise<User[]> {
    await delay(500)
    return [...mockUsersDatabase]
  },

  async createUser(userData: Omit<User, "id" | "createdAt">): Promise<User> {
    await delay(500)
    const newUser: User = {
      ...userData,
      id: `user-${Math.random().toString(36).substr(2, 9)}`,
      createdAt: new Date().toISOString(),
    }
    mockUsersDatabase.push(newUser)
    return newUser
  },

  async updateUser(userId: string, updates: Partial<User>): Promise<User> {
    await delay(500)
    let updatedUser: User | undefined
    mockUsersDatabase = mockUsersDatabase.map((user) => {
      if (user.id === userId) {
        updatedUser = { ...user, ...updates }
        return updatedUser
      }
      return user
    })
    if (!updatedUser) throw new Error("User not found")
    return updatedUser
  },

  async deleteUser(userId: string): Promise<{ id: string }> {
    await delay(500)
    const initialLength = mockUsersDatabase.length
    mockUsersDatabase = mockUsersDatabase.filter((user) => user.id !== userId)
    if (mockUsersDatabase.length === initialLength) {
      throw new Error("User not found")
    }
    return { id: userId }
  },
}
