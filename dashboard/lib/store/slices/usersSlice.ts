import { createSlice, type PayloadAction } from "@reduxjs/toolkit"
import type { UsersState, User } from "../types"

const initialState: UsersState = {
  users: [],
  loading: false,
  error: null,
}

const usersSlice = createSlice({
  name: "users",
  initialState,
  reducers: {
    // Fetch
    fetchUsersRequest: (state) => {
      state.loading = true
    },
    fetchUsersSuccess: (state, action: PayloadAction<User[]>) => {
      state.users = action.payload
      state.loading = false
    },
    fetchUsersFailure: (state, action: PayloadAction<string>) => {
      state.error = action.payload
      state.loading = false
    },
    // Create
    createUserRequest: (state, _action: PayloadAction<Omit<User, "id" | "createdAt">>) => {
      state.loading = true
    },
    createUserSuccess: (state, action: PayloadAction<User>) => {
      state.users.push(action.payload)
      state.loading = false
    },
    // Update
    updateUserRequest: (state, _action: PayloadAction<{ id: string; data: Partial<User> }>) => {
      state.loading = true
    },
    updateUserSuccess: (state, action: PayloadAction<User>) => {
      const index = state.users.findIndex((u) => u.id === action.payload.id)
      if (index !== -1) {
        state.users[index] = action.payload
      }
      state.loading = false
    },
    // Delete
    deleteUserRequest: (state, _action: PayloadAction<string>) => {
      state.loading = true
    },
    deleteUserSuccess: (state, action: PayloadAction<string>) => {
      state.users = state.users.filter((u) => u.id !== action.payload)
      state.loading = false
    },
    // Generic failure for CUD
    userActionFailure: (state, action: PayloadAction<string>) => {
      state.error = action.payload
      state.loading = false
    },
  },
})

export const {
  fetchUsersRequest,
  fetchUsersSuccess,
  fetchUsersFailure,
  createUserRequest,
  createUserSuccess,
  updateUserRequest,
  updateUserSuccess,
  deleteUserRequest,
  deleteUserSuccess,
  userActionFailure,
} = usersSlice.actions

export const usersReducer = usersSlice.reducer
