import { call, put, takeLatest } from "redux-saga/effects"
import type { PayloadAction } from "@reduxjs/toolkit"
import { usersApi } from "../../api/usersApi"
import {
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
} from "../slices/usersSlice"
import type { User } from "../types"

function* fetchUsers() {
  try {
    const users: User[] = yield call(usersApi.fetchAllUsers)
    yield put(fetchUsersSuccess(users))
  } catch (e) {
    yield put(fetchUsersFailure((e as Error).message))
  }
}

function* createUser(action: PayloadAction<Omit<User, "id" | "createdAt">>) {
  try {
    const newUser: User = yield call(usersApi.createUser, action.payload)
    yield put(createUserSuccess(newUser))
  } catch (e) {
    yield put(userActionFailure((e as Error).message))
  }
}

function* updateUser(action: PayloadAction<{ id: string; data: Partial<User> }>) {
  try {
    const { id, data } = action.payload
    const updatedUser: User = yield call(usersApi.updateUser, id, data)
    yield put(updateUserSuccess(updatedUser))
  } catch (e) {
    yield put(userActionFailure((e as Error).message))
  }
}

function* deleteUser(action: PayloadAction<string>) {
  try {
    const { id }: { id: string } = yield call(usersApi.deleteUser, action.payload)
    yield put(deleteUserSuccess(id))
  } catch (e) {
    yield put(userActionFailure((e as Error).message))
  }
}

export function* usersSaga() {
  yield takeLatest(fetchUsersRequest.type, fetchUsers)
  yield takeLatest(createUserRequest.type, createUser)
  yield takeLatest(updateUserRequest.type, updateUser)
  yield takeLatest(deleteUserRequest.type, deleteUser)
}
