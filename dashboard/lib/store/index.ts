import { configureStore } from "@reduxjs/toolkit"
import createSagaMiddleware from "redux-saga"
import { rootSaga } from "./sagas"
import { metersReducer } from "./slices/metersSlice"
import { overviewReducer } from "./slices/overviewSlice"
import { usersReducer } from "./slices/usersSlice"

const sagaMiddleware = createSagaMiddleware()

export const store = configureStore({
  reducer: {
    meters: metersReducer,
    overview: overviewReducer,
    users: usersReducer,
  },
  middleware: (getDefaultMiddleware) =>
    getDefaultMiddleware({
      serializableCheck: {
        ignoredActions: ["persist/PERSIST"],
      },
    }).concat(sagaMiddleware),
})

sagaMiddleware.run(rootSaga)

export type RootState = ReturnType<typeof store.getState>
export type AppDispatch = typeof store.dispatch
