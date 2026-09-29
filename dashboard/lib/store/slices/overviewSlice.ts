import { createSlice, type PayloadAction } from "@reduxjs/toolkit"
import type { OverviewState, OverviewData } from "../types"

const initialState: OverviewState = {
  data: null,
  loading: false,
  error: null,
}

const overviewSlice = createSlice({
  name: "overview",
  initialState,
  reducers: {
    fetchOverviewDataRequest: (state) => {
      state.loading = true
      state.error = null
    },
    fetchOverviewDataSuccess: (state, action: PayloadAction<OverviewData>) => {
      state.data = action.payload
      state.loading = false
      state.error = null
    },
    fetchOverviewDataFailure: (state, action: PayloadAction<string>) => {
      state.loading = false
      state.error = action.payload
    },
    updateOverviewRealtime: (state, action: PayloadAction<Partial<OverviewData>>) => {
      if (state.data) {
        if (action.payload.kpis) {
          state.data.kpis = { ...state.data.kpis, ...action.payload.kpis }
        }
      }
    },
  },
})

export const { fetchOverviewDataRequest, fetchOverviewDataSuccess, fetchOverviewDataFailure, updateOverviewRealtime } =
  overviewSlice.actions

export const overviewReducer = overviewSlice.reducer
