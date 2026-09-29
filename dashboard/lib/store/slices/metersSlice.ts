import { createSlice, type PayloadAction } from "@reduxjs/toolkit"
import type { MetersState, MeterData } from "../types"

const initialState: MetersState = {
  meters: [],
  selectedMeterId: null,
  selectedMeterData: null,
  loading: false,
  error: null,
}

const metersSlice = createSlice({
  name: "meters",
  initialState,
  reducers: {
    // Actions that trigger sagas
    fetchMetersRequest: (state) => {
      state.loading = true
      state.error = null
    },
    fetchMeterDataRequest: (state, action: PayloadAction<string>) => {
      state.loading = true
      state.error = null
    },
    selectMeter: (state, action: PayloadAction<string>) => {
      state.selectedMeterId = action.payload
    },

    // Actions that update state (called by sagas)
    fetchMetersSuccess: (state, action: PayloadAction<MeterData[]>) => {
      state.meters = action.payload
      state.loading = false
      state.error = null
    },
    fetchMetersFailure: (state, action: PayloadAction<string>) => {
      state.loading = false
      state.error = action.payload
    },
    fetchMeterDataSuccess: (state, action: PayloadAction<MeterData>) => {
      state.selectedMeterData = action.payload
      state.loading = false
      state.error = null
    },
    fetchMeterDataFailure: (state, action: PayloadAction<string>) => {
      state.loading = false
      state.error = action.payload
    },
    updateMeterRealtime: (state, action: PayloadAction<Partial<MeterData> & { id: string }>) => {
      const { id, ...updates } = action.payload
      const meterIndex = state.meters.findIndex((meter) => meter.id === id)
      if (meterIndex !== -1) {
        state.meters[meterIndex] = { ...state.meters[meterIndex], ...updates }
      }
      if (state.selectedMeterData?.id === id) {
        state.selectedMeterData = { ...state.selectedMeterData, ...updates }
      }
    },
  },
})

export const {
  fetchMetersRequest,
  fetchMeterDataRequest,
  selectMeter,
  fetchMetersSuccess,
  fetchMetersFailure,
  fetchMeterDataSuccess,
  fetchMeterDataFailure,
  updateMeterRealtime,
} = metersSlice.actions

export const metersReducer = metersSlice.reducer
