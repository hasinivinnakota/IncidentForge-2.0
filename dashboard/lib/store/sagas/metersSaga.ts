import { call, put, takeEvery, takeLatest, select, delay } from "redux-saga/effects"
import type { PayloadAction } from "@reduxjs/toolkit"
import { metersApi } from "../../api/metersApi"
import {
  fetchMetersRequest,
  fetchMeterDataRequest,
  selectMeter,
  fetchMetersSuccess,
  fetchMetersFailure,
  fetchMeterDataSuccess,
  fetchMeterDataFailure,
  updateMeterRealtime,
} from "../slices/metersSlice"
import type { MeterData } from "../types"
import type { RootState } from "../index"

// Fetch all meters
function* fetchMetersSaga() {
  try {
    const meters: MeterData[] = yield call(metersApi.fetchAllMeters)
    yield put(fetchMetersSuccess(meters))

    // Auto-select the first online meter as default
    const state: RootState = yield select()
    if (!state.meters.selectedMeterId && meters.length > 0) {
      const firstOnlineMeter = meters.find((meter) => meter.status === "online")
      const defaultMeter = firstOnlineMeter || meters[0]
      yield put(selectMeter(defaultMeter.id))
    }
  } catch (error) {
    yield put(fetchMetersFailure(error instanceof Error ? error.message : "Unknown error"))
  }
}

// Fetch specific meter data
function* fetchMeterDataSaga(action: PayloadAction<string>) {
  try {
    const meterData: MeterData = yield call(metersApi.fetchMeterById, action.payload)
    yield put(fetchMeterDataSuccess(meterData))
  } catch (error) {
    yield put(fetchMeterDataFailure(error instanceof Error ? error.message : "Unknown error"))
  }
}

// Handle meter selection
function* selectMeterSaga(action: PayloadAction<string>) {
  // When a meter is selected, fetch its detailed data
  yield put(fetchMeterDataRequest(action.payload))
}

// Real-time data updates
function* realtimeUpdatesSaga() {
  while (true) {
    try {
      const state: RootState = yield select()
      const { selectedMeterId, meters } = state.meters

      // Update all online meters with real-time data
      const onlineMeters = meters.filter((meter) => meter.status === "online")

      for (const meter of onlineMeters) {
        try {
          const realtimeData: Partial<MeterData> = yield call(metersApi.fetchRealtimeData, meter.id)
          yield put(updateMeterRealtime({ id: meter.id, ...realtimeData }))
        } catch (error) {
          console.warn(`Failed to update real-time data for meter ${meter.id}:`, error)
        }
      }

      // Wait 5 seconds before next update
      yield delay(5000)
    } catch (error) {
      console.error("Real-time updates error:", error)
      yield delay(10000) // Wait longer on error
    }
  }
}

export function* metersSaga() {
  yield takeLatest(fetchMetersRequest.type, fetchMetersSaga)
  yield takeLatest(fetchMeterDataRequest.type, fetchMeterDataSaga)
  yield takeEvery(selectMeter.type, selectMeterSaga)

  // Start real-time updates
  yield call(realtimeUpdatesSaga)
}
