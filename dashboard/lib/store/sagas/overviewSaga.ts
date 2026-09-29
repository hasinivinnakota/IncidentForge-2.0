import { call, put, takeLatest, delay } from "redux-saga/effects"
import { overviewApi } from "../../api/overviewApi"
import {
  fetchOverviewDataRequest,
  fetchOverviewDataSuccess,
  fetchOverviewDataFailure,
  updateOverviewRealtime,
} from "../slices/overviewSlice"
import type { OverviewData } from "../types"

function* fetchOverviewDataSaga() {
  try {
    const overviewData: OverviewData = yield call(overviewApi.fetchOverviewData)
    yield put(fetchOverviewDataSuccess(overviewData))
  } catch (error) {
    yield put(fetchOverviewDataFailure(error instanceof Error ? error.message : "Unknown error"))
  }
}

function* overviewRealtimeUpdatesSaga() {
  while (true) {
    yield delay(5000) // Update every 5 seconds
    try {
      const updates: Partial<OverviewData> = {
        kpis: {
          totalConsumption: { value: 12456 + Math.random() * 100, trend: 2.5 + (Math.random() - 0.5) },
          peakDemand: { value: 876 + Math.random() * 20, trend: -1.2 + (Math.random() - 0.5) },
          energyCost: { value: 1494.72 + Math.random() * 10, trend: 2.5 + (Math.random() - 0.5) },
          co2Emissions: { value: 6228 + Math.random() * 50, trend: 2.5 + (Math.random() - 0.5) },
        },
      }
      yield put(updateOverviewRealtime(updates))
    } catch (error) {
      console.error("Overview real-time updates error:", error)
    }
  }
}

export function* overviewSaga() {
  yield takeLatest(fetchOverviewDataRequest.type, fetchOverviewDataSaga)
  yield call(overviewRealtimeUpdatesSaga)
}
