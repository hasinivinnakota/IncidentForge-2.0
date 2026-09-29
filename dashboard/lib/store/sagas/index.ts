import { all, fork } from "redux-saga/effects"
import { metersSaga } from "./metersSaga"
import { overviewSaga } from "./overviewSaga"
import { usersSaga } from "./usersSaga"

export function* rootSaga() {
  yield all([fork(metersSaga), fork(overviewSaga), fork(usersSaga)])
}
