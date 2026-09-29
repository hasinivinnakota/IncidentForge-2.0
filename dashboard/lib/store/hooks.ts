import { useDispatch, useSelector, type TypedUseSelectorHook } from "react-redux"
import type { RootState, AppDispatch } from "./index"

export const useAppDispatch = () => useDispatch<AppDispatch>()
export const useAppSelector: TypedUseSelectorHook<RootState> = useSelector

// Meters selectors
export const useMeters = () => useAppSelector((state) => state.meters.meters)
export const useSelectedMeter = () => useAppSelector((state) => state.meters.selectedMeterData)
export const useSelectedMeterId = () => useAppSelector((state) => state.meters.selectedMeterId)
export const useMetersLoading = () => useAppSelector((state) => state.meters.loading)
export const useMetersError = () => useAppSelector((state) => state.meters.error)

// Overview selectors
export const useOverviewData = () => useAppSelector((state) => state.overview.data)
export const useOverviewLoading = () => useAppSelector((state) => state.overview.loading)
export const useOverviewError = () => useAppSelector((state) => state.overview.error)

// Users selectors
export const useUsers = () => useAppSelector((state) => state.users.users)
export const useUsersLoading = () => useAppSelector((state) => state.users.loading)
export const useUsersError = () => useAppSelector((state) => state.users.error)
