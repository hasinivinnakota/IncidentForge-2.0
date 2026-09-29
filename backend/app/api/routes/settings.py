"""System settings endpoints."""

import json
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, ConfigDict, Field, model_validator
from sqlmodel import Session, select

from ...database import get_session
from ...persistence.models import SystemSettings

router = APIRouter(prefix="/api/v1/settings", tags=["settings"])


class SettingsUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    profile_name: str | None = Field(default=None, min_length=1, max_length=256)
    profile_email: str | None = Field(default=None, min_length=3, max_length=320)
    tariff_rates: list[dict[str, Any]] | None = None
    shifts: list[dict[str, Any]] | None = None
    high_threshold: int | None = Field(default=None, ge=1, le=99)
    critical_threshold: int | None = Field(default=None, ge=2, le=100)

    @model_validator(mode="after")
    def validate_threshold_order(self) -> "SettingsUpdate":
        if self.high_threshold is not None and self.critical_threshold is not None:
            if self.high_threshold >= self.critical_threshold:
                raise ValueError("high_threshold must be lower than critical_threshold")
        return self


class SettingsResponse(BaseModel):
    profile_name: str
    profile_email: str
    tariff_rates: list[dict[str, Any]]
    shifts: list[dict[str, Any]]
    high_threshold: int
    critical_threshold: int
    updated_at: datetime


def _response(record: SystemSettings) -> SettingsResponse:
    return SettingsResponse(
        profile_name=record.profile_name,
        profile_email=record.profile_email,
        tariff_rates=json.loads(record.tariff_rates_json),
        shifts=json.loads(record.shifts_json),
        high_threshold=record.high_threshold,
        critical_threshold=record.critical_threshold,
        updated_at=record.updated_at,
    )


def _get_or_create(session: Session) -> SystemSettings:
    record = session.exec(select(SystemSettings)).first()
    if record is None:
        record = SystemSettings(
            tariff_rates_json=json.dumps([
                {"id": "1", "name": "Standard Rate", "rate": 0.12, "currency": "USD", "isDefault": True},
                {"id": "2", "name": "Peak Hours", "rate": 0.18, "currency": "USD", "timeStart": "09:00", "timeEnd": "17:00", "isDefault": False},
                {"id": "3", "name": "Off-Peak Hours", "rate": 0.08, "currency": "USD", "timeStart": "22:00", "timeEnd": "06:00", "isDefault": False},
            ]),
            shifts_json=json.dumps([
                {"id": "1", "name": "Main Shift", "startTime": "09:00", "endTime": "17:00", "operatingDays": ["Mon", "Tue", "Wed", "Thu", "Fri"]},
                {"id": "2", "name": "Night Shift", "startTime": "22:00", "endTime": "06:00", "operatingDays": ["Mon", "Tue", "Wed", "Thu", "Fri"]},
            ]),
        )
        session.add(record)
        session.commit()
        session.refresh(record)
    return record


@router.get("", response_model=SettingsResponse)
def get_settings(session: Session = Depends(get_session)) -> SettingsResponse:
    return _response(_get_or_create(session))


@router.patch("", response_model=SettingsResponse)
def update_settings(update: SettingsUpdate, session: Session = Depends(get_session)) -> SettingsResponse:
    record = _get_or_create(session)
    values = update.model_dump(exclude_unset=True)
    high_threshold = values.get("high_threshold", record.high_threshold)
    critical_threshold = values.get("critical_threshold", record.critical_threshold)
    if high_threshold >= critical_threshold:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="high_threshold must be lower than critical_threshold",
        )
    if "tariff_rates" in values:
        record.tariff_rates_json = json.dumps(values.pop("tariff_rates"))
    if "shifts" in values:
        record.shifts_json = json.dumps(values.pop("shifts"))
    for key, value in values.items():
        setattr(record, key, value)
    record.updated_at = datetime.now(timezone.utc)
    session.add(record)
    session.commit()
    session.refresh(record)
    return _response(record)