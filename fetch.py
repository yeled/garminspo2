#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import datetime
import io
import sqlite3
import zipfile
from pprint import pprint
from time import sleep
import logging
import os
import sys
from pathlib import Path

import fitdecode

from intervalsicu import Intervals

from garmin_client import (
    ActivityDownloadFormat,
    GarminClient,
    GarminAuthenticationError,
    GarminConnectionError,
    GarminTooManyRequestsError,
)
from auth import EMAIL, PASSWORD, DAYS_TO_FETCH, ATHELETE_ID, API_KEY

today = datetime.date.today()
startfrom = today - datetime.timedelta(days=DAYS_TO_FETCH)
print(startfrom)

def safe_api_call(api_method, *args, **kwargs):
    """
    Safe API call wrapper. Returns (success: bool, result: Any, error_message: str).
    """
    try:
        result = api_method(*args, **kwargs)
        return True, result, None

    except GarminTooManyRequestsError as e:
        return False, None, f"Rate limit exceeded (429) - Please wait before making more requests: {e}"

    except GarminAuthenticationError as e:
        return False, None, f"Authentication required - Please re-authenticate: {e}"

    except GarminConnectionError as e:
        error_str = str(e)
        if "400" in error_str:
            return False, None, "Endpoint not available (400) - Feature may not be enabled for your account"
        elif "403" in error_str:
            return False, None, "Access denied (403) - Account may not have permission"
        elif "404" in error_str:
            return False, None, "Endpoint not found (404) - Feature may have been moved or removed"
        elif "500" in error_str:
            return False, None, "Server error (500) - Garmin's servers are experiencing issues"
        elif "503" in error_str:
            return False, None, "Service unavailable (503) - Garmin's servers are temporarily unavailable"
        return False, None, f"Connection error: {e}"

    except Exception as e:
        return False, None, f"Unexpected error: {e}"






def get_credentials():
    """Get email and password from environment or user input."""
    if not os.getenv("EMAIL"):
        email = EMAIL
    if not os.getenv("PASSWORD"):
        password = PASSWORD

    return email, password


def init_api() -> GarminClient | None:
    """Initialize Garmin API with authentication and token management."""

    tokenstore = Path(os.getenv("GARMINTOKENS", "~/.garminconnect")).expanduser()

    # Try loading existing tokens
    try:
        client = GarminClient.from_tokens(tokenstore)
        print("Loaded saved authentication tokens.")
        return client
    except (GarminAuthenticationError, GarminConnectionError):
        print("No valid tokens found. Requesting fresh login credentials.")

    # Fresh login
    email, password = get_credentials()
    client = GarminClient()

    while True:
        try:
            print("Logging in with credentials...")
            result1, result2 = client.login(email, password, return_on_mfa=True)

            if result1 == "needs_mfa":
                print("Multi-factor authentication required")
                mfa_code = input("Please enter your MFA code: ")
                print("Submitting MFA code...")
                try:
                    client.resume_login(result2, mfa_code)
                    print("MFA authentication successful!")
                except GarminTooManyRequestsError:
                    print("Too many MFA attempts. Please wait 30 minutes before trying again.")
                    sys.exit(1)
                except GarminAuthenticationError:
                    print("Invalid MFA code. Please verify your MFA code and try again.")
                    continue

            client.dump(tokenstore)
            print(f"Authentication tokens saved to: {tokenstore}")
            return client

        except GarminAuthenticationError:
            print("Authentication failed. Please check your credentials and try again.")
            continue

        except GarminTooManyRequestsError:
            print("Too many login attempts. Please wait 30 minutes before trying again.")
            sys.exit(1)

        except GarminConnectionError as err:
            print(f"Connection error: {err}")
            return None

        except KeyboardInterrupt:
            print("\nCancelled by user")
            return None


def _get_spo2_data(client: GarminClient, cdate: str) -> dict:
    return client._connectapi(f"/wellness-service/wellness/daily/spo2/{cdate}")


def display_spo2(api: GarminClient):
    """Display today's activity statistics with proper error handling."""

    success, summary, error_msg = safe_api_call(_get_spo2_data, api, today.isoformat())
    if success and summary:
        spo2_avgsleep = summary.get("avgSleepSpO2", 0)

    else:
        if not success:
            print(f"️Could not fetch daily stats: {error_msg}")
        else:
            print("️No activity summary available for today")

    print(f"latest_avg: {spo2_avgsleep}")
    return spo2_avgsleep

    # # Get sleep
    # success, sleepsummary, error_msg = safe_api_call(api.get_sleep_data, today)
    # if success and sleepsummary:
    #     wellness_spo2 = sleepsummary.get('wellnessSpO2SleepSummaryDTO', {}).get("averageSPO2", 0)

    #     print(f"wellnessEpochSPO2DataDTOList: {wellness_spo2}")

    # else:
    #     if not success:
    #         print(f"💧 Hydration: ⚠️ {error_msg}")
    #     else:
    #         print("💧 Hydration: No data available")



def spo2wellness(spo2):
    """ push spo2 to ICU """
    today = datetime.date.today()
    # print("logging into ICU with {}".format(ATHELETE_ID))
    svc = Intervals(ATHELETE_ID, API_KEY, strict=False)

    start = datetime.date.today()
    wellness = svc.wellness(start)
    wellness['spO2'] = spo2
    print("sending SPO2: {}".format(spo2))
    wellness = svc.wellness_put(wellness)
    # pprint.pprint(wellness)


def populateSpoList(api: GarminClient):
    # start populating db/json
    reqday = startfrom
    db = sqlite3.connect("spo2.db3")
    db.execute("""
        CREATE TABLE IF NOT EXISTS "spo2" (
            "timestamp_utc" INTEGER NOT NULL UNIQUE,
            "spo2_percent"  INTEGER NOT NULL,
            "spo2_confidence" INTEGER,
            PRIMARY KEY("timestamp_utc")
        )
    """)
    while reqday <= today:
        print("Querying data for: {}".format(reqday.isoformat()))
        # reqday += datetime.timedelta(days=1)
        success, sleepsummary, error_msg = safe_api_call(api.get_sleep_data, reqday.isoformat())
        if success and sleepsummary:
            # pprint(sleepsummary)
            sleep_wellness = sleepsummary.get('wellnessEpochSPO2DataDTOList', {})
            # print(f"wellnessEpochSPO2DataDTOList: {sleep}")
            # pprint(sleep_wellness)
            for rec in sleep_wellness:
               ts = datetime.datetime.fromisoformat(rec["epochTimestamp"][:-2])   # strip hundreds of seconds
            #    print(ts, rec["spo2Reading"], rec["readingConfidence"])
               sql = "INSERT OR IGNORE INTO spo2 VALUES (?, ?, ?)"
               db.execute(sql, [int(ts.timestamp()), rec["spo2Reading"], rec["readingConfidence"]])
            print("Got {} records.".format(len(sleep_wellness)))
        if not success:
            print(f"️Could not fetch daily stats: {error_msg}")
            reqday += datetime.timedelta(days=1)
        else:
            print(f"️No activity summary available for today: {error_msg}")
            reqday += datetime.timedelta(days=1)
    db.commit()
    db.close()


def _get_hrv_data(client: GarminClient, cdate: str) -> dict:
    return client._connectapi(f"/hrv-service/hrv/{cdate}")


def populateHrvList(api: GarminClient):
    reqday = startfrom
    db = sqlite3.connect("hrv.db3")
    db.execute("""
        CREATE TABLE IF NOT EXISTS hrv (
            "timestamp_utc" INTEGER NOT NULL UNIQUE,
            "hrv_value" INTEGER NOT NULL,
            PRIMARY KEY("timestamp_utc")
        )
    """)
    while reqday <= today:
        print("Querying HRV for: {}".format(reqday.isoformat()))
        success, data, error_msg = safe_api_call(_get_hrv_data, api, reqday.isoformat())
        if success and data:
            readings = data.get("hrvReadings") or []
            for rec in readings:
                start = rec.get("readingTimeGMT")
                hrv_value = rec.get("hrvValue")
                if not start or hrv_value is None:
                    continue
                ts = int(datetime.datetime.fromisoformat(start).timestamp())
                db.execute("INSERT OR IGNORE INTO hrv VALUES (?, ?)", [ts, hrv_value])
            print("Got {} HRV readings.".format(len(readings)))
        else:
            if not success:
                print(f"Could not fetch HRV data: {error_msg}")
        reqday += datetime.timedelta(days=1)
    db.commit()
    db.close()


def get_vo2max_from_fit(api: GarminClient):
    """Download the latest activity FIT file from Garmin and return (vo2max, activity_date)."""
    lookback = (today - datetime.timedelta(days=7)).isoformat()
    success, activities, error_msg = safe_api_call(
        api.get_activities_by_date, lookback, today.isoformat()
    )
    if not success or not activities:
        print(f"Could not get recent activities: {error_msg}")
        return None, None

    # API returns newest-first
    latest = activities[0]
    activity_id = latest.get('activityId')
    start_time = latest.get('startTimeLocal', '')
    activity_dt = datetime.datetime.fromisoformat(start_time) if start_time else datetime.datetime.combine(today, datetime.time())
    activity_date = activity_dt.date()
    print(f"Latest activity: {activity_id} on {activity_dt}")

    success, fit_zip_data, error_msg = safe_api_call(
        api.download_activity, activity_id, ActivityDownloadFormat.ORIGINAL
    )
    if not success or not fit_zip_data:
        print(f"Could not download FIT file: {error_msg}")
        return None, activity_date

    # ORIGINAL download is a zip; extract the .fit file
    try:
        with zipfile.ZipFile(io.BytesIO(fit_zip_data)) as zf:
            fit_names = [n for n in zf.namelist() if n.lower().endswith('.fit')]
            if not fit_names:
                print("No .fit file found inside zip")
                return None, activity_date
            fit_bytes = zf.read(fit_names[0])
            print(f"Extracted {fit_names[0]} ({len(fit_bytes)} bytes)")
    except zipfile.BadZipFile:
        fit_bytes = fit_zip_data

    # Garmin encodes VO2max in two ways depending on the device/firmware:
    #
    # 1. mesg 140 (unknown_140) def_num=7: sint32 = METs × 65536, where
    #    1 MET = 3.5 mL/kg/min. Full precision (e.g. 898327 → 47.9758).
    #    def_num=29 holds the same value as "first vo2max" (both used).
    #
    # 2. max_met_data (mesg 229) def_num=7: float32 VO2max directly.
    #    Present on some devices/firmware when Garmin computes a new estimate.
    #
    # 3. session.vo2_max_value: uint16 scale=10, only 1 decimal place.
    #    Last-resort fallback for old files.
    vo2max = None
    fallback_vo2max = None
    try:
        with fitdecode.FitReader(io.BytesIO(fit_bytes)) as fit:
            for frame in fit:
                if not isinstance(frame, fitdecode.FitDataMessage):
                    continue

                # Primary: mesg 140 stores VO2max as METs × 65536 (sint32)
                if frame.name == 'unknown_140':
                    for field in frame.fields:
                        if field.def_num == 7:
                            raw = getattr(field, 'raw_value', field.value)
                            if isinstance(raw, int) and raw > 0:
                                val = raw * 3.5 / 65536
                                if 20.0 <= val <= 100.0:
                                    vo2max = round(val, 4)
                                    print(f"VO2max from mesg 140 field 7: {vo2max} mL/kg/min")
                                    break

                # Secondary: max_met_data stores VO2max directly as float32
                elif frame.name == 'max_met_data':
                    for field in frame.fields:
                        if field.def_num == 7 and isinstance(field.value, (int, float)):
                            val = float(field.value)
                            if 20.0 <= val <= 100.0:
                                vo2max = round(val, 4)
                                print(f"VO2max from max_met_data field 7: {vo2max} mL/kg/min")
                                break

                elif frame.name == 'session' and frame.has_field('vo2_max_value'):
                    val = frame.get_value('vo2_max_value')
                    if val is not None and val > 0:
                        fallback_vo2max = round(float(val), 1)

                if vo2max is not None:
                    break
    except Exception as e:
        print(f"Error parsing FIT file: {e}")

    if vo2max is None and fallback_vo2max is not None:
        vo2max = fallback_vo2max
        print(f"VO2max from session.vo2_max_value (fallback): {vo2max} mL/kg/min")

    if vo2max is None:
        print("VO2max not found in FIT session record")

    return vo2max, activity_dt


def store_vo2max(activity_dt: datetime.datetime, vo2max: float):
    """Insert VO2max reading into local sqlite DB, keyed by activity timestamp."""
    db = sqlite3.connect("vo2max.db3")
    db.execute("""
        CREATE TABLE IF NOT EXISTS vo2max (
            "timestamp_utc" INTEGER NOT NULL UNIQUE,
            "vo2max" REAL NOT NULL,
            PRIMARY KEY("timestamp_utc")
        )
    """)
    ts = int(activity_dt.timestamp())
    db.execute("INSERT OR IGNORE INTO vo2max VALUES (?, ?)", [ts, vo2max])
    db.commit()
    db.close()
    print(f"Stored VO2max {vo2max} for {activity_dt}")


def vo2max_wellness(vo2max: float, activity_date: datetime.date = None):
    """Push VO2max to Intervals.icu wellness for the given date."""
    if activity_date is None:
        activity_date = datetime.date.today()
    svc = Intervals(ATHELETE_ID, API_KEY, strict=False)
    wellness = svc.wellness(activity_date)
    wellness['vo2max'] = vo2max
    print(f"Sending VO2max: {vo2max} for {activity_date}")
    svc.wellness_put(wellness)


def main():
    """Initialize API with authentication (will only prompt for credentials if needed)"""
    api = init_api()

    if not api:
        print("Failed to initialize API. Exiting.")
        return

    # print(f"7d average: {spo2_7d_avg}")
    # display_spo2(api)
    spo2wellness(display_spo2(api))
    populateSpoList(api)
    populateHrvList(api)

    vo2max, activity_dt = get_vo2max_from_fit(api)
    if vo2max is not None:
        store_vo2max(activity_dt, vo2max)
        vo2max_wellness(vo2max, activity_dt.date())
    else:
        print("VO2max not found in latest FIT file, skipping wellness update")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n🚪 Exiting on user interrupt!")
    except Exception as e:
        print(f"\n Unexpected error: {e}")
