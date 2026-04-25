#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import datetime
import sqlite3
from pprint import pprint
from time import sleep
import logging
import os
import sys
from pathlib import Path

from intervalsicu import Intervals

from garmin_client import (
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
               db.execute(sql, [ts.timestamp(), rec["spo2Reading"], rec["readingConfidence"]])
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
                start = rec.get("startTimestampGMT")
                hrv_value = rec.get("hrv5MinAvg")
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


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n🚪 Exiting on user interrupt!")
    except Exception as e:
        print(f"\n Unexpected error: {e}")
