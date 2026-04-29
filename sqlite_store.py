########################################################################################################################

import sqlite3
import typing as T

import omronconnect as OC

########################################################################################################################

_BP_TABLE_SQL = """
    CREATE TABLE IF NOT EXISTS blood_pressure (
        \"timestamp_utc_ms\"  INTEGER NOT NULL UNIQUE,
        \"systolic\"          INTEGER NOT NULL,
        \"diastolic\"         INTEGER NOT NULL,
        \"pulse\"             INTEGER NOT NULL,
        \"timezone\"          TEXT,
        \"irregular_hb\"      INTEGER,
        \"movement_detect\"   INTEGER,
        \"cuff_wrap_detect\"  INTEGER,
        \"notes\"             TEXT,
        PRIMARY KEY(\"timestamp_utc_ms\")
    )
"""

_WEIGHT_TABLE_SQL = """
    CREATE TABLE IF NOT EXISTS weight (
        \"timestamp_utc_ms\"      INTEGER NOT NULL UNIQUE,
        \"weight_kg\"             REAL NOT NULL,
        \"bmi\"                   REAL,
        \"body_fat_pct\"          REAL,
        \"resting_metabolism\"    REAL,
        \"skeletal_muscle_pct\"   REAL,
        \"visceral_fat_level\"    REAL,
        \"metabolic_age\"         INTEGER,
        \"notes\"                 TEXT,
        PRIMARY KEY(\"timestamp_utc_ms\")
    )
"""

########################################################################################################################


def store_bp_measurement(db_path: str, bpm: OC.BPMeasurement) -> bool:
    db = sqlite3.connect(db_path)
    db.execute(_BP_TABLE_SQL)
    db.execute(
        "INSERT OR IGNORE INTO blood_pressure VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        [
            bpm.measurementDate,
            bpm.systolic,
            bpm.diastolic,
            bpm.pulse,
            str(bpm.timeZone),
            int(bpm.irregularHB),
            int(bpm.movementDetect),
            int(bpm.cuffWrapDetect),
            bpm.notes,
        ],
    )
    db.commit()
    db.close()
    return True


def store_weight_measurement(db_path: str, wm: OC.WeightMeasurement) -> bool:
    db = sqlite3.connect(db_path)
    db.execute(_WEIGHT_TABLE_SQL)
    db.execute(
        "INSERT OR IGNORE INTO weight VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        [
            wm.measurementDate,
            wm.weight,
            wm.bmiValue if wm.bmiValue > 0 else None,
            wm.bodyFatPercentage if wm.bodyFatPercentage > 0 else None,
            wm.restingMetabolism if wm.restingMetabolism > 0 else None,
            wm.skeletalMusclePercentage if wm.skeletalMusclePercentage > 0 else None,
            wm.visceralFatLevel if wm.visceralFatLevel > 0 else None,
            wm.metabolicAge if wm.metabolicAge > 0 else None,
            wm.notes,
        ],
    )
    db.commit()
    db.close()
    return True


########################################################################################################################


def store_measurements(sqlite_dir: str, measurements: T.List[OC.MeasurementTypes]) -> None:
    import os

    bp_path = os.path.join(sqlite_dir, "blood_pressure.db3")
    weight_path = os.path.join(sqlite_dir, "weight.db3")

    for m in measurements:
        if isinstance(m, OC.BPMeasurement):
            store_bp_measurement(bp_path, m)
        elif isinstance(m, OC.WeightMeasurement):
            store_weight_measurement(weight_path, m)
