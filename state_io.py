
"""
Utilities for saving/loading Stage-2 rolling states between runs.

Design:
- One row per hour.
- One column per server state: Ti_<i>, To_<i>.
- Scalar columns for SoC_final, TRCU_final, QRCU_final, PS1_final, PS2_final (extend if needed).
"""
from __future__ import annotations

import os
from typing import Dict, Optional

import numpy as np
import pandas as pd


def load_state(csv_path: str, hour: int, n_servers: int) -> Optional[Dict[str, object]]:
    """
    Load the *previous* hour state (row position = hour) from csv_path.
    Returns None if hour < 0 or file missing.
    """
    if hour < 0 or (not os.path.isfile(csv_path)):
        return None

    df = pd.read_csv(csv_path)
    if hour >= len(df):
        return None

    row = df.iloc[hour]

    # Validate required columns
    req_cols = [f"Ti_{i}" for i in range(n_servers)] + [f"To_{i}" for i in range(n_servers)] + [
        "SoC_final", "TRCU_final", "QRCU_final", "PS1_final", "PS2_final"
    ]
    missing = [c for c in req_cols if c not in df.columns]
    if missing:
        raise KeyError(f"{csv_path} is missing columns: {missing}")

    # Extract
    Ti = np.array([row[f"Ti_{i}"] for i in range(n_servers)], dtype=float)
    To = np.array([row[f"To_{i}"] for i in range(n_servers)], dtype=float)

    # Basic NaN check (prevents spiky resets)
    if np.isnan(Ti).any() or np.isnan(To).any() or pd.isna(row["SoC_final"]):
        raise ValueError(f"{csv_path} row {hour} contains NaNs; cannot initialise MPC safely.")

    X0 = np.concatenate([Ti, To])

    U0 = np.array([row["TRCU_final"], row["QRCU_final"], row["PS1_final"], row["PS2_final"]], dtype=float)

    return {"X0": X0, "Ti": Ti, "To": To, "SoC_0": float(row["SoC_final"]), "U0": U0}


def save_state(csv_path: str, hour: int, Ti: np.ndarray, To: np.ndarray, SoC: float, U: np.ndarray) -> None:
    """
    Save final state for a given hour, overwriting row position = hour.
    Creates file if missing, and adds any new columns if server count increases.
    """
    Ti = np.asarray(Ti, dtype=float)
    To = np.asarray(To, dtype=float)
    U = np.asarray(U, dtype=float)
    n_servers = len(Ti)

    row = {}
    for i in range(n_servers):
        row[f"Ti_{i}"] = float(Ti[i])
        row[f"To_{i}"] = float(To[i])

    row.update({
        "SoC_final": float(SoC),
        "TRCU_final": float(U[0]),
        "QRCU_final": float(U[1]),
        "PS1_final": float(U[2]),
        "PS2_final": float(U[3]),
    })

    row_df = pd.DataFrame([row])

    if os.path.isfile(csv_path):
        df = pd.read_csv(csv_path)
    else:
        df = pd.DataFrame(columns=row_df.columns)

    # Ensure all new columns exist
    for col in row_df.columns:
        if col not in df.columns:
            df[col] = np.nan

    # Ensure df has enough rows
    if hour >= len(df):
        # Extend with empty rows up to 'hour'
        extra = pd.DataFrame(np.nan, index=range(len(df), hour + 1), columns=df.columns)
        df = pd.concat([df, extra], ignore_index=True)

    df.iloc[hour] = row_df.iloc[0]
    df.to_csv(csv_path, index=False)
