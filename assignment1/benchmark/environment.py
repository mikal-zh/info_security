# PROJECT, 2026
# info_security
# File description:
# Description of the machine the benchmark ran on.

"""Description of the machine the benchmark ran on."""

import os
import platform
import time
from pathlib import Path

import Crypto

POWER_STATES = {"1": "mains", "0": "battery"}


def _cpu_info() -> tuple[str, bool]:
    """CPU model name and whether it has the AES-NI instruction set."""
    model, flags = platform.processor(), ""
    try:
        with open("/proc/cpuinfo", encoding="utf-8") as cpuinfo:
            for line in cpuinfo:
                if line.startswith("model name") and not model.strip():
                    model = line.split(":", 1)[1].strip()
                if line.startswith("flags"):
                    flags = line
                    break
    except OSError:
        pass
    return model, " aes " in flags


def _power_state() -> str:
    """'mains', 'battery' or 'unknown' (laptops throttle on battery)."""
    supplies = Path("/sys/class/power_supply").glob("A*/online")
    for supply in supplies:
        state = supply.read_text().strip()
        return POWER_STATES.get(state, "unknown")
    return "unknown"


def environment() -> dict:
    """Everything needed to reproduce or compare a benchmark run."""
    model, aes_ni = _cpu_info()
    return {
        "cpu": model, "aes_ni": aes_ni, "cores": os.cpu_count(),
        "power": _power_state(), "os": platform.platform(),
        "python": platform.python_version(),
        "pycryptodome": Crypto.__version__,
        "date": time.strftime("%Y-%m-%d %H:%M"),
    }
