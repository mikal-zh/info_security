# PROJECT, 2026
# info_security
# File description:
# Timing helpers: repeated runs and robust summary statistics.

"""Timing helpers: repeated runs and robust summary statistics.

Runs use time.perf_counter_ns with the garbage collector disabled, after
discarded warm-up runs. The median and interquartile range are reported
because they are robust to outliers caused by scheduler noise.
"""

import gc
import statistics
import time


def time_ns(func, repeats: int, warmup: int) -> list[int]:
    """Call `func` warmup + repeats times; return the timed durations."""
    for _ in range(warmup):
        func()
    samples = []
    gc.disable()
    try:
        for _ in range(repeats):
            start = time.perf_counter_ns()
            func()
            samples.append(time.perf_counter_ns() - start)
    finally:
        gc.enable()
    return samples


def summarise(samples_ns: list[int]) -> dict:
    """Median, first and third quartile in milliseconds, and the count."""
    millis = []
    for sample in samples_ns:
        millis.append(sample / 1e6)
    millis.sort()
    median = statistics.median(millis)
    if len(millis) >= 4:
        first, _, third = statistics.quantiles(millis, n=4)
    else:
        first, third = millis[0], millis[-1]
    return {"median_ms": median, "q1_ms": first, "q3_ms": third,
            "n": len(millis)}
