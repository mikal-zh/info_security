# PROJECT, 2026
# info_security
# File description:
# Benchmark workloads sized like the real onboarding items.

"""Benchmark workloads sized like the real onboarding items.

Each workload is (name, size of one item in bytes, items per operation).
Inputs are random bytes: cipher speed does not depend on content, and
random data avoids accidental caching or compression effects.
"""

KB, MB = 1024, 1024 * 1024
FORM_FIELDS = 17

WORKLOADS = [
    ("single field (NIK)", 16, 1),
    ("full form (17 fields)", 40, FORM_FIELDS),
    ("KTP scan", 400 * KB, 1),
    ("contract PDF", 2 * MB, 1),
    ("interview video", 30 * MB, 1),
]

FILE_WORKLOADS = WORKLOADS[2:]


def repeats_for(total_bytes: int, quick: bool) -> int:
    """Timed runs per measurement: fewer for large items or a quick run."""
    if quick:
        return 5
    return 15 if total_bytes >= 10 * MB else 51
