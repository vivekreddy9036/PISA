"""Cross-protocol confidence fusion: combine per-protocol probe features
(each optionally carrying a device_type_hint + confidence) with the
existing mDNS-derived guess (pisa/m1/mdns_discover.py) into one
device_type + confidence.
"""

# Baseline weight for the mDNS-derived device_type M1 may have already
# set, so a single low-confidence protocol hint doesn't override a
# self-announced mDNS name for no reason, but two or more agreeing
# protocol signals still can.
_MDNS_BASELINE_CONFIDENCE = 0.5


def fuse(existing_device_type: str | None, probe_results: list[dict]) -> tuple[str | None, float]:
    """Group candidates by device_type_hint, sum their confidence (capped
    at 1.0), return the highest-scoring (device_type, confidence). Pure
    function, no I/O — unit-testable offline like WSPS (NFR-2)."""
    scores: dict[str, float] = {}
    if existing_device_type:
        scores[existing_device_type] = _MDNS_BASELINE_CONFIDENCE

    for feature in probe_results:
        hint = feature.get("device_type_hint")
        if not hint:
            continue
        confidence = feature.get("confidence") or 0.0
        scores[hint] = min(1.0, scores.get(hint, 0.0) + confidence)

    if not scores:
        return existing_device_type, 0.0

    best_type = max(scores, key=scores.get)
    return best_type, scores[best_type]
