"""Cross-protocol confidence fusion: combine per-protocol probe features
(each optionally carrying a device_type_hint + confidence) with the
existing mDNS-derived guess (pisa/m1/mdns_discover.py) into one
device_type + confidence.
"""
import re
from dataclasses import dataclass, field

# Baseline weight for the mDNS-derived device_type M1 may have already
# set, so a single low-confidence protocol hint doesn't override a
# self-announced mDNS name for no reason, but two or more agreeing
# protocol signals still can.
_MDNS_BASELINE_CONFIDENCE = 0.5

# feature_keys whose feature_value is a banner string that may identify a
# product (and, embedded in it, a version) rather than just confirm a
# protocol is present — see .scratch/pisa-phase2-identity-audit.md §1.
# device_type_hint is deliberately None on both in http_probe.py/
# rtsp_probe.py, so fuse() already ignores them for device_type — this is
# the only place they're read.
_PRODUCT_BANNER_KEYS = ("http.server", "rtsp.server")

_VERSION_RE = re.compile(r"\d+(?:\.\d+){1,3}")


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


@dataclass
class DeviceIdentity:
    """Structured identity result (Phase 2). Conceptually the same
    conclusion fuse() reaches for device_type, widened to vendor/product/
    model/firmware/version — with `evidence` carrying enough per-field
    provenance to answer "why did you believe this" without a new DB
    table (see the Phase 2 audit doc, §5). Any field PISA has no evidence
    for is None, never guessed."""
    vendor: str | None = None
    product: str | None = None
    model: str | None = None
    firmware: str | None = None
    version: str | None = None
    device_type: str | None = None
    confidence: float = 0.0
    evidence: list[dict] = field(default_factory=list)


def _parse_banner(value: str) -> tuple[str | None, str | None]:
    """Best-effort split of a Server-header-style banner into
    (product, version). Handles the common "Product/Version" and
    "Product Version" conventions (nginx/1.18.0, uc-httpd 1.0.0). Returns
    (value, None) unchanged when no version-like token is found — never
    invents a version, and never attributes the banner to `vendor`: a
    software banner identifies software, not necessarily who manufactured
    the hardware it runs on (see audit doc §6)."""
    value = (value or "").strip()
    if not value:
        return None, None
    match = _VERSION_RE.search(value)
    if not match:
        return value, None
    version = match.group(0)
    product = value[: match.start()].strip(" /")
    return (product or None), version


def fuse_identity(
    oui_vendor: str | None,
    probe_results: list[dict],
    device_type: str | None = None,
    device_type_confidence: float = 0.0,
) -> DeviceIdentity:
    """Build a structured DeviceIdentity from the same probe evidence
    fuse() already receives, plus the OUI vendor already computed at M1
    discovery time (pisa/m0/oui_cve.py::bssid_to_vendor, stored in
    devices.vendor). Does not recompute device_type — callers pass
    fuse()'s own result straight through, so this function adds new
    fields without changing how the existing one is decided (fuse()'s
    tests and behavior are untouched by this phase).

    model/firmware have no evidence source today (see audit doc §6) and
    are always None — that is the correct output, not a shortfall.
    """
    evidence: list[dict] = []

    vendor = oui_vendor if oui_vendor and oui_vendor != "Unknown" else None
    if vendor:
        # Synthesized, not a fingerprint_signatures row — the OUI lookup
        # itself is never logged as one (audit doc §4). Describes a real
        # computation that already happened, not a fabricated one.
        evidence.append({"field": "vendor", "source": "oui", "value": vendor, "confidence": None})

    product: str | None = None
    product_confidence = 0.0
    version: str | None = None

    for feature in probe_results:
        if feature.get("feature_key") not in _PRODUCT_BANNER_KEYS:
            continue
        parsed_product, parsed_version = _parse_banner(feature.get("feature_value") or "")
        if not parsed_product:
            continue
        confidence = feature.get("confidence") or 0.0
        evidence.append({
            "field": "product", "source": feature["feature_key"],
            "value": parsed_product, "confidence": confidence,
        })
        if parsed_version:
            evidence.append({
                "field": "version", "source": feature["feature_key"],
                "value": parsed_version, "confidence": confidence,
            })
        # Highest-confidence banner wins on conflict — same rule fuse()
        # already uses for device_type (max(scores, key=scores.get)), not
        # a new policy invented for this function. Ties keep the
        # first-seen candidate (strict `>`, not `>=`).
        if confidence > product_confidence:
            product, product_confidence, version = parsed_product, confidence, parsed_version

    if device_type:
        evidence.append({
            "field": "device_type", "source": "fuse()",
            "value": device_type, "confidence": device_type_confidence,
        })

    return DeviceIdentity(
        vendor=vendor,
        product=product,
        model=None,
        firmware=None,
        version=version,
        device_type=device_type,
        confidence=device_type_confidence,
        evidence=evidence,
    )
