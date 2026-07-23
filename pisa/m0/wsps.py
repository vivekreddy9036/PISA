import config

_GRADES = config.WSPS_GRADES
_W = config.WSPS_WEIGHTS
_NON_OVERLAPPING = config.NON_OVERLAPPING_CHANNELS


def score_network(network: dict) -> tuple[int, str]:
    """Return (score 0-100, grade A-F) for a beacon-derived network dict."""
    score = 0

    enc = network.get("encryption", "Open")
    score += _W["encryption"].get(enc, 0)

    ch = network.get("channel")
    if ch in _NON_OVERLAPPING:
        score += _W["channel_bonus"]
    elif ch is not None:
        score += 5

    sig = network.get("signal_dbm")
    if sig is not None:
        if sig > -50:
            score += _W["signal_excellent"]
        elif sig > -70:
            score += _W["signal_good"]
        elif sig > -85:
            score += _W["signal_fair"]

    bi = network.get("beacon_interval")
    if bi == 100:
        score += _W["beacon_interval_bonus"]
    elif bi is not None:
        score += 5

    if network.get("hidden"):
        score += _W["hidden_ssid_penalty"]

    if network.get("pmf_enabled"):
        score += _W["pmf_bonus"]

    if network.get("wps_enabled"):
        score += _W["wps_penalty"]

    score = max(0, min(score, 100))
    grade = next((g for g, threshold in _GRADES if score >= threshold), "F")
    return score, grade
