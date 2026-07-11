from pisa.m0.wsps import score_network


def test_wpa3_non_overlapping_strong_signal_gets_high_score():
    net = {"encryption": "WPA3", "channel": 6, "signal_dbm": -45,
           "beacon_interval": 100, "pmf_enabled": 1, "hidden": 0}
    score, grade = score_network(net)
    assert grade in ("A", "B")
    assert score >= 75


def test_open_network_gets_low_score():
    net = {"encryption": "Open", "channel": 3, "signal_dbm": -80,
           "beacon_interval": 200, "pmf_enabled": 0, "hidden": 0}
    score, grade = score_network(net)
    assert grade in ("D", "E", "F")
    assert score < 45


def test_hidden_ssid_applies_penalty():
    net_visible = {"encryption": "WPA2", "channel": 1, "signal_dbm": -60,
                   "beacon_interval": 100, "pmf_enabled": 0, "hidden": 0}
    net_hidden  = {**net_visible, "hidden": 1}
    score_v, _ = score_network(net_visible)
    score_h, _ = score_network(net_hidden)
    assert score_h < score_v


def test_score_clamped_to_100():
    net = {"encryption": "WPA3", "channel": 1, "signal_dbm": -30,
           "beacon_interval": 100, "pmf_enabled": 1, "hidden": 0}
    score, _ = score_network(net)
    assert 0 <= score <= 100


def test_missing_fields_do_not_crash():
    score, grade = score_network({})
    assert isinstance(score, int)
    assert grade in ("A", "B", "C", "D", "E", "F")
