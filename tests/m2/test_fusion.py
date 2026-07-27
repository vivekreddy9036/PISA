from pisa.m2 import fusion


def test_fuse_prefers_higher_confidence_candidate():
    device_type, confidence = fusion.fuse(None, [
        {"device_type_hint": "IP Camera", "confidence": 0.9},
        {"device_type_hint": "MQTT Broker", "confidence": 0.5},
    ])

    assert device_type == "IP Camera"
    assert confidence == 0.9


def test_fuse_sums_confidence_for_same_hint():
    device_type, confidence = fusion.fuse(None, [
        {"device_type_hint": "IP Camera", "confidence": 0.5},
        {"device_type_hint": "IP Camera", "confidence": 0.4},
    ])

    assert device_type == "IP Camera"
    assert confidence == 0.9


def test_fuse_caps_confidence_at_one():
    _, confidence = fusion.fuse(None, [
        {"device_type_hint": "IP Camera", "confidence": 0.9},
        {"device_type_hint": "IP Camera", "confidence": 0.8},
    ])

    assert confidence == 1.0


def test_fuse_includes_existing_mdns_type_as_baseline_candidate():
    device_type, confidence = fusion.fuse("Apple device (AirPlay)", [])

    assert device_type == "Apple device (AirPlay)"
    assert confidence == 0.5


def test_fuse_protocol_signal_can_override_mdns_baseline():
    device_type, _ = fusion.fuse("Apple device (AirPlay)", [
        {"device_type_hint": "IP Camera", "confidence": 0.9},
    ])

    assert device_type == "IP Camera"


def test_fuse_ignores_features_without_hint():
    device_type, confidence = fusion.fuse(None, [
        {"feature_key": "http.server", "feature_value": "nginx", "confidence": 0.5, "device_type_hint": None},
    ])

    assert device_type is None
    assert confidence == 0.0


def test_fuse_returns_none_with_no_candidates():
    assert fusion.fuse(None, []) == (None, 0.0)
