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


# ---------------------------------------------------------------------------
# Phase 2: structured identity (fuse_identity / DeviceIdentity)
# ---------------------------------------------------------------------------

def test_parse_banner_splits_product_and_version():
    assert fusion._parse_banner("nginx/1.18.0") == ("nginx", "1.18.0")
    assert fusion._parse_banner("uc-httpd 1.0.0") == ("uc-httpd", "1.0.0")


def test_parse_banner_no_version_returns_product_only():
    assert fusion._parse_banner("GoAhead-Webs") == ("GoAhead-Webs", None)


def test_parse_banner_empty_returns_none_none():
    assert fusion._parse_banner("") == (None, None)
    assert fusion._parse_banner(None) == (None, None)


def test_fuse_identity_vendor_only_no_protocol_evidence():
    identity = fusion.fuse_identity("Hangzhou Xiongmai Technology", [])

    assert identity.vendor == "Hangzhou Xiongmai Technology"
    assert identity.product is None
    assert identity.model is None
    assert identity.firmware is None
    assert identity.version is None
    assert identity.evidence == [
        {"field": "vendor", "source": "oui", "value": "Hangzhou Xiongmai Technology", "confidence": None}
    ]


def test_fuse_identity_vendor_and_product_from_http_banner():
    identity = fusion.fuse_identity("Hangzhou Xiongmai Technology", [
        {"feature_key": "http.server", "feature_value": "uc-httpd 1.0.0", "confidence": 0.5, "device_type_hint": None},
    ])

    assert identity.vendor == "Hangzhou Xiongmai Technology"
    assert identity.product == "uc-httpd"
    assert identity.version == "1.0.0"


def test_fuse_identity_model_and_firmware_stay_none_without_evidence():
    """No current probe produces model/firmware — this is the correct
    output, not a shortfall (see audit doc §6), even when every other
    field is populated."""
    identity = fusion.fuse_identity("Some Vendor", [
        {"feature_key": "http.server", "feature_value": "nginx/1.18.0", "confidence": 0.5, "device_type_hint": None},
    ], device_type="Router", device_type_confidence=0.9)

    assert identity.model is None
    assert identity.firmware is None
    assert identity.vendor == "Some Vendor"
    assert identity.product == "nginx"
    assert identity.device_type == "Router"


def test_fuse_identity_conflicting_banners_highest_confidence_wins():
    """Two banners disagree on product — same conflict-resolution rule
    fuse() already uses for device_type (highest confidence wins), not a
    new policy invented for identity."""
    identity = fusion.fuse_identity(None, [
        {"feature_key": "http.server", "feature_value": "GoAhead-Webs/2.5", "confidence": 0.5, "device_type_hint": None},
        {"feature_key": "rtsp.server", "feature_value": "GStreamer/1.2.0", "confidence": 0.9, "device_type_hint": None},
    ])

    assert identity.product == "GStreamer"
    assert identity.version == "1.2.0"
    # both candidates are still recorded as evidence, even though only one won
    product_values = {e["value"] for e in identity.evidence if e["field"] == "product"}
    assert product_values == {"GoAhead-Webs", "GStreamer"}


def test_fuse_identity_returns_all_none_with_no_evidence_at_all():
    identity = fusion.fuse_identity(None, [])

    assert identity == fusion.DeviceIdentity()


def test_fuse_identity_unknown_oui_vendor_becomes_none():
    """bssid_to_vendor() returns the literal string "Unknown" for an
    unrecognized OUI (pisa/m0/oui_cve.py) — that must not be stored as if
    it were a real vendor name."""
    identity = fusion.fuse_identity("Unknown", [])

    assert identity.vendor is None
    assert identity.evidence == []


def test_fuse_identity_combines_multiple_protocol_evidence_sources():
    identity = fusion.fuse_identity("Some Vendor", [
        {"feature_key": "http.server", "feature_value": "nginx/1.18.0", "confidence": 0.5, "device_type_hint": None},
        {"feature_key": "mqtt.connack", "feature_value": "reason_code=0", "confidence": 0.9, "device_type_hint": "MQTT Broker"},
    ], device_type="MQTT Broker", device_type_confidence=0.9)

    assert identity.vendor == "Some Vendor"
    assert identity.product == "nginx"
    assert identity.device_type == "MQTT Broker"
    sources = {e["source"] for e in identity.evidence}
    assert sources == {"oui", "http.server", "fuse()"}


def test_fuse_identity_confidence_matches_device_type_confidence():
    """No separate blended score is invented — confidence is exactly the
    already-existing fuse() result, reused rather than duplicated (Phase 1
    deliberately didn't add a second confidence column)."""
    identity = fusion.fuse_identity(None, [], device_type="Router", device_type_confidence=0.73)

    assert identity.confidence == 0.73
