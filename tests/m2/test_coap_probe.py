from pisa.m2 import coap_probe


def test_probe_returns_feature_with_resources(monkeypatch):
    monkeypatch.setattr(
        coap_probe, "_get_well_known_core",
        lambda ip, port, timeout: b'</sensors/temp>;rt="temperature"',
    )

    features = coap_probe.probe("192.168.1.20", 5683, 3.0)

    assert len(features) == 1
    assert features[0]["protocol"] == "coap"
    assert features[0]["device_type_hint"] == "CoAP Device"
    assert features[0]["confidence"] == 0.85


def test_probe_lower_confidence_on_empty_resource_list(monkeypatch):
    monkeypatch.setattr(coap_probe, "_get_well_known_core", lambda ip, port, timeout: b"ok")

    features = coap_probe.probe("192.168.1.20", 5683, 3.0)

    assert features[0]["confidence"] == 0.4


def test_probe_returns_empty_on_no_response(monkeypatch):
    monkeypatch.setattr(coap_probe, "_get_well_known_core", lambda ip, port, timeout: None)

    assert coap_probe.probe("192.168.1.20", 5683, 3.0) == []
