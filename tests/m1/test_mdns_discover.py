from scapy.layers.dns import DNS, DNSRR

from pisa.m1 import mdns_discover


def _dns_response(*ptr_pairs) -> DNS:
    """Build a real, round-trip-parsed DNS response with PTR answers, the
    same way tests/m0/test_beacon_capture.py builds real scapy packets
    rather than mocking scapy itself. ptr_pairs is (rrname, rdata) tuples.

    Multiple answers must be chained with `/` (scapy's DNS RR list field
    convention) — passing a plain Python list silently only serializes the
    first record.
    """
    answers = None
    for rrname, rdata in ptr_pairs:
        rr = DNSRR(rrname=rrname, type=12, rclass=1, ttl=120, rdata=rdata)
        answers = rr if answers is None else answers / rr
    return DNS(DNS(id=0, qr=1, aa=1, qd=None, an=answers).build())


def test_ptr_targets_extracts_rdata_from_answers():
    dns = _dns_response(("_services._dns-sd._udp.local.", "_airplay._tcp.local."))
    assert mdns_discover._ptr_targets(dns) == ["_airplay._tcp.local."]


def test_ptr_targets_ignores_non_ptr_records():
    # A record (type 1), not PTR (type 12) - should be skipped
    dns = DNS(DNS(id=0, qr=1, qd=None, an=[
        DNSRR(rrname="host.local.", type=1, rclass=1, ttl=120, rdata="1.2.3.4"),
    ]).build())
    assert mdns_discover._ptr_targets(dns) == []


def test_discover_service_types_groups_by_source_ip(monkeypatch):
    def fake_send_and_collect(qname, timeout):
        assert qname == mdns_discover._META_SERVICE
        return [
            ("11.12.3.135", _dns_response(("x", "_airplay._tcp.local."), ("x", "_raop._tcp.local."))),
            ("11.12.6.68", _dns_response(("x", "_nvstream_dbd._tcp.local."))),
        ]

    monkeypatch.setattr(mdns_discover, "_send_and_collect", fake_send_and_collect)

    result = mdns_discover.discover_service_types()

    assert result["11.12.3.135"] == {"_airplay._tcp.local.", "_raop._tcp.local."}
    assert result["11.12.6.68"] == {"_nvstream_dbd._tcp.local."}


def test_discover_instance_names_strips_service_type_suffix(monkeypatch):
    def fake_send_and_collect(qname, timeout):
        assert qname == "_airplay._tcp.local."
        return [("11.12.4.184", _dns_response(
            ("_airplay._tcp.local.", "sumana's MacBook Air._airplay._tcp.local."),
        ))]

    monkeypatch.setattr(mdns_discover, "_send_and_collect", fake_send_and_collect)

    result = mdns_discover.discover_instance_names("_airplay._tcp.local.")

    assert result["11.12.4.184"] == ["sumana's MacBook Air"]


def test_identify_hosts_merges_types_and_names_scoped_to_target_ips(monkeypatch):
    calls = []

    def fake_send_and_collect(qname, timeout):
        calls.append(qname)
        if qname == mdns_discover._META_SERVICE:
            return [
                ("11.12.4.184", _dns_response(("x", "_airplay._tcp.local."))),
                ("11.12.9.9", _dns_response(("x", "_smb._tcp.local."))),  # not in target_ips
            ]
        if qname == "_airplay._tcp.local.":
            return [("11.12.4.184", _dns_response(
                ("_airplay._tcp.local.", "sumana's MacBook Air._airplay._tcp.local."),
            ))]
        raise AssertionError(f"unexpected query for {qname}")

    monkeypatch.setattr(mdns_discover, "_send_and_collect", fake_send_and_collect)

    result = mdns_discover.identify_hosts({"11.12.4.184"})

    assert result == {
        "11.12.4.184": {"name": "sumana's MacBook Air", "device_type": "Apple device (AirPlay)"},
    }
    # only queried the meta-service plus the one service type relevant to
    # our target_ips, never "_smb._tcp.local." (belongs to an out-of-scope host)
    assert calls == [mdns_discover._META_SERVICE, "_airplay._tcp.local."]


def test_identify_hosts_falls_back_to_cleaned_label_without_instance_name(monkeypatch):
    def fake_send_and_collect(qname, timeout):
        if qname == mdns_discover._META_SERVICE:
            return [("11.12.6.68", _dns_response(("x", "_expo._tcp.local.")))]
        return []  # no instance name resolved for _expo._tcp.local.

    monkeypatch.setattr(mdns_discover, "_send_and_collect", fake_send_and_collect)

    result = mdns_discover.identify_hosts({"11.12.6.68"})

    assert result["11.12.6.68"] == {"name": None, "device_type": "expo"}


def test_identify_hosts_returns_none_for_unresponsive_host(monkeypatch):
    monkeypatch.setattr(mdns_discover, "_send_and_collect", lambda qname, timeout: [])

    result = mdns_discover.identify_hosts({"11.12.0.1"})

    assert result == {"11.12.0.1": {"name": None, "device_type": None}}
