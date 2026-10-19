from tests.v3.test_scanner_real import loopback_seam  # noqa


def test_debug_in_test(loopback_seam):
    from services.scanner import port_scanner as ps
    import utils.egress as eg
    print("IN-TEST ps:", ps.resolve_validated_ips, "eg:", eg.resolve_validated_ips)


def test_debug_after():
    from services.scanner import port_scanner as ps
    import utils.egress as eg
    print("AFTER ps:", ps.resolve_validated_ips, "eg:", eg.resolve_validated_ips)
