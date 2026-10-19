def test_debug_in_test(loopback_seam):
    from services.scanner import port_scanner as ps
    import utils.egress as eg
    print("IN-TEST ps.resolve is eg.resolve?",
          ps.resolve_validated_ips is eg.resolve_validated_ips)


def test_debug_after():
    from services.scanner import port_scanner as ps
    import utils.egress as eg
    print("AFTER-TEST ps.resolve is eg.resolve?",
          ps.resolve_validated_ips is eg.resolve_validated_ips)
