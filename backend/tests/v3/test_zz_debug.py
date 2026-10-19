def test_debug_guard_state():
    from services.scanner import port_scanner as ps
    import utils.egress as eg

    print("ps.resolve_validated_ips is eg.resolve_validated_ips:",
          ps.resolve_validated_ips is eg.resolve_validated_ips)
    print("ps.resolve repr:", ps.resolve_validated_ips)
    print("ps.open_tcp_ip repr:", ps.open_tcp_ip)
    import socket
    print("socket.getaddrinfo:", socket.getaddrinfo)
    try:
        ips = ps.resolve_validated_ips("localhost", 80)
        print("RESOLVE SUCCEEDED:", ips)
    except Exception as e:
        print("resolve raised:", type(e).__name__, e)
    try:
        out = ps.scan_ports("localhost")
        print("SCAN RETURNED", out[:3])
    except Exception as e:
        print("scan raised:", type(e).__name__, e)
