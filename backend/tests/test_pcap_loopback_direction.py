

def test_same_ip_both_ends_direction_uses_port():
    """Loopback / host-to-itself: both ends share one IP. Direction must come
    from (IP, port); an IP-only test counted every byte as src_bytes and never
    saw the second FIN (found by a real loopback capture)."""
    import io
    import dpkt
    from app.ingestion.pcap import parse_pcap_bytes

    def pkt(sp, dp, flags, n):
        t = dpkt.tcp.TCP(sport=sp, dport=dp, flags=flags, data=b"x" * n)
        ip = dpkt.ip.IP(src=b"\x7f\x00\x00\x01", dst=b"\x7f\x00\x00\x01", p=6, data=t)
        ip.len = 20 + len(bytes(t))
        return bytes(dpkt.ethernet.Ethernet(dst=b"\0" * 6, src=b"\0" * 6, type=0x0800, data=ip))

    buf = io.BytesIO()
    w = dpkt.pcap.Writer(buf)
    for i, (sp, dp, fl, n) in enumerate([(40000, 80, 0x02, 0), (80, 40000, 0x12, 0), (40000, 80, 0x18, 300),
                                         (80, 40000, 0x18, 5000), (40000, 80, 0x11, 0), (80, 40000, 0x11, 0)]):
        w.writepkt(pkt(sp, dp, fl, n), 1.7e9 + i * 0.001)
    df = parse_pcap_bytes(buf.getvalue())
    assert len(df) == 1, "two FINs must close the flow exactly once"
    assert df.iloc[0]["dst_bytes"] > 5000 and 300 < df.iloc[0]["src_bytes"] < 1000
