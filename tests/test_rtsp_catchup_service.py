from services.rtsp_catchup_service import CombinedRtspUdpSession


def test_combined_transport_matches_stb_four_alternative_shape():
    value = CombinedRtspUdpSession._build_transport("10.0.0.8", 20000)

    alternatives = value.split(",")
    assert [item.split(";", 1)[0] for item in alternatives] == [
        "MP2T/RTP/UDP", "MP2T/RTP/TCP", "MP2T/UDP", "MP2T/TCP",
    ]
    assert sum("destination=10.0.0.8" in item for item in alternatives) == 4
    assert sum("client_port=20000-20001" in item for item in alternatives) == 2
    assert sum("interleaved=0-1" in item for item in alternatives) == 2


def test_rtp_payload_returns_mpegts_without_exposing_header():
    media = b"\x47" + b"\x00" * 187
    packet = bytes([0x80, 33]) + b"\x00" * 10 + media

    assert CombinedRtspUdpSession._rtp_payload(packet) == media
