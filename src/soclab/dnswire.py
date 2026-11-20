"""Minimal RFC 1035 DNS PTR message encoding/decoding for a loopback-only responder.

This is deliberately NOT a recursive DNS server and must not be exposed to a network.
"""
from __future__ import annotations

import struct

QTYPE_PTR = 12
QCLASS_IN = 1


def encode_qname(name: str) -> bytes:
    out = bytearray()
    for part in name.rstrip(".").split("."):
        label = part.encode("ascii")
        if not label or len(label) > 63 or b"\x00" in label:
            raise ValueError("invalid DNS label")
        out.append(len(label))
        out.extend(label)
    out.append(0)
    if len(out) > 255:
        raise ValueError("DNS name too long")
    return bytes(out)


def decode_qname(data: bytes, offset: int = 12) -> tuple[str, int]:
    parts: list[str] = []
    size = 0
    while True:
        if offset >= len(data) or size > 255:
            raise ValueError("malformed DNS question")
        length = data[offset]
        offset += 1
        if length == 0:
            return ".".join(parts) + ".", offset
        if length > 63:  # DNS compression intentionally unsupported in queries
            raise ValueError("compressed or malformed name unsupported")
        if offset + length > len(data):
            raise ValueError("truncated DNS label")
        parts.append(data[offset:offset + length].decode("ascii"))
        offset += length
        size += length + 1


def make_query(transaction_id: int, qname: str) -> bytes:
    header = struct.pack("!HHHHHH", transaction_id, 0x0100, 1, 0, 0, 0)
    return header + encode_qname(qname) + struct.pack("!HH", QTYPE_PTR, QCLASS_IN)


def parse_query(data: bytes) -> tuple[int, str, int]:
    if len(data) < 17 or len(data) > 512:
        raise ValueError("invalid query length")
    transaction_id, flags, questions, answers, authority, extra = struct.unpack("!HHHHHH", data[:12])
    if flags & 0x8000 or questions != 1 or answers or authority or extra:
        raise ValueError("unsupported DNS question")
    qname, offset = decode_qname(data)
    if offset + 4 != len(data):
        raise ValueError("unexpected DNS question tail")
    qtype, qclass = struct.unpack("!HH", data[offset:])
    if (qtype, qclass) != (QTYPE_PTR, QCLASS_IN):
        raise ValueError("only PTR/IN supported")
    return transaction_id, qname, offset


def make_response(query: bytes, hostname: str = "node.lab.invalid.") -> bytes:
    txid, _, _ = parse_query(query)
    # 0x8180: standard response, recursion not available, one answer
    header = struct.pack("!HHHHHH", txid, 0x8180, 1, 1, 0, 0)
    question = query[12:]
    answer = b"\xc0\x0c" + struct.pack("!HHIH", QTYPE_PTR, QCLASS_IN, 30, len(encode_qname(hostname)))
    return header + question + answer + encode_qname(hostname)


def validate_response(data: bytes, expected_id: int) -> None:
    if len(data) < 12:
        raise ValueError("truncated response")
    txid, flags, qd, an, _, _ = struct.unpack("!HHHHHH", data[:12])
    if txid != expected_id or not flags & 0x8000 or qd != 1 or an != 1:
        raise ValueError("unexpected DNS response")
