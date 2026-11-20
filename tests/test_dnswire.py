import struct
import unittest
from soclab.dnswire import encode_qname, decode_qname, make_query, parse_query, make_response, validate_response


class DNSWireTests(unittest.TestCase):
    def test_ptr_round_trip(self):
        packet = make_query(455, "20.2.0.192.in-addr.arpa.")
        txid, name, offset = parse_query(packet)
        self.assertEqual((txid, name), (455, "20.2.0.192.in-addr.arpa."))
        self.assertEqual(offset + 4, len(packet))
        validate_response(make_response(packet), 455)

    def test_reject_invalid_transaction_id(self):
        with self.assertRaises(ValueError):
            validate_response(make_response(make_query(45, "10.0.0.127.in-addr.arpa.")), 46)

    def test_truncated_dns_query(self):
        with self.assertRaises(ValueError):
            parse_query(b"\x01" * 10)

    def test_reject_non_ptr_query(self):
        packet = bytearray(make_query(1, "20.2.0.192.in-addr.arpa."))
        packet[-4:-2] = struct.pack("!H", 1)
        with self.assertRaises(ValueError):
            parse_query(bytes(packet))

    def test_reject_malformed_compression_pointer(self):
        packet = bytearray(make_query(1, "20.2.0.192.in-addr.arpa."))
        packet[12] = 0xC0
        with self.assertRaises(ValueError):
            parse_query(bytes(packet))

    def test_long_label_rejected(self):
        with self.assertRaises(ValueError):
            encode_qname("a" * 64 + ".example.org.")

    def test_encoding(self):
        encoded = encode_qname("node.lab.invalid.")
        name, end = decode_qname(b"\x00" * 12 + encoded)
        self.assertEqual(name, "node.lab.invalid.")
        self.assertEqual(end, 12 + len(encoded))


if __name__ == "__main__":
    unittest.main()
