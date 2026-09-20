import unittest

from routemap.packet_utils import checksum, split_ip_header


class TestChecksum(unittest.TestCase):
    def test_self_consistent(self):
        # Standard one's-complement identity: recomputing the checksum over
        # data that already contains its own correct checksum field yields 0.
        payload = b"hello world"
        header_zeroed = bytes([8, 0, 0, 0, 0x12, 0x34, 0x00, 0x01])
        csum = checksum(header_zeroed + payload)
        full = bytes([8, 0, (csum >> 8) & 0xFF, csum & 0xFF, 0x12, 0x34, 0x00, 0x01]) + payload
        self.assertEqual(checksum(full), 0)

    def test_odd_length_padding(self):
        # Must not raise on odd-length input.
        checksum(b"\x01\x02\x03")


class TestSplitIPHeader(unittest.TestCase):
    def test_no_options(self):
        ip_header = bytes([0x45]) + bytes(19)  # version 4, IHL=5 (20 bytes)
        body = b"payload"
        ihl, rest = split_ip_header(ip_header + body)
        self.assertEqual(ihl, 20)
        self.assertEqual(rest, body)

    def test_with_options(self):
        ip_header = bytes([0x46]) + bytes(23)  # IHL=6 (24 bytes)
        body = b"payload"
        ihl, rest = split_ip_header(ip_header + body)
        self.assertEqual(ihl, 24)
        self.assertEqual(rest, body)


if __name__ == "__main__":
    unittest.main()
