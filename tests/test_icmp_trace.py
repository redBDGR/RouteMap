import socket
import struct
import unittest

from routemap import icmp_trace


def _outer_ip(payload: bytes) -> bytes:
    return bytes([0x45]) + bytes(19) + payload


def _time_exceeded_packet(identifier: int, seq: int) -> bytes:
    inner_icmp = struct.pack("!BBHHH", 8, 0, 0, identifier, seq) + b"data"
    inner_ip = bytes([0x45]) + bytes(19) + inner_icmp
    te_icmp = struct.pack("!BBHI", 11, 0, 0, 0) + inner_ip
    return _outer_ip(te_icmp)


def _echo_reply_packet(identifier: int, seq: int) -> bytes:
    icmp = struct.pack("!BBHHH", 0, 0, 0, identifier, seq) + b"data"
    return _outer_ip(icmp)


class FakeSocket:
    """Duck-types the subset of socket.socket that _send_probe touches, so
    the ICMP parsing/matching logic can be exercised without a real raw
    socket (which needs root/admin)."""

    def __init__(self, replies):
        self._replies = list(replies)
        self.sent = []

    def sendto(self, data, addr):
        self.sent.append((data, addr))

    def settimeout(self, t):
        pass

    def recvfrom(self, n):
        if not self._replies:
            raise socket.timeout()
        return self._replies.pop(0)


class TestSendProbe(unittest.TestCase):
    def test_time_exceeded_from_intermediate_hop(self):
        packet = _time_exceeded_packet(identifier=42, seq=1)
        sock = FakeSocket([(packet, ("10.0.0.1", 0))])

        probe, reached = icmp_trace._send_probe(sock, "8.8.8.8", 42, 1, timeout=1.0)

        self.assertEqual(probe.responder_ip, "10.0.0.1")
        self.assertFalse(probe.timed_out)
        self.assertFalse(reached)

    def test_echo_reply_from_destination_marks_reached(self):
        packet = _echo_reply_packet(identifier=42, seq=1)
        sock = FakeSocket([(packet, ("8.8.8.8", 0))])

        probe, reached = icmp_trace._send_probe(sock, "8.8.8.8", 42, 1, timeout=1.0)

        self.assertEqual(probe.responder_ip, "8.8.8.8")
        self.assertTrue(reached)

    def test_mismatched_identifier_is_ignored(self):
        # Simulates a stray ICMP reply from unrelated traffic on the shared
        # raw socket — must not be mistaken for our probe's reply.
        packet = _echo_reply_packet(identifier=999, seq=1)
        sock = FakeSocket([(packet, ("8.8.8.8", 0))])

        probe, reached = icmp_trace._send_probe(sock, "8.8.8.8", 42, 1, timeout=0.01)

        self.assertTrue(probe.timed_out)
        self.assertFalse(reached)

    def test_no_reply_times_out(self):
        sock = FakeSocket([])
        probe, reached = icmp_trace._send_probe(sock, "8.8.8.8", 42, 1, timeout=0.01)
        self.assertTrue(probe.timed_out)
        self.assertFalse(reached)


class TestFixedFlowID(unittest.TestCase):
    def test_stable_for_same_target(self):
        self.assertEqual(icmp_trace._fixed_flow_id("8.8.8.8"), icmp_trace._fixed_flow_id("8.8.8.8"))

    def test_differs_across_targets(self):
        self.assertNotEqual(icmp_trace._fixed_flow_id("8.8.8.8"), icmp_trace._fixed_flow_id("1.1.1.1"))


if __name__ == "__main__":
    unittest.main()
