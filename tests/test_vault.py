import tempfile
import unittest
from pathlib import Path

from routemap import vault
from routemap.models import Hop, Probe, Result


def _probe(ip: str, rtt_ms: float, method: str = "icmp") -> Probe:
    return Probe(method=method, responder_ip=ip, rtt=rtt_ms / 1000.0)


class TestVaultBuild(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmpdir.cleanup)
        self.out = Path(self.tmpdir.name) / "vault"

    def test_generates_a_node_for_every_hop_including_silent_ones(self):
        results = [
            Result(
                target="8.8.8.8",
                resolved_ip="8.8.8.8",
                reached=True,
                hops=[
                    Hop(ttl=1, probes=[_probe("192.168.1.1", 2)]),
                    Hop(ttl=2, probes=[Probe(timed_out=True)]),  # silent hop — still gets a node
                    Hop(ttl=3, probes=[_probe("203.0.113.1", 12)]),
                    Hop(ttl=4, probes=[_probe("8.8.8.8", 20)], reached_destination=True),
                ],
            ),
            Result(
                target="10.99.99.99",
                resolved_ip="10.99.99.99",
                reached=False,
                hops=[Hop(ttl=1, probes=[_probe("192.168.1.1", 1)])],
            ),
        ]

        vault.build(results, str(self.out))

        self.assertTrue((self.out / "Home.md").exists())
        self.assertTrue((self.out / "Nodes" / "192.168.1.1.md").exists())
        self.assertTrue((self.out / "Nodes" / "203.0.113.1.md").exists())
        self.assertTrue((self.out / "Nodes" / "8.8.8.8.md").exists())
        self.assertTrue((self.out / "Targets" / "Target - 8.8.8.8.md").exists())
        self.assertTrue((self.out / "Targets" / "Target - 10.99.99.99.md").exists())

        placeholder_note = list((self.out / "Nodes").glob("Unresponsive hop 2*.md"))
        self.assertEqual(len(placeholder_note), 1)
        self.assertIn("Unidentified — no response at this hop", placeholder_note[0].read_text())

        target_note = (self.out / "Targets" / "Target - 8.8.8.8.md").read_text()
        self.assertIn("[[192.168.1.1]]", target_note)
        self.assertIn("[[203.0.113.1]]", target_note)
        self.assertIn("no response", target_note)  # placeholder hop shown inline
        self.assertIn("destination", target_note)
        self.assertEqual(target_note.count("\n1. ") + target_note.count("\n2. ") + target_note.count("\n3. ") + target_note.count("\n4. "), 4)

        gateway_note = (self.out / "Nodes" / "192.168.1.1.md").read_text()
        self.assertIn("Internal (private address space)", gateway_note)
        # The gateway's next hop was silent — it should link to the placeholder, not skip past it.
        self.assertIn("Unresponsive hop 2", gateway_note)

        edge_target_note = (self.out / "Nodes" / "203.0.113.1.md").read_text()
        self.assertIn("External", edge_target_note)
        self.assertIn("Unresponsive hop 2", edge_target_note)  # incoming edge from the placeholder
        self.assertIn("→ [[8.8.8.8]]", edge_target_note)  # outgoing edge

    def test_sanitizes_unsafe_filename_characters(self):
        results = [Result(target="weird:name?.local", resolved_ip="10.0.0.5", reached=False)]
        vault.build(results, str(self.out))
        matches = list((self.out / "Targets").glob("Target - weird-name-.local.md"))
        self.assertEqual(len(matches), 1)


if __name__ == "__main__":
    unittest.main()
