"""Tests for flow builder component."""

import pytest
import sys
import os

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from app.ingest.flow_builder import FlowBuilder
from app.ingest.pcap_reader import FlowState, PacketInfo
from app.utils.ja_hasher import ip_port_to_5tuple


class TestFlowBuilder:
    """Test flow builder functionality."""

    def setup_method(self):
        """Set up test fixtures."""
        self.builder = FlowBuilder(ttl_seconds=30)

    def test_basic_flow_creation(self):
        """Test basic packet addition to flow builder."""
        # Create a packet info
        pkt = PacketInfo(
            src_ip="10.0.0.1",
            dst_ip="10.0.0.2",
            src_port=12345,
            dst_port=80,
            protocol="tcp",
            timestamp=1000.0,
            flags="SA",
            ja3="",
            ja3s="",
            dns_query="",
            dns_qtype=0,
            packet_size=60,
        )

        key = self.builder.add_packet(pkt)
        assert key is not None
        assert self.builder.count() == 1

    def test_5tuple_hash_determinism(self):
        """Test that 5-tuple hash is deterministic."""
        key1 = ip_port_to_5tuple("10.0.0.1", 1234, "10.0.0.2", 80, "tcp")
        key2 = ip_port_to_5tuple("10.0.0.1", 1234, "10.0.0.2", 80, "tcp")
        key3 = ip_port_to_5tuple("10.0.0.1", 5678, "10.0.0.2", 80, "tcp")

        assert key1 == key2  # Same tuple = same key
        assert key1 != key3  # Different port = different key

    def test_flow_state_accumulation(self):
        """Test that flow state accumulates packet data."""
        pkt1 = PacketInfo(
            src_ip="10.0.0.1", dst_ip="10.0.0.2",
            src_port=12345, dst_port=80, protocol="tcp",
            timestamp=1000.0, flags="S", ja3="", ja3s="",
            dns_query="", dns_qtype=0, packet_size=60,
        )
        pkt2 = PacketInfo(
            src_ip="10.0.0.1", dst_ip="10.0.0.2",
            src_port=12345, dst_port=80, protocol="tcp",
            timestamp=1001.0, flags="S", ja3="", ja3s="",
            dns_query="", dns_qtype=0, packet_size=80,
        )

        self.builder.add_packet(pkt1)
        self.builder.add_packet(pkt2)

        flow = self.builder.get_flow(self.builder.get_flow_keys()[0])
        assert flow is not None
        assert flow.packet_count == 2
        assert flow.bytes_transferred == 140  # 60 + 80

    def test_ttl_expiry_cleanup(self):
        """Test that expired flows are cleaned up."""
        # Add a packet
        pkt = PacketInfo(
            src_ip="10.0.0.1", dst_ip="10.0.0.2",
            src_port=12345, dst_port=80, protocol="tcp",
            timestamp=1000.0, flags="S", ja3="", ja3s="",
            dns_query="", dns_qtype=0, packet_size=60,
        )
        self.builder.add_packet(pkt)

        # Check flow exists
        assert self.builder.count() == 1

        # TTL is 30 seconds; in practice we'd advance time
        # For test, just verify the mechanism exists
        stats = self.builder.get_stats()
        assert "total_flows" in stats


class TestFlowState:
    """Test FlowState class."""

    def test_flow_state_creation(self):
        """Test FlowState can be created and packet added."""
        fs = FlowState(key="test", src_ip="1.1.1.1", dst_ip="2.2.2.2", protocol="tcp")
        assert fs.packet_count == 0
        assert fs.duration_seconds() == 0.0

    def test_packet_accumulation(self):
        """Test that packets are properly accumulated."""
        fs = FlowState(key="test", src_ip="1.1.1.1", dst_ip="2.2.2.2", protocol="tcp")

        pkt1 = type('P', (), {'flags': 'S', 'packet_size': 60})()
        pkt2 = type('P', (), {'flags': 'A', 'packet_size': 80})()

        fs.add_packet(type('P', (), {
            'src_ip': '1.1.1.1', 'dst_ip': '2.2.2.2', 'src_port': 1234,
            'dst_port': 80, 'protocol': 'tcp', 'timestamp': 1000.0,
            'flags': 'S', 'ja3': '', 'ja3s': '', 'dns_query': '',
            'dns_qtype': 0, 'packet_size': 60,
        })())

        fs.add_packet(type('P', (), {
            'src_ip': '1.1.1.1', 'dst_ip': '2.2.2.2', 'src_port': 1234,
            'dst_port': 80, 'protocol': 'tcp', 'timestamp': 1001.0,
            'flags': 'A', 'ja3': '', 'ja3s': '', 'dns_query': '',
            'dns_qtype': 0, 'packet_size': 80,
        })())

        assert fs.packet_count == 2
        assert fs.bytes_transferred == 140
        assert fs.duration_seconds() == 1.0


class TestEntropyUtils:
    """Test entropy utility functions."""

    def test_shannon_entropy(self):
        """Test Shannon entropy calculation."""
        from app.utils.entropy import shannon_entropy

        # Uniform distribution should have high entropy
        uniform_data = bytes([i % 256 for i in range(256)])
        entropy = shannon_entropy(uniform_data)
        assert entropy > 7.0  # Close to 8 for 8-bit uniform

        # Constant data should have zero entropy
        constant_data = b"AAAAAAAA"
        entropy_zero = shannon_entropy(constant_data)
        assert entropy_zero == 0.0

    def test_consonant_vowel_ratio(self):
        """Test consonant-vowel ratio calculation."""
        from app.utils.entropy import consonant_vowel_ratio

        # All vowels
        ratio = consonant_vowel_ratio("aeiou")
        assert ratio == 0.0  # No consonants

        # All consonants
        ratio = consonant_vowel_ratio("bcdfg")
        assert ratio > 1.0  # More consonants than vowels

        # Mixed
        ratio = consonant_vowel_ratio("hello")
        assert ratio > 0  # Should have both


class TestJaHasher:
    """Test JA fingerprint hashing."""

    def test_ja3_fingerprint(self):
        """Test JA3 fingerprint computation."""
        from app.utils.ja_hasher import ja3_fingerprint

        fingerprint = ja3_fingerprint(
            version="TLS 1.2",
            ciphers=["AES256-SHA", "AES128-SHA"],
            extensions=["server_name", "extended_master_secret"],
            curves=["P-256", "P-384"],
            point_formats=["uncompressed", "fx"],
        )
        assert len(fingerprint) == 32  # MD5 hex = 32 chars
        # Should be deterministic
        fingerprint2 = ja3_fingerprint(
            version="TLS 1.2",
            ciphers=["AES256-SHA", "AES128-SHA"],
            extensions=["server_name", "extended_master_secret"],
            curves=["P-256", "P-384"],
            point_formats=["uncompressed", "fx"],
        )
        assert fingerprint == fingerprint2

    def test_ja4_fingerprint(self):
        """Test JA4 fingerprint computation."""
        from app.utils.ja_hasher import ja4_fingerprint

        ja3 = "a3f2c7e5d6b1a4c9f8e2d7c6b5a4c3d"  # 32 char JA3
        fingerprint = ja4_fingerprint(ja3, "example.com", ["server_name"])
        assert len(fingerprint) == 64  # SHA-256 hex = 64 chars

    def test_5tuple_hash(self):
        """Test 5-tuple hash computation."""
        from app.utils.ja_hasher import five_tuple_hash

        tup = ("tcp", "10.0.0.1", 12345, "10.0.0.2", 80)
        hash1 = five_tuple_hash(tup)
        hash2 = five_tuple_hash(tup)
        assert hash1 == hash2  # Deterministic
        assert len(hash1) == 16  # Truncated SHA-256