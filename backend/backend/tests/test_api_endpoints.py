"""Tests for API endpoints."""

import sys
import os
import json

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from fastapi.testclient import TestClient
from app.main import app


class TestAPIEndpoints:
    """Test FastAPI endpoint responses."""

    def setup_method(self):
        self.client = TestClient(app)

    def test_root_endpoint(self):
        """Test root responds with API info."""
        response = self.client.get("/")
        assert response.status_code == 200
        data = response.json()
        assert "name" in data or "version" in data

    def test_health_endpoint(self):
        """Test health check endpoint."""
        response = self.client.get("/health")
        assert response.status_code == 200
        data = response.json()
        # Should return liveness probe status
        assert "status" in data or "status_code" in data

    def test_metrics_endpoint(self):
        """Test Prometheus metrics endpoint."""
        response = self.client.get("/metrics")
        # May return Prometheus format or error if prometheus not set up
        assert response.status_code in (200, 501)  # 501 = not implemented yet

    def test_threats_list_endpoint(self):
        """Test threats list endpoint."""
        response = self.client.get("/threats?limit=5")
        # Should return 200 even if no alerts (empty list)
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)

    def test_threats_filter_by_severity(self):
        """Test threats filtered by severity."""
        response = self.client.get("/threats?severity=high&limit=5")
        assert response.status_code == 200
        data = response.json()
        # All returned should have high severity
        for alert in data:
            assert alert.get("severity") == "high"

    def test_threats_filter_by_class(self):
        """Test threats filtered by threat class."""
        response = self.client.get("/threats?threat_class=ddos&limit=5")
        assert response.status_code == 200
        data = response.json()
        for alert in data:
            assert alert.get("threat_class") == "ddos"

    def test_threat_detail_endpoint(self):
        """Test get specific alert detail."""
        # First create an alert ID we know doesn't exist
        response = self.client.get("/threats/nonexistent-uuid")
        # Should return 404
        assert response.status_code == 404

    def test_traffic_stats_endpoint(self):
        """Test traffic stats endpoint."""
        response = self.client.get("/traffic/stats")
        assert response.status_code == 200
        data = response.json()
        # Should have some traffic metrics
        assert "total_flows" in data or "flows_per_sec" in data

    def test_top_talkers_endpoint(self):
        """Test top talkers endpoint."""
        response = self.client.get("/traffic/top-talkers?limit=10")
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)
        # Limit to reasonable number
        assert len(data) <= 10

    def test_protocol_distribution(self):
        """Test protocol distribution endpoint."""
        response = self.client.get("/traffic/protocols")
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, (dict, list))

    def test_dns_dga_endpoint(self):
        """Test DGA DNS endpoint."""
        response = self.client.get("/dns/dga?limit=5")
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)

    def test_dns_tunneling_endpoint(self):
        """Test DNS tunneling endpoint."""
        response = self.client.get("/dns/tunneling")
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)

    def test_tls_fingerprints_endpoint(self):
        """Test TLS fingerprints endpoint."""
        response = self.client.get("/tls/fingerprints?limit=5")
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)

    def test_recon_scans_endpoint(self):
        """Test recon scans endpoint."""
        response = self.client.get("/recon/scans?limit=5")
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)

    def test_exfil_anomalies_endpoint(self):
        """Test exfiltration anomalies endpoint."""
        response = self.client.get("/exfil/anomalies?limit=5")
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)

    def test_system_status_endpoint(self):
        """Test system status endpoint."""
        response = self.client.get("/system/status")
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, (dict, list))

    def test_system_throughput_endpoint(self):
        """Test system throughput endpoint."""
        response = self.client.get("/system/throughput")
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, (dict, list))

    def test_reports_generate_post(self):
        """Test report generation POST endpoint."""
        response = self.client.post(
            "/reports/generate",
            json={"format": "json"},
        )
        # Should return 200 (generate summary) or 404 for specific alert
        assert response.status_code in (200, 404, 422, 503)  # 503 = service unavailable when no manager in test

    def test_websocket_route_exists(self):
        """Test WebSocket route is registered."""
        # WebSocket routes can't be tested with GET/POST in TestClient
        # Just verify the router is included
        ws_paths = [str(r) for r in app.routes if "ws" in str(r).lower()]
        # At least some WS routes should be registered
        assert len(ws_paths) > 0