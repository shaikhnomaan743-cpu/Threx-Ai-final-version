from pydantic import Field
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    project_name: str = "Threx AI Backend"
    version: str = "2.0.0"
    api_v1_str: str = "/api"
    cors_origins: str = "http://localhost:5173"
    log_level: str = "info"
    alert_max_history: int = 10000
    env: str = "development"

    # Database — SQLite for structured alert + flow storage
    db_path: str = "data/alerts.db"

    # Ingest
    pcap_dir: str = "data/pcaps"
    live_interface: str | None = None
    flow_ttl_seconds: int = 60

    # Model paths
    models_dir: str = "data/models"
    artifacts_dir: str = "app/models/artifacts"

    # Detection thresholds
    ddos_syn_ratio: float = 10.0
    ddos_udp_amp_ratio: float = 20.0
    ddos_contamination: float = 0.05
    beacon_min_observations: int = 8
    scan_unique_ports_threshold: int = 20
    scan_unique_hosts_threshold: int = 15
    exfil_byte_ratio: float = 10.0
    exfil_min_volume_bytes: int = 10 * 1024 * 1024  # 10MB
    dga_threshold: float = 0.5

    # Security
    api_key: str | None = None
    rate_limit_per_minute: int = 120

    class Config:
        env_file = ".env"
        env_prefix = "CYBERSENTINEL_"


settings = Settings()
