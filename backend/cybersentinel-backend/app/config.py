from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    project_name: str = "Threx AI Backend"
    version: str = "2.0.0"
    api_v1_str: str = "/api"
    cors_origins: str = "http://localhost:5173"
    log_level: str = "info"
    alert_max_history: int = 10000
    env: str = "development"

    # Database — PostgreSQL in production, SQLite fallback for local/dev
    postgres_dsn: str = "postgresql://postgres:postgres@localhost:5432/cybersentinel"
    redis_url: str = "redis://localhost:6379/0"
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
    rate_limit_per_minute: int = 600  # single-operator dashboard polls ~5 endpoints every 2s

    # Startup strictness
    # False (default): if the inference engine cannot load, startup FAILS loudly.
    # A backend that cannot detect threats should not pretend to be healthy.
    # Set true only for UI work against a machine without the ML wheels.
    allow_degraded_start: bool = False

    # Ingest queue / batch inference
    # Flows are enqueued by the capture side and drained by a worker task, so
    # packet ingestion never blocks the FastAPI event loop.
    ingest_queue_maxsize: int = 10000
    ingest_batch_size: int = 64
    ingest_batch_timeout_ms: int = 50
    # Replay pacing for the lab/demo source. 0 = ingest as fast as possible.
    # Default is throttled: an unthrottled producer plus the batch worker will
    # monopolise the event loop and starve the HTTP handlers, so the dashboard
    # stops responding while the pipeline "performs well". Benchmarks set this
    # to 0 deliberately and do not serve traffic at the same time.
    replay_target_fps: float = 200.0
    # Flow-record ingest (NetFlow v5/v9, IPFIX over UDP, listen-only).
    # 0 disables. When enabled it replaces lab replay as the data source.
    # Conventional ports: 2055 (NetFlow), 4739 (IPFIX); one socket handles both.
    flow_listen_port: int = 0
    flow_listen_host: str = "0.0.0.0"
    # >0: run the multi-core pipeline (receiver + this many detection worker
    # processes) for the flow-record listener. 0: single process.
    parallel_workers: int = 0

    model_config = SettingsConfigDict(
        env_file=".env",
        env_prefix="CYBERSENTINEL_",
        extra="ignore",
    )


settings = Settings()
