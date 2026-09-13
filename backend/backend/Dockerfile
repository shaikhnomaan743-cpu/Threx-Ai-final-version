FROM python:3.11-slim

# Environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PYTHONPATH=/app

# Set work directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    gcc \
    git \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt .
COPY requirements-dev.txt .
RUN pip install --upgrade pip && \
    pip install -r requirements.txt

# Copy project code
COPY . .

# Create necessary directories
RUN mkdir -p data/pcaps data/logs data/models app/models/artifacts

# Expose ports
# - 8000: FastAPI/Uvicorn API
# - 9090: Prometheus metrics (optional)
EXPOSE 8000 9090

# Startup command
# Use 4 workers for production, 1 for development
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "4"]

# Health check - fixed path to /health (also available at /system/health and /health/live)
HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 \
    CMD curl -f http://localhost:8000/health || curl -f http://localhost:8000/system/health || curl -f http://localhost:8000/health/live || exit 1