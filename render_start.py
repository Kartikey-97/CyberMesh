import subprocess
import os
import time
import sys
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("render_start")

logger.info("Starting CyberMesh Auth Service on port 8081...")
auth_proc = subprocess.Popen(
    [sys.executable, "-m", "uvicorn", "auth_service.main:app", "--host", "127.0.0.1", "--port", "8081"]
)

# Wait for auth-service to spin up so proxy can fetch the public key
time.sleep(3)

port = os.environ.get("PORT", "8080")
os.environ["AUTH_SERVICE_URL"] = "http://127.0.0.1:8081"

logger.info(f"Starting CyberMesh Proxy on port {port}...")
proxy_proc = subprocess.Popen(
    [sys.executable, "-m", "uvicorn", "proxy.main:app", "--host", "0.0.0.0", "--port", port]
)

try:
    proxy_proc.wait()
    auth_proc.wait()
except KeyboardInterrupt:
    logger.info("Shutting down services...")
    proxy_proc.terminate()
    auth_proc.terminate()
