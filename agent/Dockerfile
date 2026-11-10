# The agent's image (step 19a, ADR-54). Built from the repository root:
#   docker build -f agent/Dockerfile .
# Pinned by digest, like every base image here.
FROM python:3.14.7-slim-trixie@sha256:51dafde81dbdb6ebde285137a295cf18a47ca95234fe388a343719cb97305b3d

# No .pyc files written at run time, and log lines appear straight away.
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_DISABLE_PIP_VERSION_CHECK=1
RUN useradd --system --no-create-home --uid 10001 app
WORKDIR /app

# Only the packages the service needs (not the test tools), each checked against its recorded hash.
COPY agent/requirements.txt .
RUN pip install --no-cache-dir --require-hashes -r requirements.txt
COPY agent/app app

USER app
# Still only on this loopback address: in deploy/compose.yaml the agent shares the gateway's network,
# so the gateway is the only thing that can reach it, exactly as on a development machine (ADR-4).
CMD ["python", "-m", "uvicorn", "app.main:app", "--host", "127.0.0.1", "--port", "8001", "--no-server-header"]
