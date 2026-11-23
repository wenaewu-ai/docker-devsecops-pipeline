FROM python:3.12-slim
WORKDIR /app
ENV PYTHONPATH=/app \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

# Apply Debian security updates at build time. The official python:3.12-slim image is not
# rebuilt the moment debian-security ships a fix, so its OS packages are often a few days
# behind, and the Trivy gate would block the deploy until upstream catches up.
RUN apt-get update \
    && apt-get upgrade --yes --no-install-recommends \
    && rm -rf /var/lib/apt/lists/*

# Runtime dependencies only, pinned in requirements.txt. pip itself is removed afterwards:
# nothing needs it at runtime, and the packages vendored inside pip are a recurring source
# of scanner findings that have nothing to do with the application.
COPY requirements.txt .
RUN PIP_ROOT_USER_ACTION=ignore pip install --no-cache-dir -r requirements.txt \
    && PIP_ROOT_USER_ACTION=ignore pip uninstall --yes pip

COPY app ./app
COPY migrations ./migrations

# Run as a non-root user. The code stays owned by root and is read-only to the app.
RUN groupadd --system --gid 10001 app \
    && useradd --system --uid 10001 --gid 10001 --no-create-home app
USER 10001:10001

EXPOSE 8000
HEALTHCHECK --interval=10s --timeout=3s --start-period=5s --retries=5 \
    CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/healthz', timeout=2)"]
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
