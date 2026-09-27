# Registry manifest digests resolved 2026-09-08. Refresh only through review + CI.
FROM ghcr.io/astral-sh/uv:0.12.10@sha256:2bb3ebca0a796a155094a27773d290c4b074572e6107f171d88d086682fd2500 AS uv
FROM python:3.12.14-slim-bookworm@sha256:782412e85d0f0984994c290652577d4018aff08145c85b262bb63dc0c7522254 AS build
COPY --from=uv /uv /usr/local/bin/uv
WORKDIR /opt/eye-for-an-eye
COPY pyproject.toml uv.lock README.md ./
COPY eye_for_an_eye ./eye_for_an_eye
RUN uv sync --frozen --no-dev --no-editable

FROM python:3.12.14-slim-bookworm@sha256:782412e85d0f0984994c290652577d4018aff08145c85b262bb63dc0c7522254 AS runtime
LABEL org.opencontainers.image.title="Eye for an Eye" org.opencontainers.image.version="0.8.0-rc.1"
RUN groupadd --gid 10000 eye-for-an-eye && useradd --uid 10001 --gid 10000 --no-create-home --shell /usr/sbin/nologin eye-for-an-eye \
    && install -d -o 10001 -g 10000 -m 0750 /var/lib/eye-for-an-eye /run/eye-for-an-eye
COPY --from=build /opt/eye-for-an-eye/.venv /opt/eye-for-an-eye/.venv
COPY deploy/container.toml /etc/eye-for-an-eye/config.toml
ENV PATH="/opt/eye-for-an-eye/.venv/bin:$PATH" PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
USER 10001:10000
WORKDIR /var/lib/eye-for-an-eye
VOLUME ["/var/lib/eye-for-an-eye"]
ENTRYPOINT ["eye-for-an-eye"]
CMD ["run", "--config", "/etc/eye-for-an-eye/config.toml"]
HEALTHCHECK --interval=5s --timeout=2s --start-period=5s --retries=3 CMD ["eye-for-an-eye", "status", "--health-only", "--config", "/etc/eye-for-an-eye/config.toml"]
