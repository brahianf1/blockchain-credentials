# syntax=docker/dockerfile:1.7
#
# Hyperledger Indy Tails Server — multi-architecture build.
#
# Runs natively on linux/amd64 and linux/arm64 because
# ``python:3.11-slim-bookworm`` is itself a multi-arch image. No QEMU
# emulation is involved on either target.
#
# The upstream project (https://github.com/bcgov/indy-tails-server) is
# vendored at build time at a pinned tag so we do not depend on a
# third-party pre-built image whose ARM64 support is inconsistent.

ARG TAILS_SERVER_REPO=https://github.com/bcgov/indy-tails-server.git
ARG TAILS_SERVER_REF=v1.1.0


###############################################################################
# Stage 1 — Build: fetch the upstream code and install Python deps
###############################################################################
FROM python:3.11-slim-bookworm AS builder

ARG TAILS_SERVER_REPO
ARG TAILS_SERVER_REF

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
        git \
        build-essential \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build
RUN git clone --branch "${TAILS_SERVER_REF}" --depth 1 "${TAILS_SERVER_REPO}" . \
    && pip install --prefix=/install --no-cache-dir .


###############################################################################
# Stage 2 — Runtime: minimal image with only the installed Python package
###############################################################################
FROM python:3.11-slim-bookworm AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# Copy only the installed packages from the builder stage so the final
# image does not ship git or build-essential.
COPY --from=builder /install /usr/local

# Unprivileged user for the runtime process. The storage directory is
# owned by this user so that the container can write tails files to the
# mounted volume without needing root.
RUN groupadd --system --gid 1001 tails \
    && useradd --system --uid 1001 --gid 1001 --shell /sbin/nologin tails \
    && mkdir -p /tails-files \
    && chown -R tails:tails /tails-files

USER tails
WORKDIR /tails-files

VOLUME ["/tails-files"]
EXPOSE 6543

# Health check: the tails server answers 404 with a body on GET / when
# healthy, which is treated as "service is up". We consider any response
# with status < 500 as healthy.
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD python -c "import urllib.request, sys; \
        r = urllib.request.urlopen('http://127.0.0.1:6543/', timeout=3); \
        sys.exit(0 if r.status < 500 else 1)" || exit 1

ENTRYPOINT ["python", "-m", "tails_server"]
CMD ["--host", "0.0.0.0", \
     "--port", "6543", \
     "--log-level", "INFO", \
     "--storage-path", "/tails-files"]
