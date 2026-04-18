# syntax=docker/dockerfile:1.7
#
# Hyperledger Indy Tails Server — multi-architecture build.
#
# Runs natively on linux/amd64 and linux/arm64 because
# ``python:3.10-slim-bookworm`` is itself a multi-arch image. No QEMU
# emulation is involved on either target.
#
# The upstream project (https://github.com/bcgov/indy-tails-server) is
# vendored at build time at a pinned tag so we do not depend on a
# third-party pre-built image whose ARM64 support is inconsistent.
#
# Why Python 3.10 and not 3.11+:
#   The tails-server v1.1.0 requirements pull in an old yarl release
#   whose C extension includes ``longintrepr.h``. That header was
#   removed from Python's public headers in 3.11, so yarl fails to
#   compile from source on 3.11 when no pre-built wheel exists for
#   linux/aarch64. Python 3.10 still exposes the header and is in LTS
#   support until October 2026.
#
# Why we side-step ``pip install .`` for the package itself:
#   The v1.1.0 setup.py declares ``packages=["tails_server"]`` instead
#   of ``find_packages()``. The resulting wheel ships only the root
#   module; subpackages (``tails_server.config``, ``tails_server.utils``,
#   …) are missing and the service crashes at import time with
#   ``ModuleNotFoundError: No module named 'tails_server.config'``.
#
#   We therefore split the job: pip installs the transitive
#   dependencies (aiohttp, yarl, base58, indy_vdr, …) from
#   ``requirements.txt``, and the ``tails_server`` package itself is
#   copied verbatim from the source tree into site-packages. A runtime
#   import check at build time fails fast if upstream ever drifts.

ARG TAILS_SERVER_REPO=https://github.com/bcgov/indy-tails-server.git
ARG TAILS_SERVER_REF=v1.1.0


###############################################################################
# Stage 1 — Builder
###############################################################################
FROM python:3.10-slim-bookworm AS builder

ARG TAILS_SERVER_REPO
ARG TAILS_SERVER_REF

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    VIRTUAL_ENV=/opt/venv

RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
        git \
        build-essential \
    && rm -rf /var/lib/apt/lists/*

# Create a virtual environment so every Python artifact lives under a
# single well-known path. This makes the multi-stage copy below
# deterministic and avoids hard-coding a site-packages layout that may
# differ between pip versions.
RUN python -m venv "${VIRTUAL_ENV}"
ENV PATH="${VIRTUAL_ENV}/bin:${PATH}"

WORKDIR /build

# Everything in a single shell with ``set -eux`` so the build log
# surfaces exactly which line fails if anything goes wrong.
RUN set -eux; \
    echo "=== [1/5] Cloning upstream ==="; \
    git clone --branch "${TAILS_SERVER_REF}" --depth 1 "${TAILS_SERVER_REPO}" .; \
    echo "=== [2/5] Source tree layout ==="; \
    ls -la; \
    ls -la tails_server/; \
    echo "=== [3/5] Installing runtime dependencies from requirements.txt ==="; \
    pip install --no-cache-dir -r requirements.txt; \
    echo "=== [4/5] Copying tails_server source tree into site-packages ==="; \
    SITE_PACKAGES="$(python -c 'import sysconfig; print(sysconfig.get_paths()["purelib"])')"; \
    echo "Target site-packages: ${SITE_PACKAGES}"; \
    rm -rf "${SITE_PACKAGES}/tails_server"; \
    cp -r tails_server "${SITE_PACKAGES}/tails_server"; \
    ls -la "${SITE_PACKAGES}/tails_server/"; \
    echo "=== [5/5] Runtime import check ==="; \
    python -c "from tails_server.config.defaults import DEFAULT_WEB_HOST, DEFAULT_WEB_PORT, CHUNK_SIZE; print('tails_server import OK')"; \
    python -c "import tails_server.__main__; print('tails_server.__main__ import OK')"


###############################################################################
# Stage 2 — Runtime
###############################################################################
FROM python:3.10-slim-bookworm AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    VIRTUAL_ENV=/opt/venv \
    PATH=/opt/venv/bin:$PATH

# Bring in the self-contained virtualenv with both deps and the
# tails_server package already placed under its site-packages.
COPY --from=builder /opt/venv /opt/venv

# Unprivileged user for the runtime process. The storage directory is
# owned by this user so the container can write tails files to the
# mounted volume without needing root.
RUN groupadd --system --gid 1001 tails \
    && useradd --system --uid 1001 --gid 1001 --shell /sbin/nologin tails \
    && mkdir -p /tails-files \
    && chown -R tails:tails /tails-files

USER tails
WORKDIR /tails-files

VOLUME ["/tails-files"]
EXPOSE 6543

# Health check: the tails server answers with a body on GET / when
# healthy. We treat any response with status < 500 as service-up.
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD python -c "import urllib.request, sys; \
        r = urllib.request.urlopen('http://127.0.0.1:6543/', timeout=3); \
        sys.exit(0 if r.status < 500 else 1)" || exit 1

ENTRYPOINT ["python", "-m", "tails_server"]
CMD ["--host", "0.0.0.0", \
     "--port", "6543", \
     "--log-level", "INFO", \
     "--storage-path", "/tails-files"]
