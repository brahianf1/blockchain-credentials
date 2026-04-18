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
#   compile from source on 3.11 when no pre-built wheel exists for the
#   target arch (e.g. linux/aarch64). Python 3.10 still exposes the
#   header and is in LTS support, giving us a clean compile on both
#   amd64 and arm64 without pinning internal dependency versions.

ARG TAILS_SERVER_REPO=https://github.com/bcgov/indy-tails-server.git
ARG TAILS_SERVER_REF=v1.1.0


###############################################################################
# Stage 1 — Build: fetch the upstream code and install Python deps
###############################################################################
FROM python:3.10-slim-bookworm AS builder

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
    && pip install --prefix=/install --no-cache-dir . \
    # ``indy-tails-server`` v1.1.0 ships a setup.py that declares
    # ``packages=["tails_server"]`` instead of ``find_packages()``, so
    # subpackages such as ``tails_server.config`` and ``tails_server.utils``
    # never make it into the resulting wheel. ``pip install .`` then yields
    # a broken install where ``from .config.defaults import ...`` raises
    # ``ModuleNotFoundError``. To avoid patching upstream we keep pip's
    # resolution of transitive dependencies (aiohttp, yarl, base58, etc.)
    # but overwrite the ``tails_server`` package on disk with the full
    # source tree. A final pair of asserts fails the build early if the
    # upstream layout drifts in a way we did not anticipate.
    && rm -rf /install/lib/python3.10/site-packages/tails_server \
    && cp -r tails_server /install/lib/python3.10/site-packages/tails_server \
    && test -d /install/lib/python3.10/site-packages/tails_server/config \
    && test -f /install/lib/python3.10/site-packages/tails_server/__main__.py


###############################################################################
# Stage 2 — Runtime: minimal image with only the installed Python package
###############################################################################
FROM python:3.10-slim-bookworm AS runtime

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
