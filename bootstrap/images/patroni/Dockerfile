FROM postgres:18.6-trixie@sha256:885953109528ad3dfc90362b1a6f50a78620b5315be19f187753d267e484dc5b
USER root
RUN groupmod -g 19999 postgres && usermod -u 19999 -g 19999 postgres
RUN apt-get update \
 && apt-get install -y --no-install-recommends python3 python3-venv ca-certificates openssl \
 && rm -rf /var/lib/apt/lists/* \
 && python3 -m venv /opt/patroni
COPY requirements.lock build-requirements.lock /tmp/
RUN /opt/patroni/bin/pip install --no-cache-dir --require-hashes --only-binary=:all: -r /tmp/build-requirements.lock \
 && /opt/patroni/bin/pip install --no-cache-dir --require-hashes --no-build-isolation --only-binary=:all: --no-binary=ydiff -r /tmp/requirements.lock \
 && /opt/patroni/bin/patroni --version | grep -Fx 'patroni 4.1.5' \
 && postgres --version | grep -E '^postgres \(PostgreSQL\) 18\.6' \
 && test "$(id -u postgres)" = 19999
COPY entrypoint.py manual-promotion-gate.py verify-runtime.py image-smoke.py /opt/infra/
RUN chmod 0555 /opt/infra/*.py
ENV PATH="/opt/patroni/bin:/usr/lib/postgresql/18/bin:${PATH}" PYTHONUNBUFFERED=1
USER 19999:19999
ENTRYPOINT ["/opt/patroni/bin/python", "/opt/infra/entrypoint.py"]
STOPSIGNAL SIGTERM
