# NG-SOAR CACAO Validator/Executor (training edition)
FROM python:3.12-slim

# Only openssh-client (for the ssh to the firewall) and ca-certificates are
# needed in the container. curl is NOT installed: the verification probe runs
# curl on the REMOTE host over ssh, and app.py uses Python's urllib for HTTP.
# Fewer packages = smaller apt peak, avoiding OOM (exit 137) on the small ng-soar.
RUN apt-get update \
    && apt-get install -y --no-install-recommends openssh-client ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY app.py /app/app.py

EXPOSE 9100
ENTRYPOINT ["python3", "/app/app.py"]
