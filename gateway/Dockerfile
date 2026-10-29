FROM python:3.12.12-slim-bookworm@sha256:593bd06efe90efa80dc4eee3948be7c0fde4134606dd40d8dd8dbcade98e669c
WORKDIR /app
COPY --chmod=0644 requirements.lock /app/
RUN pip install --no-cache-dir -r requirements.lock
COPY --chmod=0644 channel.py registry.py private_api.py public_limits.py gateway.py admin_frontend.py approval_portal.py service.py admin.py deployment_policy.py owner_network_model.py tool-catalog.json /app/
USER 10008:10008
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 FASTMCP_HOME=/state/fastmcp HOME=/state
CMD ["python", "/app/service.py"]
