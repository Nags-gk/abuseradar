# Build stage: generate the synthetic dataset, run detections, train the model.
FROM python:3.12-slim AS build
RUN apt-get update && apt-get install -y --no-install-recommends libgomp1 && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
RUN python -m abuseradar.pipeline && rm -f data/alerts.parquet

# Runtime stage: same dependencies, no build tooling, non-root user.
FROM python:3.12-slim
RUN apt-get update && apt-get install -y --no-install-recommends libgomp1 && rm -rf /var/lib/apt/lists/* \
    && useradd --uid 10001 --no-create-home app
WORKDIR /app
COPY --from=build /usr/local/lib/python3.12/site-packages /usr/local/lib/python3.12/site-packages
COPY --from=build /usr/local/bin/uvicorn /usr/local/bin/uvicorn
COPY --from=build --chown=app /app/abuseradar ./abuseradar
COPY --from=build --chown=app /app/docs ./docs
COPY --from=build --chown=app /app/rules ./rules
COPY --from=build --chown=app /app/data ./data
COPY --from=build --chown=app /app/results ./results
USER app
ENV PYTHONUNBUFFERED=1 PORT=8080
CMD exec uvicorn abuseradar.api:app --host 0.0.0.0 --port ${PORT} --no-server-header
