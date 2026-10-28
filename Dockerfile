FROM python:3.11-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /srv
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
RUN useradd --create-home --uid 10001 demo && mkdir -p /data /config && chown demo:demo /data /config
COPY --chown=demo:demo app ./app
COPY --chown=demo:demo static ./static
COPY --chown=demo:demo scripts ./scripts
USER demo
EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1"]
