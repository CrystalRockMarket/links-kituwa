# A non-root, read-only-friendly image. The published host uses systemd, but the
# same tree runs in a container.
FROM python:3.12-slim

RUN useradd --create-home --uid 10001 links
WORKDIR /srv/links-kituwa
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .

ENV SL_DATA_DIR=/data SL_HOST=0.0.0.0 SL_PORT=8891 SL_COOKIE_SECURE=1
RUN mkdir -p /data && chown links:links /data
USER links
EXPOSE 8891
VOLUME ["/data"]
CMD ["python", "run.py"]
