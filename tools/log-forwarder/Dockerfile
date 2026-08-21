FROM python:3.13-slim

WORKDIR /app
COPY forwarder.py /app/forwarder.py

RUN useradd --create-home --uid 10001 forwarder
USER forwarder

CMD ["python", "/app/forwarder.py"]
