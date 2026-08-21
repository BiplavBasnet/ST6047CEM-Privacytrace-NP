# PrivacyTrace-NP Log Forwarder

This optional forwarder tails one configured text log and sends new lines to
the Universal Integration Gateway. It uses only the Python standard library.

1. Copy .env.example to .env and set the one-time integration token.
2. Mount the log directory read-only.
3. Build and run:

    docker build -t privacytrace-log-forwarder tools/log-forwarder

    docker run --rm --env-file tools/log-forwarder/.env -v C:\path\to\logs:/logs:ro privacytrace-log-forwarder

Set DRY_RUN=true to verify file watching without sending content. Set
SYNTHETIC_TEST_MODE=true to send one synthetic event and exit.

The forwarder never prints log lines, response bodies, or the integration
token. Delivery messages contain only status and a short event hash prefix.
