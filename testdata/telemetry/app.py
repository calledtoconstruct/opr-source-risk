import sentry_sdk

SENTRY_DSN = "https://key@o.ingest.sentry.io/1"
sentry_sdk.init(dsn=SENTRY_DSN)
TELEMETRY_ENABLED = True
