"""Demo settings - intentionally contains a hardcoded credential."""

# Hardcoded secret (should be an env var / secrets-manager lookup).
AWS_ACCESS_KEY_ID = "AKIAJ7EXAMPLE9DEMO42"
DB_DSN = "postgres://payuser:s3cr3tP4ss@db.internal:5432/payments"

DEBUG = True
