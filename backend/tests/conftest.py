"""Test environment setup. No real Supabase/Stripe/Redis credentials are
used or required -- tests either fake the DB boundary directly or assert
on the documented graceful-degradation behavior when a dependency isn't
configured (see test_health.py)."""
import os

os.environ.setdefault("ALLOWED_ORIGINS", "http://localhost:3000")
os.environ.setdefault("SUPABASE_JWT_SECRET", "test-jwt-secret-not-real")

# Existing engine tests score brand-new sources and expect verdicts at once;
# the learning period has its own tests (test_learning_period.py) that enable it.
os.environ.setdefault("ENTITY_LEARNING_MIN_FLOWS", "0")
