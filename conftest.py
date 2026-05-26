"""Root conftest.py — cross-platform test configuration.

Sets a file-based keyring backend before any test that touches meridian.canon.keys
so the suite works on headless Linux/Windows CI without a system credential store.

Override by setting PYTHON_KEYRING_BACKEND in the environment before running pytest.
"""
import os

# Use file-based keyring backend for tests unless the caller already set one.
# keyrings.alt.file.PlaintextKeyring stores entries in a temp file — safe for CI.
# On developer machines with a real Keychain this is intentionally overridden.
if "PYTHON_KEYRING_BACKEND" not in os.environ:
    os.environ["PYTHON_KEYRING_BACKEND"] = "keyrings.alt.file.PlaintextKeyring"
