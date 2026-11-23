"""Stable paths for verification resources, independent of the working directory."""
from pathlib import Path

VERIFICATION_ROOT = Path(__file__).resolve().parents[1]
PRODUCT_ROOT = VERIFICATION_ROOT.parent / "product"
FIXTURES = VERIFICATION_ROOT / "logs" / "samples"
ARTIFACTS = VERIFICATION_ROOT / "artifacts"
