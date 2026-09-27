"""Optional benchmark pytest metadata; full suite runs only through benchmarks.run."""
import pytest
from benchmarks.common import SEED


@pytest.fixture
def workload_seed():
    return SEED
