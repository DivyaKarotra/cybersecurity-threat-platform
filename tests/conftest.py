"""
Shared pytest fixtures for tests – local SparkSession and synthetic data.
Synthetic fixture results are NEVER written to Gold.
"""
import os
import sys
import pytest

# Ensure project root is on path
from pathlib import Path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))
os.environ["PYSPARK_PYTHON"] = sys.executable
os.environ["PYSPARK_DRIVER_PYTHON"] = sys.executable


@pytest.fixture(scope="session")
def spark():
    """Shared local SparkSession for all tests using project defaults."""
    from src.utils.spark_session import get_spark_session
    spark = get_spark_session("CyberTestSuite")
    yield spark
    spark.stop()
