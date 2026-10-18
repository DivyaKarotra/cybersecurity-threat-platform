"""
Tests for shared statistics calculation and validation functions.
Uses synthetic temporary parquet fixtures (never writing to project Gold).
Avoids PySpark PythonRunner daemon socket bug via pyarrow.
"""
import pytest
import pyarrow as pa
import pyarrow.parquet as pq
from pyspark.sql import functions as F

from src.utils.schemas import THREAT_SCHEMA
from src.utils.statistics import compute_statistics


def _create_synthetic_threats(spark, tmp_path, name, rows):
    """Create a synthetic threats DataFrame via PyArrow (avoids Windows Py3.13 socket bug)."""
    col_names = [f.name for f in THREAT_SCHEMA.fields]
    pydict = {col: [r[i] for r in rows] for i, col in enumerate(col_names)}
    table = pa.Table.from_pydict(pydict)
    out_path = tmp_path / name
    pq.write_table(table, str(out_path))
    return spark.read.parquet(str(out_path))


class TestComputeStatistics:
    def test_empty_dataframe(self, spark, tmp_path):
        """Empty DataFrame must return zeroes and empty dicts."""
        df = _create_synthetic_threats(spark, tmp_path, "empty_threats", [])
        stats = compute_statistics(df)
        assert stats["total_threats"] == 0
        assert stats["unique_users"] == 0
        assert stats["unique_computers"] == 0
        assert stats["high_critical_count"] == 0
        assert stats["avg_risk_score"] == 0.0
        assert stats["by_type"] == {}
        assert stats["by_severity"] == {}

    def test_exact_distinct_counts(self, spark, tmp_path):
        """Statistics must compute exact distinct counts and correct severity groupings."""
        rows = [
            (100, "U1", "C1", "C2", "R1_suspicious_auth", "Medium", 50, 5, 5, "desc1"),
            (101, "U1", "C1", "C3", "R1_suspicious_auth", "High", 75, 10, 10, "desc2"),
            (102, "U2", "C2", "C4", "R2_redteam_flow", "Critical", 95, 0, 1, "desc3"),
            (103, "U3", "C3", None, "R4_suspicious_process", "Low", 30, 0, 10, "desc4"),
        ]
        df = _create_synthetic_threats(spark, tmp_path, "exact_stats", rows)
        stats = compute_statistics(df)

        assert stats["total_threats"] == 4
        # Unique users: U1, U2, U3 = 3
        assert stats["unique_users"] == 3
        # Unique computers union across src (C1, C2, C3) and dst (C2, C3, C4): C1, C2, C3, C4 = 4
        assert stats["unique_computers"] == 4
        assert stats["unique_src_computers"] == 3
        assert stats["unique_dst_computers"] == 3

        # By type
        assert stats["by_type"]["R1_suspicious_auth"] == 2
        assert stats["by_type"]["R2_redteam_flow"] == 1
        assert stats["by_type"]["R4_suspicious_process"] == 1

        # By severity
        assert stats["by_severity"]["Medium"] == 1
        assert stats["by_severity"]["High"] == 1
        assert stats["by_severity"]["Critical"] == 1
        assert stats["by_severity"]["Low"] == 1

        # High + Critical = 2
        assert stats["high_critical_count"] == 2
        # Avg risk: (50 + 75 + 95 + 30) / 4 = 250 / 4 = 62.5
        assert stats["avg_risk_score"] == 62.5
        # Null counts: dst_computer has 1 null
        assert stats["null_counts"].get("dst_computer") == 1


class TestValidationLogic:
    def test_schema_and_column_integrity(self, spark, tmp_path):
        """Threat schema must contain exactly the 10 defined fields."""
        df = _create_synthetic_threats(spark, tmp_path, "schema_test", [
            (100, "U1", "C1", "C2", "R1_suspicious_auth", "Medium", 50, 5, 5, "desc"),
        ])
        expected = {
            "time", "user", "src_computer", "dst_computer", "threat_type",
            "severity", "risk_score", "failed_attempts", "event_count", "description"
        }
        assert set(df.columns) == expected
