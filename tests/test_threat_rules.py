"""
Tests for threat detection rules, risk scoring, identifier normalisation,
schema validation, and null-marker handling.
Each rule has one known-positive and one known-negative test case.
"""
import sys
from pathlib import Path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

import pytest
from pyspark.sql import functions as F
from pyspark.sql.types import (
    StructType, StructField, LongType, StringType, IntegerType, BooleanType
)


import pyarrow as pa
import pyarrow.parquet as pq


def _df_from_rows(spark, tmp_path, name, schema, rows):
    """Create a DataFrame without invoking Python worker daemon (avoids Windows Py3.13 socket bug)."""
    col_names = [f.name for f in schema.fields]
    pydict = {col: [r[i] for r in rows] for i, col in enumerate(col_names)}
    table = pa.Table.from_pydict(pydict)
    out_path = tmp_path / name
    pq.write_table(table, str(out_path))
    return spark.read.parquet(str(out_path))


def _write_temp_silver(spark, tmp_path, source_name, schema, rows):
    """Write test data to a temp Silver-like directory."""
    return _df_from_rows(spark, tmp_path, source_name, schema, rows)



# ═══════════════════════════════════════════════════════════════════════════
# Risk Scoring Tests
# ═══════════════════════════════════════════════════════════════════════════
class TestRiskScoring:
    def test_risk_score_bounds(self):
        """Risk scores must be in [0, 100]."""
        from src.analytics.threat_rules import compute_risk_score
        for tt in ["R1_suspicious_auth", "R2_redteam_flow", "R3_redteam_dns",
                    "R4_suspicious_process", "R5_redteam_process"]:
            for fails in [0, 5, 50, 100]:
                for events in [1, 10, 100]:
                    score = compute_risk_score(tt, fails, events)
                    assert 0 <= score <= 100, f"Score {score} out of bounds for {tt}"

    def test_severity_mapping(self):
        """Severity labels map correctly to score ranges."""
        from src.analytics.threat_rules import get_severity
        assert get_severity(0) == "Low"
        assert get_severity(39) == "Low"
        assert get_severity(40) == "Medium"
        assert get_severity(69) == "Medium"
        assert get_severity(70) == "High"
        assert get_severity(89) == "High"
        assert get_severity(90) == "Critical"
        assert get_severity(100) == "Critical"

    def test_redteam_bonus_applied(self):
        """Redteam rules should have higher base scores."""
        from src.analytics.threat_rules import compute_risk_score
        r1_score = compute_risk_score("R1_suspicious_auth", 0, 1)
        r2_score = compute_risk_score("R2_redteam_flow", 0, 1)
        assert r2_score > r1_score


# ═══════════════════════════════════════════════════════════════════════════
# Identifier Normalisation Tests
# ═══════════════════════════════════════════════════════════════════════════
class TestIdentifierNormalisation:
    def test_preserves_originals_adds_keys(self, spark, tmp_path):
        """Silver should keep original identifiers and add normalised keys."""
        from src.transformation.silver import _add_join_keys

        schema = StructType([
            StructField("src_computer", StringType(), True),
            StructField("user", StringType(), True),
        ])
        df = _df_from_rows(spark, tmp_path, "ident_test", schema, [
            ("Comp1$", "user@DOM1"),
            ("  comp2  ", "USER2@dom2"),
        ])

        result = _add_join_keys(df, computer_cols=["src_computer"], user_cols=["user"])

        rows = result.collect()
        # Original preserved
        assert rows[0]["src_computer"] == "Comp1$"
        assert rows[0]["user"] == "user@DOM1"
        # Keys are upper-trimmed
        assert rows[0]["src_computer_key"] == "COMP1$"
        assert rows[0]["user_key"] == "USER@DOM1"
        assert rows[1]["src_computer_key"] == "COMP2"
        assert rows[1]["user_key"] == "USER2@DOM2"


# ═══════════════════════════════════════════════════════════════════════════
# Null Marker Handling Tests
# ═══════════════════════════════════════════════════════════════════════════
class TestNullMarkerHandling:
    def test_question_mark_treated_as_null(self, spark):
        """? should be read as null by Spark CSV reader."""
        import tempfile
        from src.utils.schemas import DNS_SCHEMA
        with tempfile.NamedTemporaryFile(mode="w", suffix=".csv", delete=False) as f:
            f.write("100,CompA,?\n")
            f.write("200,?,CompB\n")
            tmp = f.name

        df = spark.read.option("nullValue", "?").schema(DNS_SCHEMA).csv(tmp)
        rows = df.collect()
        assert rows[0]["resolved_computer"] is None
        assert rows[1]["src_computer"] is None

        import os
        os.unlink(tmp)


# ═══════════════════════════════════════════════════════════════════════════
# Rule Tests (synthetic data – NEVER written to Gold)
# ═══════════════════════════════════════════════════════════════════════════
class TestRuleR1SuspiciousAuth:
    """R1: Suspicious Authentication."""

    def _get_auth_schema(self):
        return StructType([
            StructField("time", LongType(), False),
            StructField("src_user", StringType(), True),
            StructField("dst_user", StringType(), True),
            StructField("src_computer", StringType(), True),
            StructField("dst_computer", StringType(), True),
            StructField("auth_type", StringType(), True),
            StructField("logon_type", StringType(), True),
            StructField("orientation", StringType(), True),
            StructField("success_failure", StringType(), True),
            StructField("is_failure", BooleanType(), True),
            StructField("src_computer_key", StringType(), True),
            StructField("dst_computer_key", StringType(), True),
            StructField("src_user_key", StringType(), True),
            StructField("dst_user_key", StringType(), True),
        ])

    def test_positive_detects_failures(self, spark, tmp_path):
        """5+ failures from same user/src/dst in 300s window should trigger."""
        import config.settings as cfg
        orig_silver = cfg.SILVER_DIR
        cfg.SILVER_DIR = tmp_path

        schema = self._get_auth_schema()
        rows = [
            (100, "baduser@D", "admin@D", "C1", "C2", "Negotiate", "Network", "LogOn", "Fail", True, "C1", "C2", "BADUSER@D", "ADMIN@D"),
            (110, "baduser@D", "admin@D", "C1", "C2", "Negotiate", "Network", "LogOn", "Fail", True, "C1", "C2", "BADUSER@D", "ADMIN@D"),
            (120, "baduser@D", "admin@D", "C1", "C2", "Negotiate", "Network", "LogOn", "Fail", True, "C1", "C2", "BADUSER@D", "ADMIN@D"),
            (130, "baduser@D", "admin@D", "C1", "C2", "Negotiate", "Network", "LogOn", "Fail", True, "C1", "C2", "BADUSER@D", "ADMIN@D"),
            (140, "baduser@D", "admin@D", "C1", "C2", "Negotiate", "Network", "LogOn", "Fail", True, "C1", "C2", "BADUSER@D", "ADMIN@D"),
        ]
        _write_temp_silver(spark, tmp_path, "auth", schema, rows)

        from src.analytics.threat_rules import rule_suspicious_auth
        result = rule_suspicious_auth(spark)
        assert result.count() > 0
        assert result.filter(F.col("threat_type") == "R1_suspicious_auth").count() > 0

        cfg.SILVER_DIR = orig_silver

    def test_negative_not_enough_failures(self, spark, tmp_path):
        """Less than 5 failures should not trigger."""
        import config.settings as cfg
        orig_silver = cfg.SILVER_DIR
        cfg.SILVER_DIR = tmp_path

        schema = self._get_auth_schema()
        rows = [
            (100, "user@D", "admin@D", "C1", "C2", "Negotiate", "Network", "LogOn", "Fail", True, "C1", "C2", "USER@D", "ADMIN@D"),
            (110, "user@D", "admin@D", "C1", "C2", "Negotiate", "Network", "LogOn", "Fail", True, "C1", "C2", "USER@D", "ADMIN@D"),
            (120, "user@D", "admin@D", "C1", "C2", "Negotiate", "Network", "LogOn", "Success", False, "C1", "C2", "USER@D", "ADMIN@D"),
        ]
        _write_temp_silver(spark, tmp_path, "auth", schema, rows)

        from src.analytics.threat_rules import rule_suspicious_auth
        result = rule_suspicious_auth(spark)
        assert result.count() == 0

        cfg.SILVER_DIR = orig_silver


class TestRuleR2RedteamFlow:
    """R2: RedTeam + Flow correlation."""

    def _get_flow_schema(self):
        return StructType([
            StructField("time", LongType(), False),
            StructField("duration", LongType(), True),
            StructField("src_computer", StringType(), True),
            StructField("src_port", IntegerType(), True),
            StructField("dst_computer", StringType(), True),
            StructField("dst_port", IntegerType(), True),
            StructField("protocol", IntegerType(), True),
            StructField("packet_count", LongType(), True),
            StructField("byte_count", LongType(), True),
            StructField("src_computer_key", StringType(), True),
            StructField("dst_computer_key", StringType(), True),
        ])

    def _get_rt_schema(self):
        return StructType([
            StructField("time", LongType(), False),
            StructField("user", StringType(), True),
            StructField("src_computer", StringType(), True),
            StructField("dst_computer", StringType(), True),
            StructField("user_key", StringType(), True),
            StructField("src_computer_key", StringType(), True),
            StructField("dst_computer_key", StringType(), True),
        ])

    def test_positive_matching_flow(self, spark, tmp_path):
        """Flow matching redteam src/dst within time window should trigger."""
        import config.settings as cfg
        orig = cfg.SILVER_DIR
        cfg.SILVER_DIR = tmp_path

        _write_temp_silver(spark, tmp_path, "flows", self._get_flow_schema(), [
            (1000, 5, "C1", 80, "C2", 443, 6, 10, 5000, "C1", "C2"),
        ])
        _write_temp_silver(spark, tmp_path, "redteam", self._get_rt_schema(), [
            (1100, "attacker@D", "C1", "C2", "ATTACKER@D", "C1", "C2"),
        ])

        from src.analytics.threat_rules import rule_redteam_flow
        result = rule_redteam_flow(spark)
        assert result.count() > 0

        cfg.SILVER_DIR = orig

    def test_negative_outside_window(self, spark, tmp_path):
        """Flow outside time window should not trigger."""
        import config.settings as cfg
        orig = cfg.SILVER_DIR
        cfg.SILVER_DIR = tmp_path

        _write_temp_silver(spark, tmp_path, "flows", self._get_flow_schema(), [
            (1000, 5, "C1", 80, "C2", 443, 6, 10, 5000, "C1", "C2"),
        ])
        _write_temp_silver(spark, tmp_path, "redteam", self._get_rt_schema(), [
            (5000, "attacker@D", "C1", "C2", "ATTACKER@D", "C1", "C2"),
        ])

        from src.analytics.threat_rules import rule_redteam_flow
        result = rule_redteam_flow(spark)
        assert result.count() == 0

        cfg.SILVER_DIR = orig


class TestRuleR3RedteamDNS:
    """R3: RedTeam + DNS correlation."""

    def _get_dns_schema(self):
        return StructType([
            StructField("time", LongType(), False),
            StructField("src_computer", StringType(), True),
            StructField("resolved_computer", StringType(), True),
            StructField("src_computer_key", StringType(), True),
            StructField("resolved_computer_key", StringType(), True),
        ])

    def _get_rt_schema(self):
        return StructType([
            StructField("time", LongType(), False),
            StructField("user", StringType(), True),
            StructField("src_computer", StringType(), True),
            StructField("dst_computer", StringType(), True),
            StructField("user_key", StringType(), True),
            StructField("src_computer_key", StringType(), True),
            StructField("dst_computer_key", StringType(), True),
        ])

    def test_positive_matching_dns(self, spark, tmp_path):
        """DNS from redteam src within time window should trigger."""
        import config.settings as cfg
        orig = cfg.SILVER_DIR
        cfg.SILVER_DIR = tmp_path

        _write_temp_silver(spark, tmp_path, "dns", self._get_dns_schema(), [
            (1000, "C1", "evil.com", "C1", "EVIL.COM"),
        ])
        _write_temp_silver(spark, tmp_path, "redteam", self._get_rt_schema(), [
            (1100, "attacker@D", "C1", "C2", "ATTACKER@D", "C1", "C2"),
        ])

        from src.analytics.threat_rules import rule_redteam_dns
        result = rule_redteam_dns(spark)
        assert result.count() > 0

        cfg.SILVER_DIR = orig

    def test_negative_no_overlap(self, spark, tmp_path):
        """DNS from unrelated computer should not trigger."""
        import config.settings as cfg
        orig = cfg.SILVER_DIR
        cfg.SILVER_DIR = tmp_path

        _write_temp_silver(spark, tmp_path, "dns", self._get_dns_schema(), [
            (1000, "C99", "safe.com", "C99", "SAFE.COM"),
        ])
        _write_temp_silver(spark, tmp_path, "redteam", self._get_rt_schema(), [
            (1100, "attacker@D", "C1", "C2", "ATTACKER@D", "C1", "C2"),
        ])

        from src.analytics.threat_rules import rule_redteam_dns
        result = rule_redteam_dns(spark)
        assert result.count() == 0

        cfg.SILVER_DIR = orig


class TestRuleR4SuspiciousProcess:
    """R4: Suspicious Process frequency anomaly."""

    def _get_proc_schema(self):
        return StructType([
            StructField("time", LongType(), False),
            StructField("user", StringType(), True),
            StructField("computer", StringType(), True),
            StructField("process_name", StringType(), True),
            StructField("start_end", StringType(), True),
            StructField("computer_key", StringType(), True),
            StructField("user_key", StringType(), True),
        ])

    def test_positive_anomalous_frequency(self, spark, tmp_path):
        """Process with frequency far above mean should trigger."""
        import config.settings as cfg
        orig = cfg.SILVER_DIR
        cfg.SILVER_DIR = tmp_path
        orig_exclude = cfg.PROC_TOP_N_EXCLUDE
        cfg.PROC_TOP_N_EXCLUDE = 0

        # Create many events for one user on one computer, few for others
        rows = []
        for i in range(300):
            rows.append((100 + i, "baduser@D", "C1", "evil.exe", "Start", "C1", "BADUSER@D"))
        # Baseline: 1 event each on 20 other computers
        for j in range(20):
            rows.append((100 + j, f"user{j}@D", f"C{j+10}", "evil.exe", "Start", f"C{j+10}", f"USER{j}@D"))

        _write_temp_silver(spark, tmp_path, "proc", self._get_proc_schema(), rows)

        from src.analytics.threat_rules import rule_suspicious_process
        result = rule_suspicious_process(spark)
        assert result.count() > 0

        cfg.SILVER_DIR = orig
        cfg.PROC_TOP_N_EXCLUDE = orig_exclude

    def test_negative_normal_frequency(self, spark, tmp_path):
        """Process with normal frequency should not trigger."""
        import config.settings as cfg
        orig = cfg.SILVER_DIR
        cfg.SILVER_DIR = tmp_path

        rows = []
        for j in range(10):
            rows.append((100, f"user{j}@D", f"C{j}", "normal.exe", "Start", f"C{j}", f"USER{j}@D"))

        _write_temp_silver(spark, tmp_path, "proc", self._get_proc_schema(), rows)

        from src.analytics.threat_rules import rule_suspicious_process
        result = rule_suspicious_process(spark)
        assert result.count() == 0

        cfg.SILVER_DIR = orig


class TestRuleR5RedteamProcess:
    """R5: RedTeam + Process correlation."""

    def _get_proc_schema(self):
        return StructType([
            StructField("time", LongType(), False),
            StructField("user", StringType(), True),
            StructField("computer", StringType(), True),
            StructField("process_name", StringType(), True),
            StructField("start_end", StringType(), True),
            StructField("computer_key", StringType(), True),
            StructField("user_key", StringType(), True),
        ])

    def _get_rt_schema(self):
        return StructType([
            StructField("time", LongType(), False),
            StructField("user", StringType(), True),
            StructField("src_computer", StringType(), True),
            StructField("dst_computer", StringType(), True),
            StructField("user_key", StringType(), True),
            StructField("src_computer_key", StringType(), True),
            StructField("dst_computer_key", StringType(), True),
        ])

    def test_positive_matching_process(self, spark, tmp_path):
        """Process by redteam user on redteam computer within window should trigger."""
        import config.settings as cfg
        orig = cfg.SILVER_DIR
        cfg.SILVER_DIR = tmp_path

        _write_temp_silver(spark, tmp_path, "proc", self._get_proc_schema(), [
            (1050, "attacker@D", "C1", "cmd.exe", "Start", "C1", "ATTACKER@D"),
        ])
        _write_temp_silver(spark, tmp_path, "redteam", self._get_rt_schema(), [
            (1000, "attacker@D", "C1", "C2", "ATTACKER@D", "C1", "C2"),
        ])

        from src.analytics.threat_rules import rule_redteam_process
        result = rule_redteam_process(spark)
        assert result.count() > 0

        cfg.SILVER_DIR = orig

    def test_negative_different_user(self, spark, tmp_path):
        """Process by different user should not trigger."""
        import config.settings as cfg
        orig = cfg.SILVER_DIR
        cfg.SILVER_DIR = tmp_path

        _write_temp_silver(spark, tmp_path, "proc", self._get_proc_schema(), [
            (1050, "innocent@D", "C1", "cmd.exe", "Start", "C1", "INNOCENT@D"),
        ])
        _write_temp_silver(spark, tmp_path, "redteam", self._get_rt_schema(), [
            (1000, "attacker@D", "C1", "C2", "ATTACKER@D", "C1", "C2"),
        ])

        from src.analytics.threat_rules import rule_redteam_process
        result = rule_redteam_process(spark)
        assert result.count() == 0

        cfg.SILVER_DIR = orig


class TestThreatSchema:
    """Test unified threat table schema."""

    def test_schema_has_required_columns(self, spark):
        """Combined threats must have all required columns."""
        from src.utils.schemas import THREAT_SCHEMA
        expected = {"time", "user", "src_computer", "dst_computer", "threat_type",
                    "severity", "risk_score", "failed_attempts", "event_count", "description"}
        actual = {f.name for f in THREAT_SCHEMA.fields}
        assert expected == actual

    def test_union_by_name_works(self, spark, tmp_path):
        """Two threat DataFrames should union cleanly."""
        from src.utils.schemas import THREAT_SCHEMA
        from src.analytics.threat_rules import _cast_threat_schema

        df1 = _df_from_rows(spark, tmp_path, "df1", THREAT_SCHEMA, [
            (100, "u1", "C1", "C2", "R1_suspicious_auth", "Medium", 50, 5, 5, "desc1"),
        ])

        df2 = _df_from_rows(spark, tmp_path, "df2", THREAT_SCHEMA, [
            (200, "u2", "C3", "C4", "R2_redteam_flow", "High", 80, 0, 10, "desc2"),
        ])

        combined = df1.unionByName(df2)
        assert combined.count() == 2
        assert set(combined.columns) == {f.name for f in THREAT_SCHEMA.fields}
