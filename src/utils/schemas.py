"""
Explicit StructType schemas for LANL Cyber1 datasets.
These are the expected schemas; the inspection stage may adapt them.
Field names are kept raw (matching column positions); Silver renames.
`?` is read as null via Spark CSV nullValue option.
"""
from pyspark.sql.types import (
    StructType, StructField, LongType, StringType, IntegerType
)

AUTH_SCHEMA = StructType([
    StructField("time", LongType(), False),
    StructField("src_user", StringType(), True),
    StructField("dst_user", StringType(), True),
    StructField("src_computer", StringType(), True),
    StructField("dst_computer", StringType(), True),
    StructField("auth_type", StringType(), True),
    StructField("logon_type", StringType(), True),
    StructField("orientation", StringType(), True),
    StructField("success_failure", StringType(), True),
])

DNS_SCHEMA = StructType([
    StructField("time", LongType(), False),
    StructField("src_computer", StringType(), True),
    StructField("resolved_computer", StringType(), True),
])

FLOWS_SCHEMA = StructType([
    StructField("time", LongType(), False),
    StructField("duration", LongType(), True),
    StructField("src_computer", StringType(), True),
    StructField("src_port", StringType(), True),
    StructField("dst_computer", StringType(), True),
    StructField("dst_port", StringType(), True),
    StructField("protocol", StringType(), True),
    StructField("packet_count", LongType(), True),
    StructField("byte_count", LongType(), True),
])

PROC_SCHEMA = StructType([
    StructField("time", LongType(), False),
    StructField("user", StringType(), True),
    StructField("computer", StringType(), True),
    StructField("process_name", StringType(), True),
    StructField("start_end", StringType(), True),
])

REDTEAM_SCHEMA = StructType([
    StructField("time", LongType(), False),
    StructField("user", StringType(), True),
    StructField("src_computer", StringType(), True),
    StructField("dst_computer", StringType(), True),
])

SCHEMAS = {
    "auth": AUTH_SCHEMA,
    "dns": DNS_SCHEMA,
    "flows": FLOWS_SCHEMA,
    "proc": PROC_SCHEMA,
    "redteam": REDTEAM_SCHEMA,
}

# Unified threat output schema
from pyspark.sql.types import BooleanType  # noqa: E402

THREAT_SCHEMA = StructType([
    StructField("time", LongType(), False),
    StructField("user", StringType(), True),
    StructField("src_computer", StringType(), True),
    StructField("dst_computer", StringType(), True),
    StructField("threat_type", StringType(), False),
    StructField("severity", StringType(), True),
    StructField("risk_score", IntegerType(), True),
    StructField("failed_attempts", LongType(), True),
    StructField("event_count", LongType(), True),
    StructField("description", StringType(), True),
])
