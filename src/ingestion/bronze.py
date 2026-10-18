"""
Bronze layer: read sampled CSVs with explicit StructType schemas, treat `?` as null,
write typed Parquet. No cleaning – raw typed data only.
"""
import logging
from pathlib import Path
import sys

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from pyspark.sql import SparkSession

from config.settings import SAMPLE_DIR, BRONZE_DIR
from src.utils.schemas import SCHEMAS

logger = logging.getLogger(__name__)


def ingest_to_bronze(spark: SparkSession, sources: list = None) -> dict:
    """Read each sampled CSV into a typed DataFrame and write as Parquet."""
    BRONZE_DIR.mkdir(parents=True, exist_ok=True)
    counts = {}
    target_sources = sources if sources else list(SCHEMAS.keys())

    for source in target_sources:
        if source not in SCHEMAS:
            continue
        schema = SCHEMAS[source]
        csv_path = SAMPLE_DIR / f"{source}.csv"
        if not csv_path.exists():
            logger.warning(f"Sample file not found: {csv_path}")
            continue

        logger.info(f"Bronze ingestion: {source}")
        df = (
            spark.read
            .option("header", "false")
            .option("nullValue", "?")
            .option("mode", "PERMISSIVE")
            .schema(schema)
            .csv(str(csv_path))
        )

        row_count = df.count()
        out_path = BRONZE_DIR / source
        df.write.mode("overwrite").parquet(str(out_path))
        counts[source] = row_count
        logger.info(f"  {source}: {row_count:,} rows → {out_path}")

    return counts


if __name__ == "__main__":
    import argparse
    from src.utils.spark_session import get_spark_session
    parser = argparse.ArgumentParser(description="Run Bronze ingestion.")
    parser.add_argument("--sources", nargs="+", default=None, help="Sources to ingest")
    args = parser.parse_args()

    spark = get_spark_session("BronzeIngestion")
    ingest_to_bronze(spark, sources=args.sources)
    spark.stop()

