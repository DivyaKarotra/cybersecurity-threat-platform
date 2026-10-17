"""
Bronze layer: read sampled CSVs with explicit StructType schemas, treat `?` as null,
write typed Parquet. No cleaning – raw typed data only.
"""
import logging

from pyspark.sql import SparkSession

from config.settings import SAMPLE_DIR, BRONZE_DIR
from src.utils.schemas import SCHEMAS

logger = logging.getLogger(__name__)


def ingest_to_bronze(spark: SparkSession) -> dict:
    """Read each sampled CSV into a typed DataFrame and write as Parquet."""
    BRONZE_DIR.mkdir(parents=True, exist_ok=True)
    counts = {}

    for source, schema in SCHEMAS.items():
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
