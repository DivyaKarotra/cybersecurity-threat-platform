"""
Main pipeline runner: executes all stages in order with timing and error handling.
Stages: inspect -> sample -> bronze -> silver -> analytics -> 5 rules -> combine -> gold -> validate
Supports --skip-sample and --stage flags.

Usage:
  python run_pipeline.py                    # Run all stages end-to-end
  python run_pipeline.py --skip-sample      # Skip sampling (use existing samples)
  python run_pipeline.py --stage gold       # Run only the gold stage
  python run_pipeline.py --stage rule_R1    # Run only rule R1
"""
import argparse
import logging
import sys
import time
from pathlib import Path

# Add project root to path
PROJECT_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(PROJECT_ROOT))

from config.settings import GOLD_DIR

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("pipeline")


def timed(stage_name: str, func, *args, **kwargs):
    """Run a function with timing, log start/finish, fail fast on exception."""
    logger.info(f"{'='*60}")
    logger.info(f"STAGE: {stage_name}")
    logger.info(f"{'='*60}")
    start = time.time()
    try:
        result = func(*args, **kwargs)
        elapsed = time.time() - start
        logger.info(f"STAGE {stage_name} DONE in {elapsed:.2f}s")
        return result
    except Exception as e:
        elapsed = time.time() - start
        logger.error(f"STAGE {stage_name} FAILED after {elapsed:.2f}s: {e}")
        raise


def main():
    parser = argparse.ArgumentParser(description="Cybersecurity Threat Detection Pipeline")
    parser.add_argument(
        "--skip-sample",
        action="store_true",
        help="Skip the sampling stage (use existing sampled files)",
    )
    parser.add_argument(
        "--stage",
        type=str,
        default=None,
        help="Run only a specific stage",
    )
    args = parser.parse_args()

    all_stages = [
        "inspect",
        "sample",
        "bronze",
        "silver",
        "analytics",
        "rule_R1",
        "rule_R2",
        "rule_R3",
        "rule_R4",
        "rule_R5",
        "combine",
        "gold",
        "validate",
    ]

    if args.stage:
        if args.stage not in all_stages:
            logger.error(f"Unknown stage: '{args.stage}'. Available stages: {all_stages}")
            sys.exit(1)
        stages_to_run = [args.stage]
    else:
        stages_to_run = list(all_stages)

    if args.skip_sample and "sample" in stages_to_run:
        stages_to_run.remove("sample")
        logger.info("Skipping sample stage (--skip-sample requested)")

    spark = None
    rule_results = {}
    combined_threats = None
    pipeline_start = time.time()

    try:
        # 1. INSPECT
        if "inspect" in stages_to_run:
            from src.ingestion.inspect_data import inspect_sources
            timed("inspect", inspect_sources)

        # 2. SAMPLE
        if "sample" in stages_to_run:
            from src.ingestion.sample_data import sample_sources
            timed("sample", sample_sources)

        # SPARK SESSION (needed for bronze through validate)
        spark_needed = any(
            s in stages_to_run
            for s in [
                "bronze", "silver", "analytics",
                "rule_R1", "rule_R2", "rule_R3", "rule_R4", "rule_R5",
                "combine", "gold", "validate"
            ]
        )
        if spark_needed:
            from src.utils.spark_session import get_spark_session
            spark = get_spark_session("ThreatDetectionPipeline")
            spark.sparkContext.setLogLevel("ERROR")
            logger.info("PySpark session initialised (Log level: ERROR)")

        # 3. BRONZE
        if "bronze" in stages_to_run:
            from src.ingestion.bronze import ingest_to_bronze
            bronze_counts = timed("bronze", ingest_to_bronze, spark)
            logger.info(f"Bronze ingestion summary: {bronze_counts}")

        # 4. SILVER
        if "silver" in stages_to_run:
            from src.transformation.silver import run_silver
            silver_counts = timed("silver", run_silver, spark)
            logger.info(f"Silver transformation summary: {silver_counts}")

        # 5. PER-SOURCE ANALYTICS
        if "analytics" in stages_to_run:
            from src.analytics.gold import write_source_analytics
            timed("analytics", write_source_analytics, spark)

        # 6. RULES (R1 - R5)
        from src.analytics.threat_rules import (
            rule_suspicious_auth,
            rule_redteam_flow,
            rule_redteam_dns,
            rule_suspicious_process,
            rule_redteam_process,
            combine_threats,
        )

        if "rule_R1" in stages_to_run:
            rule_results["R1"] = timed("rule_R1", rule_suspicious_auth, spark)

        if "rule_R2" in stages_to_run:
            rule_results["R2"] = timed("rule_R2", rule_redteam_flow, spark)

        if "rule_R3" in stages_to_run:
            rule_results["R3"] = timed("rule_R3", rule_redteam_dns, spark)

        if "rule_R4" in stages_to_run:
            rule_results["R4"] = timed("rule_R4", rule_suspicious_process, spark)

        if "rule_R5" in stages_to_run:
            rule_results["R5"] = timed("rule_R5", rule_redteam_process, spark)

        # 7. COMBINE
        if "combine" in stages_to_run:
            dfs = [rule_results[k] for k in ["R1", "R2", "R3", "R4", "R5"] if k in rule_results]
            if not dfs:
                logger.info("Executing rules to supply inputs to combine stage...")
                r1 = rule_suspicious_auth(spark)
                r2 = rule_redteam_flow(spark)
                r3 = rule_redteam_dns(spark)
                r4 = rule_suspicious_process(spark)
                r5 = rule_redteam_process(spark)
                rule_results.update({"R1": r1, "R2": r2, "R3": r3, "R4": r4, "R5": r5})
                dfs = [r1, r2, r3, r4, r5]
            combined_threats = timed("combine", combine_threats, spark, *dfs)

        # 8. GOLD
        if "gold" in stages_to_run:
            from src.analytics.gold import write_gold
            if combined_threats is None:
                threats_path = GOLD_DIR / "all_threats"
                has_parquet = threats_path.exists() and any(threats_path.glob("*.parquet"))
                if has_parquet:
                    combined_threats = spark.read.parquet(str(threats_path))
                else:
                    logger.info("Running rules and combine to prepare threats for Gold...")
                    r1 = rule_suspicious_auth(spark)
                    r2 = rule_redteam_flow(spark)
                    r3 = rule_redteam_dns(spark)
                    r4 = rule_suspicious_process(spark)
                    r5 = rule_redteam_process(spark)
                    rule_results.update({"R1": r1, "R2": r2, "R3": r3, "R4": r4, "R5": r5})
                    combined_threats = combine_threats(spark, r1, r2, r3, r4, r5)

            stats = timed("gold", write_gold, spark, combined_threats)
            logger.info(f"Gold stage complete. Statistics: {stats}")

        # 9. VALIDATE
        if "validate" in stages_to_run:
            from src.utils.validate import validate
            passed = timed("validate", validate, spark)
            if not passed:
                logger.error("PIPELINE FAILED: Validation checks did not pass.")
                sys.exit(1)

    except Exception as e:
        logger.error(f"PIPELINE EXECUTION FAILED: {e}", exc_info=True)
        sys.exit(1)
    finally:
        if spark is not None:
            spark.stop()
            logger.info("PySpark session cleanly stopped.")

    total_time = time.time() - pipeline_start
    logger.info(f"{'='*60}")
    logger.info(f"PIPELINE COMPLETED SUCCESSFULLY in {total_time:.2f}s")
    logger.info(f"{'='*60}")


if __name__ == "__main__":
    main()
