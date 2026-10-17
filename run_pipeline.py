"""
Main pipeline runner: executes all stages in order with timing and error handling.
Supports --skip-sample and --stage flags.

Usage:
  python run_pipeline.py                    # Run all stages
  python run_pipeline.py --skip-sample      # Skip sampling (use existing samples)
  python run_pipeline.py --stage silver     # Run only the silver stage
  python run_pipeline.py --stage "rule_R1"  # Run only rule R1
"""
import argparse
import logging
import sys
import time

# Add project root to path
from pathlib import Path
PROJECT_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(PROJECT_ROOT))

from config.settings import SAMPLE_DIR

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("pipeline")


def timed(stage_name: str, func, *args, **kwargs):
    """Run a function with timing and error handling."""
    logger.info(f"{'='*60}")
    logger.info(f"STAGE: {stage_name}")
    logger.info(f"{'='*60}")
    start = time.time()
    try:
        result = func(*args, **kwargs)
        elapsed = time.time() - start
        logger.info(f"STAGE {stage_name} DONE in {elapsed:.1f}s")
        return result
    except Exception as e:
        elapsed = time.time() - start
        logger.error(f"STAGE {stage_name} FAILED after {elapsed:.1f}s: {e}")
        raise


def main():
    parser = argparse.ArgumentParser(description="Cybersecurity Threat Detection Pipeline")
    parser.add_argument("--skip-sample", action="store_true",
                        help="Skip the sampling stage (use existing samples)")
    parser.add_argument("--stage", type=str, default=None,
                        help="Run only a specific stage")
    args = parser.parse_args()

    all_stages = [
        "inspect", "sample", "bronze", "silver",
        "rule_R1", "rule_R2", "rule_R3", "rule_R4", "rule_R5",
        "combine", "gold", "validate"
    ]

    if args.stage:
        if args.stage not in all_stages:
            logger.error(f"Unknown stage: {args.stage}. Available: {all_stages}")
            sys.exit(1)
        stages_to_run = [args.stage]
    else:
        stages_to_run = all_stages

    if args.skip_sample and "sample" in stages_to_run:
        stages_to_run.remove("sample")
        logger.info("Skipping sample stage (--skip-sample)")

    spark = None
    rule_results = {}
    combined_threats = None
    pipeline_start = time.time()

    try:
        # ── INSPECT ────────────────────────────────────────────────────
        if "inspect" in stages_to_run:
            from src.ingestion.inspect_data import inspect_sources
            timed("inspect", inspect_sources)

        # ── SAMPLE ────────────────────────────────────────────────────
        if "sample" in stages_to_run:
            from src.ingestion.sample_data import sample_sources
            timed("sample", sample_sources)

        # ── SPARK STAGES ──────────────────────────────────────────────
        needs_spark = any(s in stages_to_run for s in all_stages[2:])
        if needs_spark:
            from src.utils.spark_session import get_spark_session
            spark = get_spark_session()
            logger.info("SparkSession created")

        # ── BRONZE ────────────────────────────────────────────────────
        if "bronze" in stages_to_run:
            from src.ingestion.bronze import ingest_to_bronze
            bronze_counts = timed("bronze", ingest_to_bronze, spark)
            logger.info(f"Bronze counts: {bronze_counts}")

        # ── SILVER ────────────────────────────────────────────────────
        if "silver" in stages_to_run:
            from src.transformation.silver import run_silver
            silver_counts = timed("silver", run_silver, spark)
            logger.info(f"Silver counts: {silver_counts}")

        # ── THREAT RULES ──────────────────────────────────────────────
        from src.analytics.threat_rules import (
            rule_suspicious_auth, rule_redteam_flow, rule_redteam_dns,
            rule_suspicious_process, rule_redteam_process, combine_threats,
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

        # ── COMBINE ───────────────────────────────────────────────────
        if "combine" in stages_to_run:
            dfs = list(rule_results.values())
            if not dfs:
                # If running combine alone, we need to re-run rules
                logger.info("No rule results in memory; running all rules first")
                rule_results["R1"] = rule_suspicious_auth(spark)
                rule_results["R2"] = rule_redteam_flow(spark)
                rule_results["R3"] = rule_redteam_dns(spark)
                rule_results["R4"] = rule_suspicious_process(spark)
                rule_results["R5"] = rule_redteam_process(spark)
                dfs = list(rule_results.values())
            combined_threats = timed("combine", combine_threats, spark, *dfs)

        # ── GOLD ──────────────────────────────────────────────────────
        if "gold" in stages_to_run:
            from src.analytics.gold import write_gold
            if combined_threats is None:
                # Read from combine if it was run previously
                from config.settings import GOLD_DIR
                threats_path = GOLD_DIR / "all_threats"
                if threats_path.exists():
                    combined_threats = spark.read.parquet(str(threats_path))
                else:
                    raise RuntimeError("No combined threats available for Gold stage")
            stats = timed("gold", write_gold, spark, combined_threats)
            logger.info(f"Gold statistics: {stats}")

        # ── VALIDATE ──────────────────────────────────────────────────
        if "validate" in stages_to_run:
            from src.utils.validate import validate
            passed = timed("validate", validate, spark)
            if not passed:
                logger.error("VALIDATION FAILED")
                sys.exit(1)

    except Exception as e:
        logger.error(f"PIPELINE FAILED: {e}", exc_info=True)
        sys.exit(1)
    finally:
        if spark:
            spark.stop()
            logger.info("SparkSession stopped")

    elapsed = time.time() - pipeline_start
    logger.info(f"{'='*60}")
    logger.info(f"PIPELINE COMPLETE in {elapsed:.1f}s")
    logger.info(f"{'='*60}")

    # Summary
    for rule_name, df in rule_results.items():
        try:
            cnt = df.count() if hasattr(df, 'count') else 'N/A'
        except Exception:
            cnt = 'stopped'
        logger.info(f"  {rule_name}: {cnt} threats")


if __name__ == "__main__":
    main()
