"""
SparkSession factory – single shared session for the entire pipeline.
"""
import os
import sys
from pyspark.sql import SparkSession

def get_spark_session(app_name: str = "CyberThreatPlatform") -> SparkSession:
    """Create or return the shared SparkSession with project defaults."""
    # Ensure PySpark uses the same Python as the caller (use 8.3 short path on Windows to avoid space issues)
    py_exec = sys.executable
    if sys.platform == "win32":
        try:
            import ctypes
            buf = ctypes.create_unicode_buffer(500)
            if ctypes.windll.kernel32.GetShortPathNameW(sys.executable, buf, 500):
                py_exec = buf.value
        except Exception:
            pass
    os.environ["PYSPARK_PYTHON"] = py_exec
    os.environ["PYSPARK_DRIVER_PYTHON"] = py_exec

    from config.settings import SPARK_DRIVER_MEMORY, SPARK_SHUFFLE_PARTITIONS

    spark = (
        SparkSession.builder
        .appName(app_name)
        .master("local[*]")
        .config("spark.driver.memory", SPARK_DRIVER_MEMORY)
        .config("spark.sql.shuffle.partitions", str(SPARK_SHUFFLE_PARTITIONS))
        .config("spark.sql.session.timeZone", "UTC")
        .config("spark.sql.adaptive.enabled", "true")
        .config("spark.sql.adaptive.coalescePartitions.enabled", "true")
        .config("spark.ui.showConsoleProgress", "false")
        .config("spark.driver.extraJavaOptions", "--add-opens=java.base/sun.nio.ch=ALL-UNNAMED --add-opens=java.base/java.lang=ALL-UNNAMED --add-opens=java.base/java.util=ALL-UNNAMED --add-opens=java.base/java.nio=ALL-UNNAMED")
        .config("spark.executor.extraJavaOptions", "--add-opens=java.base/sun.nio.ch=ALL-UNNAMED --add-opens=java.base/java.lang=ALL-UNNAMED --add-opens=java.base/java.util=ALL-UNNAMED --add-opens=java.base/java.nio=ALL-UNNAMED")
        .getOrCreate()
    )
    spark.sparkContext.setLogLevel("ERROR")
    return spark
