import os
import json
import logging
import subprocess

logger = logging.getLogger(__name__)

class VolatilityWrapper:
    """
    Wrapper around local Volatility 3 binary for executing memory analysis plugins.
    """
    def __init__(self, memory_image_path: str, vol_bin: str = "vol"):
        self.memory_image = memory_image_path
        self.vol_bin = vol_bin

        if not os.path.exists(self.memory_image):
            raise FileNotFoundError(f"CRITICAL: Memory image not found at {self.memory_image}")

    def run_plugin(self, plugin_name: str) -> dict:
        """
        Executes a Volatility 3 plugin and parses the JSON output.
        Returns structured status.
        """
        cmd = [
            self.vol_bin,
            "-f", self.memory_image,
            "-r", "json",
            plugin_name
        ]

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            if result.returncode != 0:
                logger.error(f"Volatility plugin {plugin_name} failed: {result.stderr}")
                return {"status": "ERROR", "data": [], "reason": "Volatility execution failed"}
            
            data = json.loads(result.stdout)
            if not data:
                return {"status": "PARTIAL", "data": [], "reason": "Volatility returned empty result"}
            
            return {"status": "SUCCESS", "data": data, "reason": "OK"}
            
        except FileNotFoundError:
            return {"status": "NOT_AVAILABLE", "data": [], "reason": f"Volatility binary '{self.vol_bin}' not found"}
        except subprocess.TimeoutExpired:
            return {"status": "ERROR", "data": [], "reason": "Volatility plugin timed out"}
        except json.JSONDecodeError as e:
            return {"status": "ERROR", "data": [], "reason": "Failed to parse Volatility JSON output"}
        except Exception as e:
            return {"status": "ERROR", "data": [], "reason": f"Unexpected error: {str(e)}"}