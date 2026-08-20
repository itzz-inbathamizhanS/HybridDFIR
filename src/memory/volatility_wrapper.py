import os
import json
import subprocess

class VolatilityWrapper:
    """
    Wrapper around local Volatility 3 binary for executing memory analysis plugins.
    """
    def __init__(self, memory_image_path: str, vol_bin: str = "vol"):
        self.memory_image = memory_image_path
        self.vol_bin = vol_bin

        if not os.path.exists(self.memory_image):
            raise FileNotFoundError(f"CRITICAL: Memory image not found at {self.memory_image}")

    def run_plugin(self, plugin_name: str) -> list:
        """
        Executes a Volatility 3 plugin and parses the JSON output.
        Returns an empty list if Volatility is not installed or execution fails.
        """
        cmd = [
            self.vol_bin,
            "-f", self.memory_image,
            "-r", "json",
            plugin_name
        ]

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            return json.loads(result.stdout)
        except FileNotFoundError:
            print(f"[!] Warning: Volatility executable '{self.vol_bin}' not found in system PATH.")
            print("[!] Continuing pipeline with empty memory plugin output...")
            return []
        except (subprocess.CalledProcessError, json.JSONDecodeError) as e:
            print(f"[!] Warning: Volatility failed or returned non-JSON output: {e}")
            return []