import subprocess
import json
import os

class VolatilityWrapper:
    """
    A local wrapper for Volatility 3 to analyze memory dumps without 
    relying on external APIs. 
    """
    def __init__(self, memory_image_path: str, vol_bin: str = "vol"):
        """
        Args:
            memory_image_path (str): Path to the raw memory dump (.vmem, .raw).
            vol_bin (str): The command or path to the local Volatility 3 executable.
        """
        self.memory_image = memory_image_path
        self.vol_bin = vol_bin
        
        if not os.path.exists(self.memory_image):
            raise FileNotFoundError(f"CRITICAL: Memory image not found at {self.memory_image}")

    def run_plugin(self, plugin_name: str) -> list:
        """
        Executes a Volatility 3 plugin and parses the JSON output.
        
        Args:
            plugin_name (str): e.g., 'windows.pslist.PsList', 'windows.malfind.Malfind'
            
        Returns:
            list: Parsed JSON output from the Volatility plugin.
        """
        # Command: vol -f <image> -r pretty -o <temp_dir> <plugin>
        cmd = [
            self.vol_bin, 
            "-f", self.memory_image, 
            "-r", "json", 
            plugin_name
        ]
        
        try:
            # Execute locally in the air-gapped environment
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            
            # Volatility 3 JSON output is printed to stdout
            if result.stdout:
                return json.loads(result.stdout)
            return []
            
        except subprocess.CalledProcessError as e:
            print(f"[-] Volatility execution failed for {plugin_name}: {e.stderr}")
            return []
        except json.JSONDecodeError:
            print(f"[-] Failed to parse Volatility JSON output for {plugin_name}")
            return []