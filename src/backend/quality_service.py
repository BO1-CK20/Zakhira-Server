"""
Quality Service - Automatic hardware detection and quality tier system
Based on psutil + GPUtil for hardware detection
"""

import platform
import json
import sys
from typing import Dict, Optional, Tuple

class QualityService:
    """Automatic quality tier detection and settings management"""
    
    def __init__(self):
        self.tier = None
        self.settings = None
        self.detect_hardware()
    
    def detect_hardware(self) -> Dict:
        """Detect all hardware specifications and determine quality tier"""
        hardware_info = {}
        
        # 1. Platform information (using platform module) [citation:1]
        hardware_info['platform'] = platform.system()
        hardware_info['architecture'] = platform.machine()
        hardware_info['processor'] = platform.processor()
        
        # 2. CPU Information (using psutil) [citation:7]
        try:
            import psutil
            hardware_info['cpu_logical_cores'] = psutil.cpu_count(logical=True)
            hardware_info['cpu_physical_cores'] = psutil.cpu_count(logical=False)
            hardware_info['cpu_freq'] = psutil.cpu_freq()._asdict() if psutil.cpu_freq() else {}
            hardware_info['cpu_percent'] = psutil.cpu_percent(interval=0.5)
        except ImportError:
            print("[!] psutil not installed. Install with: pip install psutil")
            hardware_info['cpu_logical_cores'] = 4  # Default fallback
        
        # 3. RAM Information [citation:1]
        try:
            import psutil
            mem = psutil.virtual_memory()
            hardware_info['ram_total_gb'] = round(mem.total / (1024**3), 2)
            hardware_info['ram_available_gb'] = round(mem.available / (1024**3), 2)
            hardware_info['ram_percent'] = mem.percent
        except:
            hardware_info['ram_total_gb'] = 8  # Default fallback
        
        # 4. GPU Information (compatible with Python 3.12+, no GPUtil dependency)
        hardware_info['gpus'] = []
        try:
            # Method 1: Try WMI on Windows (most reliable on Windows)
            if platform.system() == "Windows":
                import subprocess
                result = subprocess.run(
                    ['wmic', 'path', 'win32_videocontroller', 'get', 'name', '/format:csv'],
                    capture_output=True, text=True, encoding='utf-8', errors='ignore', timeout=5
                )
                if result.returncode == 0:
                    lines = [line.strip() for line in result.stdout.strip().split('\n') if line.strip()]
                    for line in lines[2:]:  # Skip header and title rows
                        parts = line.split(',')
                        if len(parts) >= 2 and parts[1]:
                            hardware_info['gpus'].append({
                                'name': parts[1].strip(),
                                'memory_total_mb': 0  # WMIC memory parsing is complex
                            })
            
            # Method 2: Try using Python's ctypes to query Windows registry for GPU info
            if not hardware_info['gpus'] and platform.system() == "Windows":
                try:
                    import winreg
                    with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, 
                                       r"SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}",
                                       0, winreg.KEY_READ) as key:
                        subkey_index = 0
                        while True:
                            try:
                                subkey_name = winreg.EnumKey(key, subkey_index)
                                with winreg.OpenKey(key, subkey_name) as subkey:
                                    try:
                                        gpu_name, _ = winreg.QueryValueEx(subkey, "DriverDesc")
                                        if gpu_name:
                                            hardware_info['gpus'].append({
                                                'name': gpu_name,
                                                'memory_total_mb': 0
                                            })
                                    except:
                                        pass
                                subkey_index += 1
                            except OSError:
                                break
                except:
                    pass
                    
        except Exception as e:
            print(f"[i] GPU detection skipped: {e}")
        
        # 5. Determine quality tier based on hardware [citation:7]
        self.tier = self._determine_tier(hardware_info)
        self.settings = self._get_quality_settings(self.tier)
        
        hardware_info['quality_tier'] = self.tier
        hardware_info['quality_settings'] = self.settings
        
        return hardware_info
    
    def _determine_tier(self, hardware_info: Dict) -> str:
        """Determine quality tier based on hardware specs"""
        ram_gb = hardware_info.get('ram_total_gb', 8)
        cpu_cores = hardware_info.get('cpu_logical_cores', 4)
        
        # Check GPU VRAM if available
        gpu_vram = 0
        if hardware_info.get('gpus'):
            gpu_vram = hardware_info['gpus'][0].get('memory_total_mb', 0) / 1024  # Convert to GB
        
        # Tier determination logic [citation:7]
        if ram_gb <= 6 or cpu_cores <= 4 or (gpu_vram > 0 and gpu_vram <= 2):
            return "low"
        elif ram_gb <= 12 or cpu_cores <= 6 or (gpu_vram > 0 and gpu_vram <= 4):
            return "medium"
        elif ram_gb <= 24 or cpu_cores <= 8 or (gpu_vram > 0 and gpu_vram <= 8):
            return "high"
        else:
            return "ultra"
    
    def _get_quality_settings(self, tier: str) -> Dict:
        """Get quality settings based on tier"""
        settings = {
            "low": {
                "name": "منخفض",
                "resolution": "720p",
                "filters": ["FXAA"],
                "texture_quality": "low",
                "shadows": False,
                "vignette": False,
                "msaa": 0,
                "upscale_multiplier": 2
            },
            "medium": {
                "name": "متوسط",
                "resolution": "1080p",
                "filters": ["FXAA", "ColoredFXAA"],
                "texture_quality": "medium",
                "shadows": True,
                "vignette": False,
                "msaa": 2,
                "upscale_multiplier": 3
            },
            "high": {
                "name": "عالي",
                "resolution": "1440p",
                "filters": ["FXAA", "ColoredFXAA", "Vignette"],
                "texture_quality": "high",
                "shadows": True,
                "vignette": True,
                "msaa": 4,
                "upscale_multiplier": 4
            },
            "ultra": {
                "name": "فائق",
                "resolution": "4K",
                "filters": ["FXAA", "ColoredFXAA", "Vignette", "Scanlines"],
                "texture_quality": "ultra",
                "shadows": True,
                "vignette": True,
                "msaa": 8,
                "upscale_multiplier": 6
            }
        }
        return settings.get(tier, settings["medium"])
    
    def get_emulator_settings(self, emulator_id: str) -> Dict:
        """Get emulator-specific quality settings"""
        base_settings = self.settings
        
        # Emulator-specific overrides [citation:7]
        if emulator_id == "ps1":
            return {
                "resolution_scale": base_settings.get("upscale_multiplier", 4),
                "texture_filtering": "xBR" if base_settings["texture_quality"] != "low" else "Bilinear",
                "post_processing": ",".join(base_settings["filters"]),
                "true_color": base_settings["texture_quality"] != "low"
            }
        elif emulator_id == "ps2":
            return {
                "internal_resolution": base_settings["resolution"],
                "texture_filtering": "Bilinear" if base_settings["texture_quality"] == "low" else "Anisotropic",
                "anisotropic_filtering": 16 if base_settings["texture_quality"] in ["high", "ultra"] else 8,
                "shader": base_settings["filters"][0] if base_settings["filters"] else "FXAA"
            }
        elif emulator_id == "psp":
            return {
                "rendering_resolution": base_settings["resolution"],
                "post_processing_shader": base_settings["filters"][0] if base_settings["filters"] else "FXAA",
                "texture_scaling": 5 if base_settings["texture_quality"] == "ultra" else 3
            }
        else:
            return base_settings
    
    def to_json(self) -> str:
        """Return hardware info as JSON string"""
        info = self.detect_hardware()
        return json.dumps(info, indent=2, ensure_ascii=False)


# Standalone test
if __name__ == "__main__":
    print("[TEST] Testing Quality Service...")
    qs = QualityService()
    print(f"[OK] Hardware detected - Tier: {qs.tier}")
    print(f"[INFO] Settings: {qs.settings}")
    print(f"\n[INFO] Full info:\n{qs.to_json()}")
