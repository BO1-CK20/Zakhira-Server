# backend.py - Python backend for Electron
import sys
import json
import io
from pathlib import Path

# Fix Windows console encoding
if sys.platform == 'win32':
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8')

# Add project to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from emulators.emulator_manager import EmulatorManager

# Initialize emulator manager
emu_manager = EmulatorManager(Path(__file__).parent.parent)

def handle_command(cmd):
    """Handle incoming commands from Electron"""
    action = cmd.get('action')
    
    if action == 'launch':
        emulator_id = cmd.get('emulator')
        game_path = cmd.get('game', '')
        
        # Check BIOS
        bios_status = emu_manager.check_bios_status(emulator_id)
        if not bios_status['all_found'] and bios_status.get('required'):
            return {'success': False, 'error': f"BIOS missing: {bios_status['required']}"}
        
        # Launch emulator
        result = emu_manager.launch_game(emulator_id, game_path)
        return {'success': result}
    
    return {'success': False, 'error': 'Unknown action'}

def main():
    """Main loop - read commands from stdin"""
    print("Python backend started", flush=True)
    
    for line in sys.stdin:
        try:
            cmd = json.loads(line.strip())
            result = handle_command(cmd)
            print(json.dumps(result), flush=True)
        except json.JSONDecodeError:
            print(json.dumps({'success': False, 'error': 'Invalid JSON'}), flush=True)
        except Exception as e:
            print(json.dumps({'success': False, 'error': str(e)}), flush=True)

if __name__ == '__main__':
    main()
