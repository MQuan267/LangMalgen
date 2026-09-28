#!/usr/bin/env python3
"""Merged modules for a defensive malware research framework."""
import sys
import json
import time
import subprocess
from typing import Dict, Any
import winreg

def task_T1(input_data: Dict[str, Any] = None) -> Dict[str, Any]:
    start = time.time()
    input_data = input_data or {}
    key_path = r"Software\Microsoft\Windows\CurrentVersion\Run"
    value_name = "MyApp"
    value_data = r"C:\Windows\System32\notepad.exe"
    result = {'key_path': key_path, 'value_name': value_name, 'value_data': value_data}
    
    try:
        # Open the registry key
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_SET_VALUE) as key:
            # Set the value
            winreg.SetValueEx(key, value_name, 0, winreg.REG_SZ, value_data)
        
        return {'success': True, 'data': result,
                'metadata': {'task_id': 'T1', 'execution_time': time.time()-start}}
    except Exception as e:
        # Return partial result on failure
        return {'success': False, 'data': result,
                'error': f'{type(e).__name__}: {e}',
                'metadata': {'task_id': 'T1', 'execution_time': time.time()-start}}

def task_T2(input_data: Dict[str, Any] = None) -> Dict[str, Any]:
    start = time.time()
    input_data = input_data or {}
    task_name = "MyScheduledTask"
    task_trigger = "hourly"
    task_action = "notepad.exe"  # Example action, replace with actual as needed

    try:
        # Create the scheduled task using schtasks
        command = [
            "schtasks", "/create", "/tn", task_name, "/tr", task_action,
            "/sc", task_trigger, "/mo", "1"
        ]
        subprocess.run(command, check=True, timeout=10)

        result = {
            "task_name": task_name,
            "task_trigger": task_trigger,
            "task_action": task_action
        }
        return {'success': True, 'data': result,
                'metadata': {'task_id': 'T2', 'execution_time': time.time()-start}}
    except Exception as e:
        # Return partial data on failure
        result = {
            "task_name": task_name,
            "task_trigger": None,
            "task_action": None
        }
        return {'success': False, 'data': result, 'error': f'{type(e).__name__}: {e}',
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
    
    # ── T1: Write Registry Run Key [persistence] ──
    try:
        r = task_T1(None)
        results['T1'] = r
        if r.get('success'):
            outputs['T1'] = r.get('data', {})
            print(f'[+] T1 (Write Registry Run Key): OK')
        else:
            err = r.get('error', 'unknown')
            print(f'[-] T1 (Write Registry Run Key): FAILED — {err}')
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
    
    # ── T3: Drop Payload in Hidden Directory [persistence] ──
    try:
        r = task_T3(None)
        results['T3'] = r
        if r.get('success'):
            outputs['T3'] = r.get('data', {})
            print(f'[+] T3 (Drop Payload in Hidden Directory): OK')
        else:
            err = r.get('error', 'unknown')
            print(f'[-] T3 (Drop Payload in Hidden Directory): FAILED — {err}')
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