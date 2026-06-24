#!/usr/bin/env python3
import sys, json, time, shutil, os, base64
from typing import Dict, Any
from pathlib import Path

def task_T1(input_data: Dict[str, Any] = None) -> Dict[str, Any]:
    start = time.time()
    input_data = input_data or {}
    try:
        # Define the malicious DLL name
        dll_name = "malicious.dll"
        
        # Determine a suitable system PATH directory
        system_path = os.environ.get('WINDIR', 'C:\\Windows')
        target_directory = os.path.join(system_path, 'System32')
        
        # Define the full path for the DLL
        dll_path = os.path.join(target_directory, dll_name)
        
        # Simulate placing the DLL (in a real scenario, you would copy the DLL file)
        # Here we just ensure the directory exists
        if not os.path.exists(target_directory):
            os.makedirs(target_directory)
        
        # Simulate the DLL placement
        # shutil.copy('path_to_malicious_dll', dll_path)  # Uncomment and modify in a real scenario
        
        # Return the path and DLL name
        result = {
            "path": dll_path,
            "dll_name": dll_name
        }
        
        return {'success': True, 'data': result,
                'metadata': {'task_id': 'T1', 'execution_time': time.time()-start}}
    except Exception as e:
        # Return partial data on failure
        result = {
            "path": None,
            "dll_name": None
        }
        return {'success': False, 'data': result, 'error': f'{type(e).__name__}: {e}',
                'metadata': {'task_id': 'T1', 'execution_time': time.time()-start}}

def xor_encrypt(data: bytes, key: bytes) -> bytes:
    """XOR encrypts the data with the given key."""
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

        # Encode the encrypted payload with base64
        encoded_payload = base64.b64encode(encrypted_payload)

        # Convert to hex string for output
        encoded_data_hex = encoded_payload.hex()

        result = {'encoded_data': encoded_data_hex}
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
        # Retrieve the path and dll_name from input_data
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
        return {'success': False, 'data': {'success': False},
                'error': f'{type(e).__name__}: {e}',
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