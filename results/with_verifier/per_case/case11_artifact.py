#!/usr/bin/env python3
"""Detect sandbox environments by checking for low uptime, small RAM size, and virtual machine artifacts (VMware/VirtualBox)"""
import sys
import json
import time
import os
import subprocess
import platform
from typing import Dict, Any
import winreg

def check_system_uptime() -> bool:
    """Check if the system uptime is less than a threshold (e.g., 10 minutes)"""
    try:
        output = subprocess.run(['net', 'stats', 'srv'], capture_output=True, text=True, timeout=5)
        if output.returncode == 0:
            for line in output.stdout.splitlines():
                if "Statistics since" in line:
                    uptime_str = line.split("since")[1].strip()
                    # Simplified uptime check logic
                    return "minutes" in uptime_str and int(uptime_str.split()[0]) < 10
    except Exception:
        pass
    return False

def check_ram_size() -> bool:
    """Check if the RAM size is less than a threshold (e.g., 2GB)"""
    try:
        mem_bytes = os.sysconf('SC_PAGE_SIZE') * os.sysconf('SC_PHYS_PAGES')
        mem_gb = mem_bytes / (1024. ** 3)
        return mem_gb < 2
    except (ValueError, AttributeError, OSError):
        pass
    return False

def check_virtual_machine_artifacts() -> bool:
    """Check for VMware/VirtualBox artifacts in the registry"""
    vm_artifacts = [
        r"SYSTEM\CurrentControlSet\Services\VBoxGuest",
        r"SYSTEM\CurrentControlSet\Services\VBoxService",
        r"SYSTEM\CurrentControlSet\Services\vmci",
        r"SYSTEM\CurrentControlSet\Services\vmhgfs",
        r"SYSTEM\CurrentControlSet\Services\vmusbmouse"
    ]
    try:
        for artifact in vm_artifacts:
            try:
                with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, artifact) as key:
                    return True
            except FileNotFoundError:
                continue
    except Exception:
        pass
    return False

def task_T1(input_data: Dict[str, Any] = None) -> Dict[str, Any]:
    start = time.time()
    input_data = input_data or {}
    try:
        is_sandbox = check_system_uptime() or check_ram_size() or check_virtual_machine_artifacts()
        status = "sandbox_detected" if is_sandbox else "environment_safe"
        result = {"uptime_check": check_system_uptime(), "ram_check": check_ram_size(), "vm_check": check_virtual_machine_artifacts()}
        return {'success': True, 'data': {'status': status, 'result': json.dumps(result)},
                'metadata': {'task_id': 'T1', 'execution_time': time.time()-start}}
    except Exception as e:
        return {'success': False, 'error': f'{type(e).__name__}: {e}',
                'metadata': {'task_id': 'T1', 'execution_time': time.time()-start}}

def main() -> dict:
    """Auto-generated orchestrator — do not edit by hand."""
    outputs: dict = {}
    results: dict = {}
    failed:  list = []
    
    # ── T1: Core Objective [execution] ──
    try:
        r = task_T1(None)
        results['T1'] = r
        if r.get('success'):
            outputs['T1'] = r.get('data', {})
            print(f'[+] T1 (Core Objective): OK')
        else:
            err = r.get('error', 'unknown')
            print(f'[-] T1 (Core Objective): FAILED — {err}')
            failed.append('T1')
            print('[!] abort_mission — stopping')
            return {'success': False, 'failed': failed, 'outputs': outputs, 'results': results}
    except Exception as e:
        print(f'[!] T1 crashed: {e}')
        failed.append('T1')
        results['T1'] = {'success': False, 'error': str(e)}
        return {'success': False, 'failed': failed, 'outputs': outputs, 'results': results}
    
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