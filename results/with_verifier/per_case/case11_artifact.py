#!/usr/bin/env python3
"""Detect sandbox environments by checking for low uptime, small RAM size, and virtual machine artifacts."""
import sys
import json
import time
import os
import platform
import subprocess
from typing import Dict, Any
import winreg

def check_uptime() -> bool:
    """Check if the system uptime is suspiciously low (e.g., less than 10 minutes)."""
    try:
        output = subprocess.run(['net', 'stats', 'srv'], capture_output=True, text=True, timeout=5)
        if output.returncode == 0:
            for line in output.stdout.splitlines():
                if "Statistics since" in line:
                    # Extract the uptime timestamp and calculate the difference
                    uptime_str = line.split("since")[1].strip()
                    uptime_time = time.strptime(uptime_str, "%m/%d/%Y %I:%M:%S %p")
                    uptime_seconds = time.mktime(time.localtime()) - time.mktime(uptime_time)
                    return uptime_seconds < 600  # Less than 10 minutes
    except Exception:
        pass
    return False

def check_ram_size() -> bool:
    """Check if the system has a small amount of RAM (e.g., less than 2GB)."""
    try:
        output = subprocess.run(['wmic', 'ComputerSystem', 'get', 'TotalPhysicalMemory'], capture_output=True, text=True, timeout=5)
        if output.returncode == 0:
            lines = output.stdout.splitlines()
            if len(lines) > 1:
                total_memory = int(lines[1].strip())
                return total_memory < 2 * 1024 * 1024 * 1024  # Less than 2GB
    except Exception:
        pass
    return False

def check_vm_artifacts() -> bool:
    """Check for virtual machine artifacts in the registry."""
    vm_indicators = [
        r"SYSTEM\CurrentControlSet\Services\VBoxGuest",
        r"SYSTEM\CurrentControlSet\Services\vmicheartbeat",
        r"SOFTWARE\VMware, Inc.\VMware Tools"
    ]
    try:
        for indicator in vm_indicators:
            try:
                with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, indicator) as key:
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
        sandbox_detected = check_uptime() or check_ram_size() or check_vm_artifacts()
        status = "sandbox_detected" if sandbox_detected else "environment_safe"
        result = {
            "uptime_check": check_uptime(),
            "ram_check": check_ram_size(),
            "vm_artifacts_check": check_vm_artifacts()
        }
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