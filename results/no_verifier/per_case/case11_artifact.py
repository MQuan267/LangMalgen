#!/usr/bin/env python3
"""Detect sandbox environments by checking for low uptime, small RAM size, and virtual machine artifacts (VMware/VirtualBox)."""
import sys
import json
import time
import subprocess
from typing import Dict, Any

def check_system_uptime() -> bool:
    """Check if the system uptime is suspiciously low, indicating a potential sandbox."""
    try:
        # Using 'net stats workstation' to get uptime on Windows
        result = subprocess.run(['net', 'stats', 'workstation'], capture_output=True, text=True, timeout=5)
        if result.returncode == 0:
            output = result.stdout
            # Look for the line containing "Statistics since" to determine uptime
            for line in output.splitlines():
                if "Statistics since" in line:
                    # Extract the date and time part
                    uptime_str = line.split("Statistics since")[1].strip()
                    # Convert to a timestamp
                    uptime_time = time.mktime(time.strptime(uptime_str, "%m/%d/%Y %I:%M:%S %p"))
                    current_time = time.time()
                    # Check if uptime is less than 10 minutes (600 seconds)
                    if (current_time - uptime_time) < 600:
                        return True
        return False
    except Exception:
        return False

def check_ram_size() -> bool:
    """Check if the RAM size is suspiciously small, indicating a potential sandbox."""
    try:
        # Using 'wmic' to get total physical memory
        result = subprocess.run(['wmic', 'ComputerSystem', 'get', 'TotalPhysicalMemory'], capture_output=True, text=True, timeout=5)
        if result.returncode == 0:
            output = result.stdout
            # Extract the memory size in bytes
            for line in output.splitlines():
                if line.strip().isdigit():
                    total_memory = int(line.strip())
                    # Check if RAM is less than 2GB
                    if total_memory < 2 * 1024 * 1024 * 1024:
                        return True
        return False
    except Exception:
        return False

def check_virtual_machine_artifacts() -> bool:
    """Check for virtual machine artifacts indicating a potential sandbox."""
    try:
        # Using 'wmic' to check for virtual machine artifacts
        result = subprocess.run(['wmic', 'computersystem', 'get', 'model'], capture_output=True, text=True, timeout=5)
        if result.returncode == 0:
            output = result.stdout.lower()
            # Check for common VM indicators
            if "vmware" in output or "virtualbox" in output:
                return True
        return False
    except Exception:
        return False

def task_T1(input_data: Dict[str, Any] = None) -> Dict[str, Any]:
    start = time.time()
    input_data = input_data or {}
    try:
        sandbox_detected = (
            check_system_uptime() or
            check_ram_size() or
            check_virtual_machine_artifacts()
        )

        status = "sandbox_detected" if sandbox_detected else "environment_clean"
        result = {
            "status": status,
            "details": {
                "uptime_check": check_system_uptime(),
                "ram_check": check_ram_size(),
                "vm_artifacts_check": check_virtual_machine_artifacts()
            }
        }

        return {'success': True, 'data': {'status': status, 'result': json.dumps(result)},
                'metadata': {'task_id': 'T1', 'execution_time': time.time() - start}}
    except Exception as e:
        return {'success': False, 'error': f'{type(e).__name__}: {e}',
                'metadata': {'task_id': 'T1', 'execution_time': time.time() - start}}

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