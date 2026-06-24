#!/usr/bin/env python3
"""Detect sandbox environments by checking for low uptime, small RAM size, and virtual machine artifacts (VMware/VirtualBox)"""
import sys
import json
import time
import subprocess
from typing import Dict, Any

def check_system_uptime() -> bool:
    """Check if the system uptime is less than a threshold (e.g., 10 minutes)"""
    try:
        result = subprocess.run(
            ['net', 'stats', 'srv'],
            capture_output=True,
            text=True,
            timeout=5
        )
        if result.returncode == 0:
            output = result.stdout
            for line in output.splitlines():
                if "Statistics since" in line:
                    uptime_str = line.split("Statistics since")[1].strip()
                    uptime_time = time.strptime(uptime_str, "%m/%d/%Y %I:%M:%S %p")
                    uptime_seconds = time.mktime(time.localtime()) - time.mktime(uptime_time)
                    return uptime_seconds < 600  # 10 minutes
    except Exception:
        return False
    return False

def check_ram_size() -> bool:
    """Check if the RAM size is less than a threshold (e.g., 2GB)"""
    try:
        result = subprocess.run(
            ['wmic', 'ComputerSystem', 'get', 'TotalPhysicalMemory'],
            capture_output=True,
            text=True,
            timeout=5
        )
        if result.returncode == 0:
            output = result.stdout
            for line in output.splitlines():
                if line.strip().isdigit():
                    ram_size_bytes = int(line.strip())
                    return ram_size_bytes < 2 * 1024 * 1024 * 1024  # 2GB
    except Exception:
        return False
    return False

def check_virtual_machine_artifacts() -> bool:
    """Check for virtual machine artifacts (VMware/VirtualBox)"""
    try:
        result = subprocess.run(
            ['wmic', 'computersystem', 'get', 'model'],
            capture_output=True,
            text=True,
            timeout=5
        )
        if result.returncode == 0:
            output = result.stdout.lower()
            return 'vmware' in output or 'virtualbox' in output
    except Exception:
        return False
    return False

def task_T1(input_data: Dict[str, Any] = None) -> Dict[str, Any]:
    start = time.time()
    input_data = input_data or {}
    try:
        is_sandbox = (
            check_system_uptime() or
            check_ram_size() or
            check_virtual_machine_artifacts()
        )
        status = "sandbox_detected" if is_sandbox else "environment_safe"
        result = {
            "status": status,
            "result": json.dumps({
                "uptime_check": check_system_uptime(),
                "ram_check": check_ram_size(),
                "vm_check": check_virtual_machine_artifacts()
            })
        }
        return {'success': True, 'data': result,
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