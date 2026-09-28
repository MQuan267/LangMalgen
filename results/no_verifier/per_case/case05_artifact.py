#!/usr/bin/env python3
"""Defensive Malware Research Framework"""

import sys
import json
import time
import subprocess
from typing import Dict, Any, List

def task_T1(input_data: Dict[str, Any] = None) -> Dict[str, Any]:
    start = time.time()
    input_data = input_data or {}
    try:
        # Use netstat to get active connections and listening ports
        result = {'connections': [], 'listening_ports': []}
        
        # Run netstat command to get network connections
        netstat_output = subprocess.run(
            ['netstat', '-an'],
            capture_output=True,
            text=True,
            timeout=10
        ).stdout
        
        # Process the netstat output
        for line in netstat_output.splitlines():
            if 'LISTENING' in line:
                result['listening_ports'].append(line.strip())
            elif 'ESTABLISHED' in line:
                result['connections'].append(line.strip())
        
        return {'success': True, 'data': result,
                'metadata': {'task_id': 'T1', 'execution_time': time.time()-start}}
    except Exception as e:
        # Return partial results if possible
        return {'success': False, 'data': {'connections': None, 'listening_ports': None},
                'error': f'{type(e).__name__}: {e}',
                'metadata': {'task_id': 'T1', 'execution_time': time.time()-start}}

def task_T2(input_data: Dict[str, Any] = None) -> Dict[str, Any]:
    start = time.time()
    input_data = input_data or {}
    open_ports = []
    hosts = []
    
    try:
        # Define the ports to scan
        ports_to_scan = [445, 3389]
        
        # Use 'arp -a' to get the list of local network hosts
        arp_result = subprocess.run(['arp', '-a'], capture_output=True, text=True, timeout=10)
        arp_output = arp_result.stdout.splitlines()
        
        # Extract IP addresses from the arp output
        for line in arp_output:
            if 'dynamic' in line or 'static' in line:
                parts = line.split()
                if len(parts) > 1:
                    hosts.append(parts[0])
        
        # Scan each host for the specified ports
        for host in hosts:
            for port in ports_to_scan:
                # Use 'Test-NetConnection' PowerShell command to check port status
                command = f"powershell -Command Test-NetConnection -ComputerName {host} -Port {port}"
                result = subprocess.run(command, capture_output=True, text=True, shell=True, timeout=5)
                if 'TcpTestSucceeded : True' in result.stdout:
                    open_ports.append({'host': host, 'port': port})
        
        result = {'open_ports': open_ports, 'hosts': hosts}
        return {'success': True, 'data': result,
                'metadata': {'task_id': 'T2', 'execution_time': time.time()-start}}
    except Exception as e:
        # Return partial results on failure
        result = {'open_ports': open_ports or None, 'hosts': hosts or None}
        return {'success': False, 'data': result, 'error': f'{type(e).__name__}: {e}',
                'metadata': {'task_id': 'T2', 'execution_time': time.time()-start}}

def task_T3(input_data: Dict[str, Any] = None) -> Dict[str, Any]:
    start = time.time()
    input_data = input_data or {}
    try:
        # Execute the command to gather ARP table entries
        result = subprocess.run(['arp', '-a'], capture_output=True, text=True, timeout=10)
        arp_entries = result.stdout.splitlines() if result.returncode == 0 else None
        
        # Prepare the result dictionary
        result_data = {'arp_entries': arp_entries}
        
        return {'success': True, 'data': result_data,
                'metadata': {'task_id': 'T3', 'execution_time': time.time()-start}}
    except Exception as e:
        # Return partial result with fallback value on failure
        return {'success': False, 'data': {'arp_entries': None},
                'error': f'{type(e).__name__}: {e}',
                'metadata': {'task_id': 'T3', 'execution_time': time.time()-start}}

def main() -> dict:
    """Auto-generated orchestrator — do not edit by hand."""
    outputs: dict = {}
    results: dict = {}
    failed:  list = []
    
    # ── T1: Identify Active Network Connections [discovery] ──
    try:
        r = task_T1(None)
        results['T1'] = r
        if r.get('success'):
            outputs['T1'] = r.get('data', {})
            print(f'[+] T1 (Identify Active Network Connections): OK')
        else:
            err = r.get('error', 'unknown')
            print(f'[-] T1 (Identify Active Network Connections): FAILED — {err}')
            failed.append('T1')
    except Exception as e:
        print(f'[!] T1 crashed: {e}')
        failed.append('T1')
        results['T1'] = {'success': False, 'error': str(e)}
    
    # ── T2: Scan Local Subnet for Open Ports [discovery] ──
    try:
        r = task_T2(None)
        results['T2'] = r
        if r.get('success'):
            outputs['T2'] = r.get('data', {})
            print(f'[+] T2 (Scan Local Subnet for Open Ports): OK')
        else:
            err = r.get('error', 'unknown')
            print(f'[-] T2 (Scan Local Subnet for Open Ports): FAILED — {err}')
            failed.append('T2')
    except Exception as e:
        print(f'[!] T2 crashed: {e}')
        failed.append('T2')
        results['T2'] = {'success': False, 'error': str(e)}
    
    # ── T3: Gather ARP Table Entries [discovery] ──
    try:
        r = task_T3(None)
        results['T3'] = r
        if r.get('success'):
            outputs['T3'] = r.get('data', {})
            print(f'[+] T3 (Gather ARP Table Entries): OK')
        else:
            err = r.get('error', 'unknown')
            print(f'[-] T3 (Gather ARP Table Entries): FAILED — {err}')
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