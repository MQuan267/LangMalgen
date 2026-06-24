#!/usr/bin/env python3
"""Merged Modules for Defensive Malware Research Framework"""

import sys
import json
import time
import subprocess
from typing import Dict, Any

def task_T1(input_data: Dict[str, Any] = None) -> Dict[str, Any]:
    start = time.time()
    input_data = input_data or {}
    try:
        # Use 'netstat' command to get active network connections and listening ports
        result = {'connections': None, 'listening_ports': None}
        
        # Run the netstat command to get active connections
        netstat_output = subprocess.run(['netstat', '-an'], capture_output=True, text=True, timeout=10)
        if netstat_output.returncode == 0:
            connections = []
            listening_ports = []
            for line in netstat_output.stdout.splitlines():
                if 'LISTENING' in line:
                    listening_ports.append(line.strip())
                else:
                    connections.append(line.strip())
            result['connections'] = connections
            result['listening_ports'] = listening_ports

        return {'success': True, 'data': result,
                'metadata': {'task_id': 'T1', 'execution_time': time.time()-start}}
    except Exception as e:
        return {'success': False, 'data': {'connections': None, 'listening_ports': None},
                'error': f'{type(e).__name__}: {e}',
                'metadata': {'task_id': 'T1', 'execution_time': time.time()-start}}

def task_T2(input_data: Dict[str, Any] = None) -> Dict[str, Any]:
    start = time.time()
    input_data = input_data or {}
    open_ports = []
    hosts = []
    
    try:
        # Use PowerShell to scan the local subnet for open ports 445 and 3389
        command = (
            "powershell -Command \""
            "$subnet = (Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.IPAddress -ne '127.0.0.1' }).IPAddress -replace '\\.\\d+$', '.0';"
            "1..254 | ForEach-Object {"
            "  $ip = $subnet + $_;"
            "  $ports = @();"
            "  if (Test-NetConnection -ComputerName $ip -Port 445 -InformationLevel Quiet) { $ports += 445 };"
            "  if (Test-NetConnection -ComputerName $ip -Port 3389 -InformationLevel Quiet) { $ports += 3389 };"
            "  if ($ports.Count -gt 0) {"
            "    [PSCustomObject]@{ IPAddress = $ip; OpenPorts = $ports }"
            "  }"
            "} | ConvertTo-Json\""
        )
        
        result = subprocess.run(command, capture_output=True, text=True, shell=True, timeout=60)
        
        if result.returncode == 0:
            scan_results = json.loads(result.stdout)
            if isinstance(scan_results, list):
                for entry in scan_results:
                    hosts.append(entry['IPAddress'])
                    open_ports.extend(entry['OpenPorts'])
        
        return {'success': True, 'data': {'open_ports': open_ports, 'hosts': hosts},
                'metadata': {'task_id': 'T2', 'execution_time': time.time()-start}}
    except Exception as e:
        return {'success': False, 'data': {'open_ports': None, 'hosts': None},
                'error': f'{type(e).__name__}: {e}',
                'metadata': {'task_id': 'T2', 'execution_time': time.time()-start}}

def task_T3(input_data: Dict[str, Any] = None) -> Dict[str, Any]:
    start = time.time()
    input_data = input_data or {}
    try:
        # Execute the command to get ARP table entries
        result = subprocess.run(['arp', '-a'], capture_output=True, text=True, timeout=10)
        arp_entries = result.stdout.splitlines()

        # Prepare the result data
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