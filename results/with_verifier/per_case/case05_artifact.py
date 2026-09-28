#!/usr/bin/env python3
import sys
import json
import time
import subprocess
import re
from typing import Dict, Any

def task_T1(input_data: Dict[str, Any] = None) -> Dict[str, Any]:
    start = time.time()
    input_data = input_data or {}
    try:
        result = {
            "connections": [],
            "listening_ports": []
        }

        try:
            netstat_output = subprocess.run(
                ['netstat', '-ano'],
                capture_output=True,
                text=True,
                timeout=10
            ).stdout

            for line in netstat_output.splitlines():
                if 'TCP' in line or 'UDP' in line:
                    parts = line.split()
                    if len(parts) >= 5:
                        local_address = parts[1]
                        state = parts[3] if 'TCP' in line else 'LISTENING'
                        pid = parts[4]
                        if state == 'LISTENING':
                            result['listening_ports'].append({
                                'local_address': local_address,
                                'pid': pid
                            })
                        else:
                            result['connections'].append({
                                'local_address': local_address,
                                'foreign_address': parts[2],
                                'state': state,
                                'pid': pid
                            })
        except Exception:
            pass

        return {'success': True, 'data': result,
                'metadata': {'task_id': 'T1', 'execution_time': time.time()-start}}
    except Exception as e:
        return {'success': False, 'error': f'{type(e).__name__}: {e}',
                'metadata': {'task_id': 'T1', 'execution_time': time.time()-start}}

def task_T2(input_data: Dict[str, Any] = None) -> Dict[str, Any]:
    start = time.time()
    input_data = input_data or {}
    open_ports = []
    
    try:
        result = subprocess.run(['ipconfig', '/all'], capture_output=True, text=True, timeout=10)
        ipconfig_output = result.stdout
        
        ip_match = re.search(r'IPv4 Address[. ]*: ([\d.]+)', ipconfig_output)
        subnet_match = re.search(r'Subnet Mask[. ]*: ([\d.]+)', ipconfig_output)
        
        if ip_match and subnet_match:
            local_ip = ip_match.group(1)
            subnet_mask = subnet_match.group(1)
            
            ip_parts = list(map(int, local_ip.split('.')))
            subnet_parts = list(map(int, subnet_mask.split('.')))
            network_address = '.'.join(str(ip_parts[i] & subnet_parts[i]) for i in range(4))
            
            for last_octet in range(1, 255):
                target_ip = f"{network_address}.{last_octet}"
                for port in [445, 3389]:
                    try:
                        result = subprocess.run(['nc', '-zv', target_ip, str(port)], capture_output=True, text=True, timeout=1)
                        if "succeeded" in result.stderr:
                            open_ports.append({'ip': target_ip, 'port': port})
                    except subprocess.TimeoutExpired:
                        continue
        
        return {'success': True, 'data': {'open_ports': open_ports},
                'metadata': {'task_id': 'T2', 'execution_time': time.time()-start}}
    except Exception as e:
        return {'success': False, 'data': {'open_ports': None},
                'error': f'{type(e).__name__}: {e}',
                'metadata': {'task_id': 'T2', 'execution_time': time.time()-start}}

def task_T3(input_data: Dict[str, Any] = None) -> Dict[str, Any]:
    start = time.time()
    input_data = input_data or {}
    try:
        arp_entries = []
        result = subprocess.run(['arp', '-a'], capture_output=True, text=True, timeout=10)
        
        if result.returncode == 0:
            for line in result.stdout.splitlines():
                if 'dynamic' in line or 'static' in line:
                    arp_entries.append(line.strip())
        
        result_data = {'arp_entries': arp_entries}
        
        return {'success': True, 'data': result_data,
                'metadata': {'task_id': 'T3', 'execution_time': time.time()-start}}
    except Exception as e:
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