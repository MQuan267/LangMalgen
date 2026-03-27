# Mock providers — không gọi OS thực
from typing import Dict

def MockHostInfo() -> Dict:
    return {"platform":"linux","arch":"x86_64","ram_mb":4096}

def MockUserInfo() -> Dict:
    return {"username":"student","uid":1000}
    
def MockProcessList():
    # danh sách quy ước, vô hại
    return [
        {"pid": 101, "name": "init", "user": "root"},
        {"pid": 202, "name": "demo-app", "user": "student"},
    ]

def MockNetConfig():
    return {
        "iface": "eth0",
        "ip": "192.168.1.10",
        "gateway": "192.168.1.1",
        "dns": ["8.8.8.8", "1.1.1.1"]
    }
