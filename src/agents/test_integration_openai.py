from integrator_openai2 import IntegrationAgentOpenAI, PolicyFlags
from datetime import datetime, timezone

# 👇 Dán nguyên phần dev_specs từ output Developer Agent
dev_specs = [
    {
      "subtask_id": "1",
      "spec": {
        "refined_desc": "Collect user account information from the system using appropriate commands or APIs such as 'net user' on Windows or 'getent passwd' on Linux.",
        "malware_category": "reconnaissance",
        "stealth_requirements": "medium",
        "persistence_mechanism": "",
        "target_data": [
          "user account information",
          "user privileges",
          "group memberships"
        ],
        "evasion_techniques": [],
        "execution_triggers": "user_action",
        "lateral_movement": False,
        "communication_protocol": "",
        "encryption_method": "",
        "cleanup_required": False
      }
    },
    {
      "subtask_id": "2",
      "spec": {
        "refined_desc": "Collect OS Information - Retrieve operating system details using system commands or APIs.",
        "malware_category": "reconnaissance",
        "stealth_requirements": "low",
        "persistence_mechanism": "none",
        "target_data": [
          "OS version",
          "Kernel version",
          "Architecture",
          "Hostname",
          "User information"
        ],
        "evasion_techniques": [],
        "execution_triggers": "user_action",
        "lateral_movement": False,
        "communication_protocol": "",
        "encryption_method": "",
        "cleanup_required": False
      }
    },
    {
      "subtask_id": "3",
      "spec": {
        "refined_desc": "Collect currently running processes using system commands or APIs.",
        "malware_category": "reconnaissance",
        "stealth_requirements": "low",
        "persistence_mechanism": "",
        "target_data": [
          "process_list"
        ],
        "evasion_techniques": [],
        "execution_triggers": "user_action",
        "lateral_movement": False,
        "communication_protocol": "",
        "encryption_method": "",
        "cleanup_required": False
      }
    },
    {
      "subtask_id": "4",
      "spec": {
        "refined_desc": "Prepare collected data for exfiltration by formatting it into a structured format suitable for transmission.",
        "malware_category": "exfiltration",
        "stealth_requirements": "medium",
        "persistence_mechanism": "none",
        "target_data": [
          "collected_data"
        ],
        "evasion_techniques": [
          "encryption",
          "compression"
        ],
        "execution_triggers": "user_action",
        "lateral_movement": True,
        "communication_protocol": "https",
        "encryption_method": "aes",
        "cleanup_required": True
      }
    },
    {
      "subtask_id": "5",
      "spec": {
        "refined_desc": "Exfiltrate data to a remote HTTPS server securely",
        "malware_category": "exfiltration",
        "stealth_requirements": "medium",
        "persistence_mechanism": "service",
        "target_data": [
          "/path/to/data/file1",
          "/path/to/data/file2"
        ],
        "evasion_techniques": [
          "encryption",
          "obfuscation"
        ],
        "execution_triggers": "user_action",
        "lateral_movement": True,
        "communication_protocol": "https",
        "encryption_method": "aes",
        "cleanup_required": True
      }
    }
]

# 👇 Dán nguyên phần modules từ output Developer Agent
modules = [
  {
      "subtask_id": "1",
      "name": "Collect User Accounts",
      "path": "artifacts/modules/openai_developer_01_20251113_125207_436407_1_collect_user_accounts.py",
      "malware_category": "reconnaissance",
      "stealth_level": "medium"
    },
    {
      "subtask_id": "2",
      "name": "Collect OS Information",
      "path": "artifacts/modules/openai_developer_02_20251113_125318_464691_2_collect_os_information.py",
      "malware_category": "reconnaissance",
      "stealth_level": "low"
    },
    {
      "subtask_id": "3",
      "name": "Collect Running Processes",
      "path": "artifacts/modules/openai_developer_03_20251113_125433_053402_3_collect_running_processes.py",
      "malware_category": "reconnaissance",
      "stealth_level": "low"
    },
    {
      "subtask_id": "4",
      "name": "Prepare Data for Exfiltration",
      "path": "artifacts/modules/openai_developer_04_20251113_125555_683059_4_prepare_data_for_exfiltration.py",
      "malware_category": "exfiltration",
      "stealth_level": "medium"
    },
    {
      "subtask_id": "5",
      "name": "Exfiltrate Data",
      "path": "artifacts/modules/openai_developer_05_20251113_125655_367011_5_exfiltrate_data.py",
      "malware_category": "exfiltration",
      "stealth_level": "medium"
    }
]

def main():
    run_id = "dev_run_001"

    # 🔥 Kích hoạt chế độ dùng LLM để gộp code thật
    integrator = IntegrationAgentOpenAI(
        policy=PolicyFlags(),
        stack_name="openai",
        use_llm_merge=True
    )

    print("[+] Starting Integration with LLM merge...\n")
    result = integrator.integrate(run_id=run_id, dev_specs=dev_specs, modules=modules)

    print("\n✅ Pipeline path:", result["pipeline_path"])
    print("📄 Integration Plan:", result["plan_path"])

    # 👉 Nếu muốn chạy thử code đã gộp
    # print("\n▶️ Running the integrated pipeline:\n")
    # os.system(f"python3 {result['pipeline_path']}")

if __name__ == "__main__":
    main()
