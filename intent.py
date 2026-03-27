"""
create_intents.py (FINAL VERSION)

Input:
- test_split.json

Output:
- intent_30.json

Logic:
doc_title + full labels -> GPT -> concise, behavior-specific intent

Run:
python create_intents.py
"""

from __future__ import annotations

import json
from pathlib import Path

from dotenv import load_dotenv
from openai import OpenAI

load_dotenv(override=True)

TEST_SPLIT = "test_split.json"
OUTPUT_FILE = "intent_30.json"
MODEL = "gpt-4o"


def clean_intent(intent: str) -> str:
    intent = (intent or "").strip().strip('"').strip("'")
    lowered = intent.lower()

    bad_exact = {
        "steal sensitive data",
        "perform malicious actions",
        "maintain persistence",
        "execute malicious actions",
        "perform malicious activity",
        "conduct malicious activity",
    }

    if lowered in bad_exact:
        return ""

    bad_contains = [
        "perform malicious",
        "malicious activity",
        "malicious actions",
        "various malicious",
        "multiple malicious",
    ]

    for phrase in bad_contains:
        if phrase in lowered:
            return ""

    return intent


def fallback_intent_from_labels(labels: list[str]) -> str:
    label_set = set(labels)

    if "T1003.001" in label_set and "T1041" in label_set:
        return "dump credentials from LSASS and exfiltrate data over C2"
    if "T1056.001" in label_set and "T1113" in label_set:
        return "capture keystrokes and screenshots to steal sensitive information"
    if "T1486" in label_set and "T1562.001" in label_set:
        return "encrypt files and disable security tools to evade detection"
    if "T1071.001" in label_set and "T1041" in label_set:
        return "communicate over HTTP C2 and exfiltrate collected data"
    if "T1055" in label_set and "T1574.002" in label_set:
        return "inject code into processes and hijack DLL loading for execution"
    if "T1021.001" in label_set and "T1570" in label_set:
        return "move laterally via remote access and transfer tools across hosts"
    if "T1105" in label_set and "T1140" in label_set:
        return "download payloads and decode them at runtime for execution"
    if "T1190" in label_set and "T1210" in label_set:
        return "exploit exposed services to gain access and move laterally"
    if "T1053.005" in label_set and "T1547.001" in label_set:
        return "establish persistence through scheduled tasks and registry autorun"

    if labels:
        return "execute payloads and achieve the main intrusion objective"
    return "perform malicious behavior on the victim system"


def write_intent_with_gpt(doc_title: str, all_labels: list[str], client: OpenAI) -> str:
    prompt = (
        "You are a cybersecurity expert analyzing malware behavior.\n\n"

        f"Report title: {doc_title}\n"
        f"ATT&CK techniques observed: {all_labels}\n\n"

        "Task:\n"
        "Write ONE concise intent sentence describing what the malware actually DOES.\n\n"

        "STRICT RULES:\n"
        "- Focus on SPECIFIC attacker behaviors, not generic goals\n"
        "- MUST include HOW the action is performed when possible\n"
        "- Avoid vague phrases like 'steal sensitive data' by itself\n"
        "- Prefer concrete behaviors such as credential dumping, keylogging, HTTP C2, DLL injection, persistence, lateral movement, or file encryption\n"
        "- Reflect the main attack objective\n"
        "- Length: 12 to 30 words\n"
        "- Do NOT mention ATT&CK IDs\n"
        "- Do NOT say 'malware', 'attacker', or 'threat actor'\n\n"

        "GOOD examples:\n"
        "- dump credentials from LSASS and exfiltrate data over HTTP C2 channel\n"
        "- encrypt files and disable security tools to evade detection\n"
        "- capture keystrokes and screenshots then exfiltrate stolen data via HTTPS\n"
        "- inject code into legitimate processes and communicate with C2 over HTTP\n\n"

        "BAD examples:\n"
        "- steal sensitive data\n"
        "- perform malicious actions\n"
        "- maintain persistence\n\n"

        "Output ONLY the sentence, no explanation."
    )

    response = client.chat.completions.create(
        model=MODEL,
        messages=[{"role": "user", "content": prompt}],
        temperature=0.2,
        max_tokens=80,
    )

    content = response.choices[0].message.content or ""
    return content.strip()


def main() -> None:
    client = OpenAI()

    print("=" * 60)
    print(f"Model:  {MODEL}")
    print(f"Input:  {TEST_SPLIT}")
    print(f"Output: {OUTPUT_FILE}")
    print("=" * 60)

    data = json.loads(Path(TEST_SPLIT).read_text(encoding="utf-8"))
    print(f"Loaded {len(data)} reports")

    results = []

    for i, doc in enumerate(data, start=1):
        doc_title = doc.get("doc_title", f"Report {i}")
        labels_per_sentence = doc.get("label", [])

        full_labels = set()
        for sent_labels in labels_per_sentence:
            if isinstance(sent_labels, list):
                full_labels.update(sent_labels)

        full_labels = sorted(full_labels)

        if not full_labels:
            print(f"[{i}] Skip: no labels")
            continue

        print(f"\n[{i}] {doc_title[:80]}")
        print(f"     Labels: {len(full_labels)}")

        intent = ""
        try:
            raw_intent = write_intent_with_gpt(
                doc_title=doc_title,
                all_labels=full_labels,
                client=client,
            )
            intent = clean_intent(raw_intent)

            if not intent:
                intent = fallback_intent_from_labels(full_labels)

            print(f"     Intent: {intent}")

        except Exception as e:
            print(f"     ERROR: {e}")
            intent = fallback_intent_from_labels(full_labels)
            print(f"     Fallback intent: {intent}")

        results.append({
            "doc_title": doc_title,
            "intent": intent,
            "labels": full_labels,
        })

    Path(OUTPUT_FILE).write_text(
        json.dumps(results, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )

    print("\n" + "=" * 60)
    print(f"Done -> {OUTPUT_FILE}")
    print("=" * 60)


if __name__ == "__main__":
    main()