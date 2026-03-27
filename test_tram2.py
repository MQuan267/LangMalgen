import json
from collections import Counter

with open("tram2.jsonl") as f:
    data = [json.loads(line) for line in f]

counter = Counter(d["technique_id"] for d in data)

print(f"Total examples: {len(data)}")
print(f"Unique techniques: {len(counter)}")
print("\nTop 20 techniques:")
for tid, count in counter.most_common(20):
    print(f"  {tid}: {count}")

print("\nBottom 10 techniques:")
for tid, count in counter.most_common()[:-11:-1]:
    print(f"  {tid}: {count}")