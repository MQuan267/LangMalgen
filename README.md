# LangMal
# MalGEN (SAFE) — Hướng dẫn dùng & chuyển giữa **OpenAI** / **Gemini**

> Bản này là **mô phỏng an toàn** phục vụ kiểm thử phòng thủ. Toàn bộ agent đều **không** thực thi hành vi nguy hiểm: **không syscall thật**, **không egress mạng**, chỉ dùng **mock providers** và ghi local.

---

## 1) Yêu cầu hệ thống

- Ubuntu / Debian-based
- Python 3.10+ (khuyến nghị 3.12)
- (Tùy chọn để build executable) `pyinstaller`

```bash
sudo apt update
sudo apt install python3-pip -y
sudo ln -s /usr/bin/pip3 /usr/bin/pip 
```
## 2) Cài đặt

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -U pip
pip install -r requirements.txt
```

Nếu dùng OpenAI: pip install -U openai
Nếu dùng Gemini: pip install -U google-genai (đã nằm trong requirements)

## 3) Tạo file .env

Tạo ~/malgen/.env:

# Chọn stack mặc định khi không truyền --agent-stack (openai | gemini)
AGENT_STACK=openai

# OpenAI
OPENAI_API_KEY=sk-xxx
OPENAI_MODEL=gpt-4o-mini

# Gemini (Google AI)
GOOGLE_API_KEY=AIza-xxx
GEMINI_MODEL=gemini-1.5-flash-latest

## 4) Cấu trúc thư mục
```arduino
malgen/
├─ src/
│  ├─ agents/
│  │  ├─ planner_openai.py
│  │  ├─ developer_openai.py
│  │  ├─ integrator_openai.py
│  │  ├─ builder_openai.py
│  │  ├─ planner_gemini.py
│  │  ├─ developer_gemini.py
│  │  └─ integrator_gemini.py
│  ├─ adapters/           # mock providers & local sink
│  └─ runtime/
│     ├─ app.py           # entrypoint
│     ├─ graph.py         # chọn nodes theo AGENT_STACK
│     ├─ nodes_openai.py  # flow dùng OpenAI agents
│     └─ nodes_gemini.py  # flow dùng Gemini agents
├─ artifacts/
│  ├─ plans/              # plan JSON của planner/integrator (đặt tên có prefix stack)
│  ├─ modules/            # module .py do developer sinh
│  ├─ latest_bundle/      # pipeline.py + manifest.json
│  └─ dist/               # executable (nếu build)
└─ logs/
   └─ pipeline.jsonl      # nhật ký các bước
```
 
 
## 5) Chạy pipeline
# 5.1 Chạy với OpenAI
```bash
cd ~/malgen
source .venv/bin/activate
set -a; . ./.env; set +a

python -m src.runtime.app \
  --agent-stack openai \
  --intent "Collect OS and user information and save locally (SAFE MOCK)"
```
  
# 5.2 Chạy với Gemini
```bash
cd ~/malgen
source .venv/bin/activate
set -a; . ./.env; set +a

python -m src.runtime.app \
  --agent-stack gemini \
  --intent "Collect OS and user information and save locally (SAFE MOCK)"
```
>>>>>>> 8e6eac6 (Initial commit: malgen (SAFE) with OpenAI/Gemini stacks)
