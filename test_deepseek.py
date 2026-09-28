from openai import OpenAI
import os
from dotenv import load_dotenv

load_dotenv()

client = OpenAI(
    api_key  = os.getenv("OPENAI_API_KEY"),
    base_url = os.getenv("OPENAI_BASE_URL", "https://api.deepseek.com"),
)

resp = client.chat.completions.create(
    model    = os.getenv("OPENAI_MODEL", "deepseek-v4-pro"),
    messages = [{"role": "user", "content": "Say hello in one word."}],
    max_tokens = 10,
)

print(resp.choices[0].message.content)
print("Model  :", resp.model)
print("Tokens :", resp.usage)