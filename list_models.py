import os
from dotenv import load_dotenv
from google import genai

load_dotenv()
client = genai.Client(api_key=os.environ["GOOGLE_API_KEY"])
models = client.models.list()
for m in models:
    # m là object; cố gắng in các thuộc tính hữu ích
    name = getattr(m, "name", "")
    supp = getattr(m, "supported_generation_methods", [])
    print(f"{name}\t{supp}")

