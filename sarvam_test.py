"""
Sarvam AI — one working chat completion call.
API key is read from the environment via .env — never hardcoded.
"""
import os
from dotenv import load_dotenv
from sarvamai import SarvamAI

load_dotenv()

api_key = os.getenv("SARVAM_API_KEY")
if not api_key:
    raise RuntimeError("SARVAM_API_KEY is not set. Add it to your .env file.")

client = SarvamAI(api_subscription_key=api_key)

response = client.chat.completions(
    model="sarvam-105b",
    messages=[
        {"role": "user", "content": "What is the capital of India? Reply in one sentence."}
    ],
)

print(response.choices[0].message.content)
