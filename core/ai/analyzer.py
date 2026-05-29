from openai import OpenAI

# Primary client — NVIDIA
nvidia_client = OpenAI(
    api_key=os.environ["NVIDIA_API_KEY"],
    base_url="https://integrate.api.nvidia.com/v1",
)

# Fallback client — OpenRouter
openrouter_client = OpenAI(
    api_key=os.environ["OPENROUTER_API_KEY"],
    base_url="https://openrouter.ai/api/v1",
    default_headers={"HTTP-Referer": "https://vyala.ai"},
)

# Both use the exact same call shape:
response = nvidia_client.chat.completions.create(
    model="deepseek-ai/deepseek-v4-pro",
    messages=[
        {"role": "system", "content": VYALA_SYSTEM_PROMPT},
        {"role": "user",   "content": user_prompt},
    ],
    temperature=0.1,   # Low temp = deterministic JSON, no hallucinated fields
    max_tokens=512,    # The JSON response is tiny; cap it hard
)