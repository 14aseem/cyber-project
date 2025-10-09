import google.generativeai as genai
import os
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Get the API key from the environment
GOOGLE_API_KEY = os.getenv("xxxx")

if not GOOGLE_API_KEY:
    print("Error: GOOGLE_API_KEY not found. Please set it as an environment variable.")
else:
    try:
        genai.configure(api_key=GOOGLE_API_KEY)
        
        print("Available models that support 'generateContent':")
        for model in genai.list_models():
            if 'generateContent' in model.supported_generation_methods:
                print(f"- {model.name}")

    except Exception as e:
        print(f"An error occurred while trying to list models: {e}")