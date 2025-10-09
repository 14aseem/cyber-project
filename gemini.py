import google.generativeai as genai
import json


GOOGLE_API_KEY = 'xxx' 


phishing_email = """
Subject: Urgent Action Required: Your Account is Suspended!

Dear Valued Customer,

We have detected unusual activity on your account. For your security, we have temporarily suspended your account. 
To restore access, you must verify your identity immediately by clicking here: http://yourbank.security-update.com/login

Please complete this verification within 2 hours to avoid permanent account closure.

Sincerely,
Your Bank Security Team
"""

# A legitimate marketing email
safe_email = """
Subject: Your Weekly Tech Roundup!

Hi there,

Hope you're having a great week! 

Here's your weekly roundup of the latest news in the tech world. This week, we cover the new advancements in AI and our latest blog post on sustainable tech.
Read more on our official blog: https://www.reputable-tech-journal.com/blog/latest-updates

Cheers,
The Tech Journal Team
"""


# --- THE CORE LOGIC ---

# Configure the generative AI model
genai.configure(api_key=GOOGLE_API_KEY)
model = genai.GenerativeModel('gemini-1.0-pro')

def analyze_email(email_content):
    """
    Sends the email content to the LLM with a specialized prompt for analysis.
    """
    
    # This is the prompt that tells the LLM how to behave.
    # It's the most important part of the project!
    prompt = f"""
    You are a cybersecurity analyst specializing in phishing detection. 
    Analyze the following email content and determine if it is a phishing attempt.
    
    Provide your analysis in a JSON format with the following keys:
    - "verdict": Your final decision, either "Safe" or "Phishing".
    - "confidence_score": A number between 0.0 and 1.0 indicating your confidence in the verdict.
    - "reasoning": A brief explanation of why you made this decision, pointing out specific red flags or signs of legitimacy.

    Here is the email content to analyze:
    ---
    {email_content}
    ---
    """
    
    try:
        # Ask the LLM to generate the analysis
        response = model.generate_content(prompt)
        
        # Clean up the response to extract just the JSON
        json_response = response.text.strip().replace('```json', '').replace('```', '').strip()
        
        return json.loads(json_response)
        
    except Exception as e:
        print(f"An error occurred: {e}")
        return None


# --- RUN THE ANALYSIS ---

print("Analyzing Phishing Email...")
phishing_analysis = analyze_email(phishing_email)
if phishing_analysis:
    print(f"  Verdict: {phishing_analysis['verdict']}")
    print(f"  Confidence: {phishing_analysis['confidence_score']}")
    print(f"  Reasoning: {phishing_analysis['reasoning']}\n")

print("Analyzing Safe Email...")
safe_analysis = analyze_email(safe_email)
if safe_analysis:
    print(f"  Verdict: {safe_analysis['verdict']}")
    print(f"  Confidence: {safe_analysis['confidence_score']}")
    print(f"  Reasoning: {safe_analysis['reasoning']}")