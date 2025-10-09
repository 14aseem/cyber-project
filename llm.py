import re
from collections import Counter
import pandas as pd
import matplotlib.pyplot as plt
from datetime import datetime
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from reportlab.platypus import Paragraph
from reportlab.lib.styles import getSampleStyleSheet
import json
import os

# --- 1. CONFIGURATION AND INITIAL SETUP ---
log_file = "access.log"
pdf_file = "WebServer_Log_Report.pdf"
csv_file = "parsed_web_log.csv"
chart_files = ["top_ips.png", "top_urls.png", "requests_timeline.png"]

# Ensure a mock log file exists for execution (required if access.log is not present)
if not os.path.exists(log_file):
    print(f"'{log_file}' not found. Creating a mock file...")
    # Mock Apache Common Log Format entries
    mock_log_content = """
192.168.1.1 - - [08/Oct/2025:10:00:00 +0000] "GET /index.html HTTP/1.1" 200 1234 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/93.0.4577.63 Safari/537.36"
192.168.1.2 - user1 [08/Oct/2025:10:00:05 +0000] "POST /api/data HTTP/1.1" 200 45 "-" "curl/7.68.0"
192.168.1.3 - - [08/Oct/2025:11:15:30 +0000] "GET /images/logo.png HTTP/1.1" 200 5678 "http://example.com/index.html" "Mozilla/5.0 (iPhone; CPU iPhone OS 14_8 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.2 Mobile/15E148 Safari/604.1"
192.168.1.1 - - [08/Oct/2025:12:30:00 +0000] "GET /index.html HTTP/1.1" 200 1234 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/93.0.4577.63 Safari/537.36"
192.168.1.4 - - [08/Oct/2025:13:05:45 +0000] "GET /admin/login HTTP/1.1" 404 357 "-" "Nikto/2.1.6"
192.168.1.1 - - [08/Oct/2025:10:45:10 +0000] "GET /contact.html HTTP/1.1" 200 901 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/93.0.4577.63 Safari/537.36"
192.168.1.5 - - [08/Oct/2025:11:00:00 +0000] "GET /index.html HTTP/1.1" 200 1234 "-" "Googlebot/2.1 (+http://www.google.com/bot.html)"
192.168.1.1 - - [08/Oct/2025:14:00:00 +0000] "GET /index.html HTTP/1.1" 200 1234 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/93.0.4577.63 Safari/537.36"
"""
    with open(log_file, "w") as f:
        f.write(mock_log_content.strip())
    print("Mock log file created successfully. Run the script again.")
#     # Exit after creating the mock file to allow the user to see the data
#     # and prevent accidental runs on an empty system.
#     # Commenting out os._exit(0) to allow the script to proceed for demonstration.
#     # os._exit(0)


# --- 2. LOG PARSING ---

pattern = re.compile(
    r'(?P<ip>\d+\.\d+\.\d+\.\d+)\s+-\s+(?P<user>[\w\-]+|-)\s+\[(?P<time>[^\]]+)\]\s+"(?P<method>[A-Z]+)\s(?P<url>\S+)\sHTTP/[0-9.]+"\s(?P<status>\d+)\s(?P<size>\d+)\s"(?P<referrer>[^"]*)"\s"(?P<agent>[^"]*)"'
)

records = []
with open(log_file, "r") as f:
    for line in f:
        m = pattern.search(line)
        if m:
            records.append({
                "IP": m.group('ip'),
                "User": m.group('user'),
                # Parse time, stripping the timezone info (+0000)
                "Time": datetime.strptime(m.group('time').split()[0], "%d/%b/%Y:%H:%M:%S"),
                "Method": m.group('method'),
                "URL": m.group('url'),
                "Status": int(m.group('status')),
                "Bytes": int(m.group('size')),
                "Referrer": m.group('referrer'),
                "UserAgent": m.group('agent')
            })

df = pd.DataFrame(records)
df.to_csv(csv_file, index=False)

print(f"\n✅ Parsed {len(df)} log entries.")
print(f"Data saved to {csv_file}")


# --- 3. DATA ANALYSIS ---

# Key Metrics
ip_counts = df["IP"].value_counts().head(10)
url_counts = df["URL"].value_counts().head(10)
requests_over_time = df.groupby(df["Time"].dt.hour).size().sort_index()

# Bot/Scanner Detection
bot_agents = df["UserAgent"].value_counts()
bot_agents = bot_agents[[ua for ua in bot_agents.index if any(b in ua.lower() for b in ["bot", "curl", "nikto", "spider"])]]


# --- 4. LLM INTEGRATION (MOCK) ---

def generate_summary_with_llm(analysis_data: dict) -> str:
    """
    MOCK function to simulate an LLM generating an executive summary.
    In a real-world script, you would replace this with an API call (e.g., to Google's Gemini API).
    """
    total = analysis_data["Total_Entries"]
    peak_hour = max(analysis_data['Requests_Per_Hour'].items(), key=lambda item: item[1])[0]
    top_ip = list(analysis_data['Top_10_Client_IPs'].keys())[0]
    top_url = list(analysis_data['Top_10_Requested_URLs'].keys())[0]
    bot_count = len(analysis_data['Detected_Bots_Scanners'])
    
    if bot_count > 0:
        bot_summary = f"A total of **{bot_count}** unique User-Agents indicative of bots or scanners were detected. The most frequent of these was **{list(analysis_data['Detected_Bots_Scanners'].keys())[0]}**."
    else:
        bot_summary = "No common bots or scanners were detected based on the current filter list."
        
    return f"""
# Executive Summary

This report covers **{total}** log entries. Traffic analysis shows a peak request time around **{peak_hour}:00** hour, suggesting high user activity during this period. Overall, the server appears stable.

The top client IP, **{top_ip}**, generated the highest volume of requests. This large volume warrants further review to confirm it is a benign process (e.g., an internal monitor) and not a hostile scraping or brute-force attempt. The most frequently accessed resource was **{top_url}**, which indicates the primary landing page or most critical asset.

**Security and Anomalies:**
{bot_summary}
Recommended next steps include implementing rate limits for high-volume IPs and blocking known scanner User-Agents to enhance security posture.
"""

# Prepare data for the (mock) LLM
analysis_results = {
    "Total_Entries": len(df),
    "Top_10_Client_IPs": ip_counts.to_dict(),
    "Top_10_Requested_URLs": url_counts.to_dict(),
    "Requests_Per_Hour": requests_over_time.to_dict(),
    "Detected_Bots_Scanners": bot_agents.to_dict()
}

llm_summary = generate_summary_with_llm(analysis_results)
print("\n--- LLM-Generated Summary ---")
print(llm_summary)


# --- 5. CHART GENERATION ---

plt.figure(figsize=(10,5))
ip_counts.plot(kind="bar")
plt.title("Top Client IPs")
plt.ylabel("Request Count")
plt.xlabel("Client IP")
plt.xticks(rotation=45, ha='right')
plt.tight_layout()
plt.savefig("top_ips.png")
plt.close()

plt.figure(figsize=(10,5))
url_counts.plot(kind="bar", color='orange')
plt.title("Top Requested URLs")
plt.ylabel("Hit Count")
plt.xlabel("URL")
plt.xticks(rotation=45, ha='right')
plt.tight_layout()
plt.savefig("top_urls.png")
plt.close()

plt.figure(figsize=(10,5))
requests_over_time.plot(kind="line", marker="o")
plt.title("Requests per Hour")
plt.ylabel("Request Count")
plt.xlabel("Hour of Day")
plt.grid(True)
plt.xticks(requests_over_time.index) # Ensure all hours are shown
plt.tight_layout()
plt.savefig("requests_timeline.png")
plt.close()

print("\n📈 Charts saved: (top_ips.png, top_urls.png, requests_timeline.png)")


# --- 6. PDF REPORT GENERATION (ReportLab) ---

c = canvas.Canvas(pdf_file, pagesize=letter)
width, height = letter
styles = getSampleStyleSheet()

# --- Page 1: Summary and Text Stats ---

c.setFont("Helvetica-Bold", 18)
c.drawString(50, height - 50, "Web Server Log Analysis Report")

# LLM Summary Section
c.setFont("Helvetica-Bold", 14)
c.drawString(50, height - 90, "Executive Summary:")
y_current = height - 110

# Prepare LLM summary for multi-line text (Paragraph)
# Replace markdown bolding with ReportLab's HTML equivalent: <b>...</b>
llm_summary_html = llm_summary.replace('\n\n', '<br/><br/>').replace('\n', ' ').replace('**', '<b>').replace('<b># Executive Summary', '').strip()

style_summary = styles['Normal']
style_summary.fontName = 'Helvetica'
style_summary.fontSize = 10
style_summary.leading = 14
style_summary.spaceAfter = 6

p = Paragraph(llm_summary_html, style_summary)
p.wrapOn(c, 500, 200) # Wrap within 500pt width, 200pt height
p.drawOn(c, 50, y_current - p.height)

y_current = y_current - p.height - 30 # Adjust y position after the summary

# Basic Stats
c.setFont("Helvetica", 12)
c.drawString(50, y_current, f"Total log entries analyzed: {len(df)}")
c.drawString(50, y_current - 15, f"Report generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

y_current -= 50

# Top IPs
c.setFont("Helvetica-Bold", 14)
c.drawString(50, y_current, "Top Client IPs:")
y_current -= 20
for ip, count in ip_counts.items():
    c.setFont("Helvetica", 12)
    c.drawString(60, y_current, f"{ip} — {count} requests")
    y_current -= 15

# Top URLs
c.setFont("Helvetica-Bold", 14)
c.drawString(50, y_current - 20, "Top Requested URLs:")
y_current -= 40
for url, count in url_counts.items():
    c.setFont("Helvetica", 12)
    c.drawString(60, y_current, f"{url} — {count} hits")
    y_current -= 15

# Detected Bots/Scanners
if not bot_agents.empty:
    c.setFont("Helvetica-Bold", 14)
    c.drawString(50, y_current - 20, "Detected Bots/Scanners:")
    y_current -= 40
    for agent, count in bot_agents.items():
        c.setFont("Helvetica", 12)
        # Limit agent text length for PDF display
        display_agent = agent[:70] + '...' if len(agent) > 70 else agent
        c.drawString(60, y_current, f"{display_agent} — {count} hits")
        y_current -= 15

# --- Page 2: Charts ---
c.showPage()
c.setFont("Helvetica-Bold", 16)
c.drawString(50, height - 50, "Visualizations")

# Top IPs Chart
c.setFont("Helvetica-Bold", 12)
c.drawString(50, height - 80, "Top Client IPs")
c.drawImage("top_ips.png", 50, height/2 + 20, width=500, preserveAspectRatio=True)

# Top URLs Chart
c.setFont("Helvetica-Bold", 12)
c.drawString(50, height/2 - 40, "Top Requested URLs")
c.drawImage("top_urls.png", 50, 50, width=500, preserveAspectRatio=True)


# --- Page 3: Timeline Chart ---
c.showPage()
c.setFont("Helvetica-Bold", 16)
c.drawString(50, height - 50, "Requests Over Time")
c.drawImage("requests_timeline.png", 50, height/3, width=500, preserveAspectRatio=True)


# Save the PDF
c.save()
print(f"\n📄 PDF report generated: {pdf_file}")


# --- 7. CLEANUP (Optional) ---
# To avoid clutter, you might want to delete the charts and mock log after running.
# for f in chart_files:
#     if os.path.exists(f):
#         os.remove(f)
# print("\nCleanup: Removed temporary chart files.")