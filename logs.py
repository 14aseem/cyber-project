import re
from collections import Counter
import pandas as pd
import matplotlib.pyplot as plt
from datetime import datetime
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas

pattern = re.compile(
    r'(?P<ip>\d+\.\d+\.\d+\.\d+)\s+-\s+(?P<user>[\w\-]+|-)\s+\[(?P<time>[^\]]+)\]\s+"(?P<method>[A-Z]+)\s(?P<url>\S+)\sHTTP/[0-9.]+"\s(?P<status>\d+)\s(?P<size>\d+)\s"(?P<referrer>[^"]*)"\s"(?P<agent>[^"]*)"'
)

records = []
log_file = "access.log"

with open(log_file, "r") as f:
    for line in f:
        m = pattern.search(line)
        if m:
            records.append({
                "IP": m.group('ip'),
                "User": m.group('user'),
                "Time": datetime.strptime(m.group('time').split()[0], "%d/%b/%Y:%H:%M:%S"),
                "Method": m.group('method'),
                "URL": m.group('url'),
                "Status": int(m.group('status')),
                "Bytes": int(m.group('size')),
                "Referrer": m.group('referrer'),
                "UserAgent": m.group('agent')
            })

df = pd.DataFrame(records)
df.to_csv("parsed_web_log.csv", index=False)

print(f" Parsed {len(df)} log entries.")
print("Data saved to parsed_web_log.csv")


ip_counts = df["IP"].value_counts().head(10)
url_counts = df["URL"].value_counts().head(10)
bot_agents = df["UserAgent"].value_counts()
bot_agents = bot_agents[[ua for ua in bot_agents.index if any(b in ua.lower() for b in ["bot", "curl", "nikto"])]]

# Requests over time
requests_over_time = df.groupby(df["Time"].dt.hour).size()


plt.figure(figsize=(10,5))
ip_counts.plot(kind="bar")
plt.title("Top Client IPs")
plt.ylabel("Request Count")
plt.xlabel("Client IP")
plt.tight_layout()
plt.savefig("top_ips.png")
plt.close()

plt.figure(figsize=(10,5))
url_counts.plot(kind="bar", color='orange')
plt.title("Top Requested URLs")
plt.ylabel("Hit Count")
plt.xlabel("URL")
plt.tight_layout()
plt.savefig("top_urls.png")
plt.close()

plt.figure(figsize=(10,5))
requests_over_time.plot(kind="line", marker="o")
plt.title("Requests per Hour")
plt.ylabel("Request Count")
plt.xlabel("Hour of Day")
plt.grid(True)
plt.tight_layout()
plt.savefig("requests_timeline.png")
plt.close()

print(" Charts saved (top_ips.png, top_urls.png, requests_timeline.png)")

pdf_file = "WebServer_Log_Report.pdf"
c = canvas.Canvas(pdf_file, pagesize=letter)
width, height = letter

c.setFont("Helvetica-Bold", 16)
c.drawString(50, height - 50, "Web Server Log Analysis Report")

c.setFont("Helvetica", 12)
c.drawString(50, height - 80, f"Total log entries analyzed: {len(df)}")
c.drawString(50, height - 100, f"Report generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

c.setFont("Helvetica-Bold", 14)
c.drawString(50, height - 140, "Top IPs:")
y = height - 160
for ip, count in ip_counts.items():
    c.setFont("Helvetica", 12)
    c.drawString(60, y, f"{ip} — {count} requests")
    y -= 15

c.setFont("Helvetica-Bold", 14)
c.drawString(50, y - 20, "Top URLs:")
y -= 40
for url, count in url_counts.items():
    c.setFont("Helvetica", 12)
    c.drawString(60, y, f"{url} — {count} hits")
    y -= 15

if len(bot_agents) > 0:
    c.setFont("Helvetica-Bold", 14)
    c.drawString(50, y - 20, "Detected Bots/Scanners:")
    y -= 40
    for agent, count in bot_agents.items():
        c.setFont("Helvetica", 12)
        c.drawString(60, y, f"{agent} — {count} hits")
        y -= 15

c.showPage()
c.drawImage("top_ips.png", 50, height/2 + 20, width=500, preserveAspectRatio=True)
c.drawImage("top_urls.png", 50, height/4 - 100, width=500, preserveAspectRatio=True)

c.showPage()
c.drawImage("requests_timeline.png", 50, height/3, width=500, preserveAspectRatio=True)

c.save()
print(f"PDF report generated: {pdf_file}")
