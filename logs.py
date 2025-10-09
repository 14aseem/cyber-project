import re
from collections import Counter
import pandas as pd
import matplotlib.pyplot as plt
from datetime import datetime
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas

LOG_FILE_PATH = "access.log"
OUTPUT_CSV_FILE = "parsed_web_log.csv"
OUTPUT_PDF_REPORT = "WebServer_Log_Report.pdf"

def parse_log_file(file_path):
    log_pattern = re.compile(
        r'(?P<ip>\d+\.\d+\.\d+\.\d+)\s+-\s+(?P<user>[\w\-]+|-)\s+\[(?P<time>[^\]]+)\]\s+"(?P<method>[A-Z]+)\s(?P<url>\S+)\sHTTP/[0-9.]+"\s(?P<status>\d+)\s(?P<size>\d+)\s"(?P<referrer>[^"]*)"\s"(?P<agent>[^"]*)"'
    )

    print(f"🕵️‍♂️ Reading and parsing the log file: {file_path}")
    
    parsed_records = []
    with open(file_path, "r") as log_file:
        for log_entry in log_file:
            match = log_pattern.search(log_entry)
            if match:
                record = {
                    "IP": match.group('ip'),
                    "User": match.group('user'),
                    "Time": datetime.strptime(match.group('time').split()[0], "%d/%b/%Y:%H:%M:%S"),
                    "Method": match.group('method'),
                    "URL": match.group('url'),
                    "Status": int(match.group('status')),
                    "Bytes": int(match.group('size')),
                    "Referrer": match.group('referrer'),
                    "UserAgent": match.group('agent')
                }
                parsed_records.append(record)
                
    return parsed_records

def analyze_data(log_dataframe):
    print("🧠 Analyzing the data to find patterns...")
    
    top_ips = log_dataframe["IP"].value_counts().head(10)
    top_urls = log_dataframe["URL"].value_counts().head(10)
    
    all_user_agents = log_dataframe["UserAgent"].value_counts()
    bot_keywords = ["bot", "curl", "nikto"]
    detected_bots = all_user_agents[[ua for ua in all_user_agents.index if any(b in ua.lower() for b in bot_keywords)]]

    requests_by_hour = log_dataframe.groupby(log_dataframe["Time"].dt.hour).size()
    
    analysis_results = {
        "top_ips": top_ips,
        "top_urls": top_urls,
        "detected_bots": detected_bots,
        "requests_by_hour": requests_by_hour
    }
    return analysis_results

def create_visual_charts(analysis_results):
    print("📊 Generating visual charts...")
    
    plt.figure(figsize=(10, 5))
    analysis_results["top_ips"].plot(kind="bar")
    plt.title("Top 10 Most Active Client IPs")
    plt.ylabel("Number of Requests")
    plt.xlabel("Client IP Address")
    plt.tight_layout()
    plt.savefig("top_ips.png")
    plt.close()

    plt.figure(figsize=(10, 5))
    analysis_results["top_urls"].plot(kind="bar", color='orange')
    plt.title("Top 10 Most Requested URLs")
    plt.ylabel("Number of Hits")
    plt.xlabel("URL Path")
    plt.tight_layout()
    plt.savefig("top_urls.png")
    plt.close()

    plt.figure(figsize=(10, 5))
    analysis_results["requests_by_hour"].plot(kind="line", marker="o")
    plt.title("Website Requests per Hour of the Day")
    plt.ylabel("Number of Requests")
    plt.xlabel("Hour of Day (24-hour format)")
    plt.grid(True)
    plt.tight_layout()
    plt.savefig("requests_timeline.png")
    plt.close()
    
    print("✅ Charts saved as top_ips.png, top_urls.png, and requests_timeline.png")

def generate_pdf_report(analysis_results, total_entries):
    print(f"📄 Creating PDF report: {OUTPUT_PDF_REPORT}")
    
    pdf_canvas = canvas.Canvas(OUTPUT_PDF_REPORT, pagesize=letter)
    width, height = letter

    pdf_canvas.setFont("Helvetica-Bold", 16)
    pdf_canvas.drawString(50, height - 50, "Web Server Log Analysis Report")

    pdf_canvas.setFont("Helvetica", 12)
    pdf_canvas.drawString(50, height - 80, f"Total log entries analyzed: {total_entries}")
    pdf_canvas.drawString(50, height - 100, f"Report generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    
    current_y = height - 140

    pdf_canvas.setFont("Helvetica-Bold", 14)
    pdf_canvas.drawString(50, current_y, "Top IPs:")
    current_y -= 20
    for ip, count in analysis_results["top_ips"].items():
        pdf_canvas.setFont("Helvetica", 12)
        pdf_canvas.drawString(60, current_y, f"{ip} — {count} requests")
        current_y -= 15
    
    current_y -= 20

    pdf_canvas.setFont("Helvetica-Bold", 14)
    pdf_canvas.drawString(50, current_y, "Top URLs:")
    current_y -= 20
    for url, count in analysis_results["top_urls"].items():
        pdf_canvas.setFont("Helvetica", 12)
        pdf_canvas.drawString(60, current_y, f"{url} — {count} hits")
        current_y -= 15

    if not analysis_results["detected_bots"].empty:
        current_y -= 20
        pdf_canvas.setFont("Helvetica-Bold", 14)
        pdf_canvas.drawString(50, current_y, "Detected Bots/Scanners:")
        current_y -= 20
        for agent, count in analysis_results["detected_bots"].items():
            pdf_canvas.setFont("Helvetica", 10)
            pdf_canvas.drawString(60, current_y, f"{agent[:70]}... — {count} hits")
            current_y -= 15

    pdf_canvas.showPage()

    pdf_canvas.drawImage("top_ips.png", 50, height / 2, width=500, preserveAspectRatio=True)
    pdf_canvas.drawImage("top_urls.png", 50, 50, width=500, preserveAspectRatio=True)
    
    pdf_canvas.showPage()
    
    pdf_canvas.drawImage("requests_timeline.png", 50, height / 2, width=500, preserveAspectRatio=True)

    pdf_canvas.save()
    print(f" PDF report generated successfully!")

if __name__ == "__main__":
    log_records = parse_log_file(LOG_FILE_PATH)
    
    if not log_records:
        print("Could not find any valid log entries. Exiting.")
    else:
        print(f" Success! Parsed {len(log_records)} log entries.")

        log_dataframe = pd.DataFrame(log_records)
        log_dataframe.to_csv(OUTPUT_CSV_FILE, index=False)
        print(f"Data saved to {OUTPUT_CSV_FILE}")

        insights = analyze_data(log_dataframe)
        create_visual_charts(insights)
        generate_pdf_report(insights, total_entries=len(log_dataframe))
        
        print("\n All tasks complete!")