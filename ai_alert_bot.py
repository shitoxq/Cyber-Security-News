import html
import os
import sqlite3
import requests
import feedparser
from google import genai
from google.genai import types
from pydantic import BaseModel, Field

# ---------------------------------------------------------------------------
# Setup & Configuration
# ---------------------------------------------------------------------------
BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")
CHAT_ID = os.getenv("TELEGRAM_CHAT_ID")
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
DB_FILE = "alerts.db"

# Ensure environment variables exist before running
if not all([BOT_TOKEN, CHAT_ID, GEMINI_API_KEY]):
    raise ValueError("Missing environment variables: Ensure TELEGRAM_BOT_TOKEN, TELEGRAM_CHAT_ID, and GEMINI_API_KEY are set.")

client = genai.Client(api_key=GEMINI_API_KEY)

# ---------------------------------------------------------------------------
# Database Layer (SQLite)
# ---------------------------------------------------------------------------
def init_db():
    """Creates the alerts table if it doesn't already exist."""
    with sqlite3.connect(DB_FILE) as conn:
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS processed_alerts (
                guid TEXT PRIMARY KEY,
                processed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        conn.commit()

def is_alert_processed(guid: str) -> bool:
    """Checks if an RSS GUID has already been processed."""
    with sqlite3.connect(DB_FILE) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT 1 FROM processed_alerts WHERE guid = ?", (guid,))
        return cursor.fetchone() is not None

def mark_alert_processed(guid: str):
    """Saves a processed RSS GUID to the database."""
    with sqlite3.connect(DB_FILE) as conn:
        cursor = conn.cursor()
        cursor.execute("INSERT OR IGNORE INTO processed_alerts (guid) VALUES (?)", (guid,))
        conn.commit()

# ---------------------------------------------------------------------------
# Gemini & Telegram Functions
# ---------------------------------------------------------------------------
class SecurityAlertSchema(BaseModel):
    severity: str = Field(description="MUST be one of 'CRITICAL', 'HIGH', 'MEDIUM', or 'LOW'")
    title: str = Field(description="Clear, concise title")
    summary: str = Field(description="2-3 sentence technical summary")
    recommended_action: str = Field(description="Actionable mitigation advice")
    hashtags: list[str] = Field(description="3-5 relevant hashtags")

def analyze_threat_with_gemini(raw_text: str) -> SecurityAlertSchema:
    prompt = f"You are a Threat Analyst. Analyze and summarize this text:\n\n{raw_text}"
    response = client.models.generate_content(
        model="gemini-2.5-flash",
        contents=prompt,
        config=types.GenerateContentConfig(
            response_mime_type="application/json",
            response_schema=SecurityAlertSchema,
            temperature=0.2
        ),
    )
    return response.parsed

def build_telegram_message(alert: SecurityAlertSchema, source: str, link: str = None) -> str:
    severity_emojis = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}
    emoji = severity_emojis.get(alert.severity.upper(), "🟡")
    
    # Clean up hashtags and sanitize dynamic values for HTML safety
    tags = " ".join([t if t.startswith("#") else f"#{t}" for t in alert.hashtags])
    title = html.escape(alert.title)
    summary = html.escape(alert.summary)
    action = html.escape(alert.recommended_action)

    # Attach URL hyperlink if provided
    source_str = f'<a href="{link}">{source}</a>' if link else source

    return (
        f"🚨 <b>CYBERSECURITY ALERT</b>\n\n"
        f"{emoji} <b>Severity:</b> {alert.severity.upper()}\n\n"
        f"┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈\n\n"
        f"📌 <b>Title:</b>\n{title}\n\n"
        f"📝 <b>Description:</b>\n{summary}\n\n"
        f"┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈\n\n"
        f"🛡️ <b>Recommended Action:</b>\n{action}\n\n"
        f"📰 <b>Source:</b> {source_str}\n\n"
        f"{tags}"
    )

def send_telegram_alert(text: str):
    url = f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage"
    payload = {
        "chat_id": CHAT_ID,
        "text": text,
        "parse_mode": "HTML",
        "disable_web_page_preview": True
    }
    res = requests.post(url, json=payload)
    res.raise_for_status()

# ---------------------------------------------------------------------------
# Main Control Flow
# ---------------------------------------------------------------------------
def run():
    init_db()
    
    # Custom headers prevent government RSS feeds from blocking feedparser
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    }
    
    primary_url = "https://www.cisa.gov/cybersecurity-advisories/all.xml"
    feed = feedparser.parse(primary_url, request_headers=headers)

    # Fallback endpoint if primary fails
    if not feed.entries:
        print("Primary feed empty or blocked. Trying fallback CISA feed...")
        fallback_url = "https://www.cisa.gov/news-events/cybersecurity-advisories/rss.xml"
        feed = feedparser.parse(fallback_url, request_headers=headers)

    if not feed.entries:
        print("No feed entries found across all sources.")
        return

    print(f"Successfully fetched {len(feed.entries)} feed entries.")

    new_alerts_count = 0
    # Process newest entries (up to 5)
    for entry in reversed(feed.entries[:5]):
        guid = entry.get("id", entry.get("link"))
        article_link = entry.get("link")
        
        if not guid:
            continue

        if is_alert_processed(guid):
            print(f"Skipping already processed alert: {guid}")
            continue

        print(f"New alert detected: {guid}")
        raw_content = f"Title: {entry.title}\nContent: {entry.get('summary', '')}"

        try:
            # 1. Summarize with Gemini
            parsed_alert = analyze_threat_with_gemini(raw_content)

            # 2. Format message
            telegram_msg = build_telegram_message(
                parsed_alert, 
                source="CISA Advisories", 
                link=article_link
            )

            # 3. Send to Telegram
            send_telegram_alert(telegram_msg)

            # 4. Save GUID to SQLite to prevent duplicates
            mark_alert_processed(guid)
            
            new_alerts_count += 1
            print(f"Successfully processed and sent alert: {guid}")

        except Exception as e:
            print(f"Error processing alert {guid}: {e}")

    if new_alerts_count == 0:
        print("No new alerts to post.")

if __name__ == "__main__":
    run()
