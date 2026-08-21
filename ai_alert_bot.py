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
    source_str = f'<a href="{link}">{html.escape(source)}</a>' if link else html.escape(source)

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
    res = requests.post(url, json=payload, timeout=10)
    res.raise_for_status()

# ---------------------------------------------------------------------------
# Main Control Flow
# ---------------------------------------------------------------------------
def run():
    init_db()
    
    # Expanded Multi-Feed List including Palo Alto Networks Unit 42 & Advisories
    SOURCES = [
        {"name": "Palo Alto Unit 42", "url": "https://unit42.paloaltonetworks.com/feed/"},
        {"name": "Palo Alto Advisories", "url": "https://security.paloaltonetworks.com/rss.xml"},
        {"name": "CISA Advisories", "url": "https://www.cisa.gov/cybersecurity-advisories/all.xml"},
        {"name": "The Hacker News", "url": "https://feeds.feedburner.com/TheHackersNews"},
        {"name": "BleepingComputer", "url": "https://www.bleepingcomputer.com/feed/"},
        {"name": "Dark Reading", "url": "https://www.darkreading.com/rss.xml"},
        {"name": "SecurityWeek", "url": "https://www.securityweek.com/feed/"},
        {"name": "Sophos Research", "url": "https://news.sophos.com/en-us/category/threat-research/feed/"},
        {"name": "Krebs on Security", "url": "https://krebsonsecurity.com/feed/"},
        {"name": "SANS ISC", "url": "https://isc.sans.edu/rssfeed_full.xml"},
        {"name": "WeLiveSecurity", "url": "https://www.welivesecurity.com/en/rss/feed/"}
    ]

    # Browser headers required to bypass Cloudflare/WAF bot blocks
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    }

    total_new_alerts = 0

    for source in SOURCES:
        try:
            print(f"Fetching feed: {source['name']}...")
            response = requests.get(source["url"], headers=headers, timeout=10)
            response.raise_for_status()
            
            feed = feedparser.parse(response.content)
            if not feed.entries:
                print(f"No entries found for {source['name']}")
                continue

            # Check the newest 2 entries per source
            for entry in reversed(feed.entries[:2]):
                guid = entry.get("id", entry.get("link"))
                article_link = entry.get("link")

                if not guid or is_alert_processed(guid):
                    continue

                print(f"[{source['name']}] New threat detected: {guid}")
                raw_content = f"Title: {entry.title}\nContent: {entry.get('summary', '')}"

                try:
                    # 1. Gemini Summarization
                    parsed_alert = analyze_threat_with_gemini(raw_content)

                    # 2. Format Telegram message
                    telegram_msg = build_telegram_message(
                        alert=parsed_alert, 
                        source=source["name"], 
                        link=article_link
                    )

                    # 3. Send Alert to Telegram
                    send_telegram_alert(telegram_msg)

                    # 4. Save to SQLite DB
                    mark_alert_processed(guid)
                    
                    total_new_alerts += 1
                    print(f"[{source['name']}] Sent alert successfully.")

                except Exception as e:
                    print(f"Failed processing item from {source['name']}: {e}")

        except Exception as e:
            print(f"Could not reach {source['name']}: {e}")

    print(f"Execution complete. Total new alerts posted: {total_new_alerts}")

if __name__ == "__main__":
    run()
