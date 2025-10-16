"""
Fake Bank Website - Flask Application
For scambaiting purposes only
"""

from flask import Flask, render_template, request, redirect, url_for, session, flash
import json
import os
import sys
from datetime import datetime, timedelta

# Determine base path for resources (PyInstaller compatibility)
if getattr(sys, "frozen", False):
    # Running as compiled exe - use PyInstaller's temp directory
    BASE_PATH = sys._MEIPASS
    # Check for dev mode marker in the directory containing the exe
    DEV_MODE = os.path.exists(os.path.join(os.path.dirname(sys.executable), ".dev_mode"))
else:
    # Running as script
    BASE_PATH = os.path.dirname(os.path.abspath(__file__))
    DEV_MODE = os.path.exists(os.path.join(BASE_PATH, ".dev_mode"))

app = Flask(
    __name__, template_folder=os.path.join(BASE_PATH, "templates"), static_folder=os.path.join(BASE_PATH, "static")
)
app.secret_key = "fake-bank-secret-key-for-scambaiting-only"  # Not real security needed

# Session configuration
app.config["SESSION_COOKIE_SECURE"] = False  # Set to True if using HTTPS
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(hours=2)
app.config["SESSION_REFRESH_EACH_REQUEST"] = True


# Custom Jinja2 filter for currency formatting
@app.template_filter("currency")
def currency_filter(value):
    """Format number as currency with commas and 2 decimal places"""
    try:
        return "${:,.2f}".format(float(value))
    except (ValueError, TypeError):
        return "$0.00"


# Load JSON data
def load_json(filename):
    """Load data from JSON file"""
    filepath = os.path.join(BASE_PATH, "data", filename)
    with open(filepath, "r") as f:
        return json.load(f)


def process_transactions(transactions_data):
    """Convert days_ago to actual dates for all transactions"""
    processed = {}
    today = datetime.now()

    for account_id, transactions in transactions_data.items():
        processed[account_id] = []
        for txn in transactions:
            txn_copy = txn.copy()
            # Convert days_ago to actual date
            if "days_ago" in txn_copy:
                days_ago = txn_copy.pop("days_ago")
                txn_date = today - timedelta(days=days_ago)
                txn_copy["date"] = txn_date.strftime("%Y-%m-%d")
            processed[account_id].append(txn_copy)

    return processed


# Routes


@app.route("/")
def index():
    """Redirect to login"""
    if "username" in session:
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    """Login page - checks password and requires 2FA"""
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        users = load_json("users.json")

        # Check if user exists and password matches (demo_pass field for scambaiting)
        if username in users and users[username]["demo_pass"] == password:
            # Store credentials temporarily for 2FA
            session["pending_username"] = username
            session["pending_user_data"] = users[username]
            return redirect(url_for("login_2fa"))
        else:
            flash("Invalid User ID or Password. Please try again.", "danger")
            return redirect(url_for("login"))

    return render_template("login.html")


@app.route("/login/2fa", methods=["GET", "POST"])
def login_2fa():
    """2FA SMS verification for login"""
    if "pending_username" not in session:
        return redirect(url_for("login"))

    user_data = session.get("pending_user_data", {})
    user_phone = user_data.get("phone", "(xxx) xxx-xxxx")

    if request.method == "POST":
        code = request.form.get("code", "")

        # Accept any 6-digit code
        if code and len(code) == 6:
            # Complete login
            username = session.pop("pending_username")
            user_data = session.pop("pending_user_data")

            # Mark session as permanent (will last for PERMANENT_SESSION_LIFETIME)
            session.permanent = True

            session["username"] = username
            session["first_name"] = user_data.get("first_name", "Bob")
            session["last_name"] = user_data.get("last_name", "Gardner")
            session["full_name"] = user_data["full_name"]
            session["account_ids"] = user_data["account_ids"]

            return redirect(url_for("dashboard"))
        else:
            flash("Invalid verification code. Please enter a 6-digit code.", "danger")

    return render_template("login_2fa.html", user_phone=user_phone)


@app.route("/dashboard")
def dashboard():
    """Main dashboard showing account summary"""
    if "username" not in session:
        return redirect(url_for("login"))

    accounts = load_json("accounts.json")
    transactions_raw = load_json("transactions.json")
    transactions = process_transactions(transactions_raw)

    # Get user's accounts
    account_ids = session.get("account_ids", [])
    user_accounts = {aid: accounts[aid] for aid in account_ids if aid in accounts}

    # Get recent transactions (last 5 combined from all accounts)
    recent_transactions = []
    for aid in account_ids:
        if aid in transactions:
            for txn in transactions[aid][:3]:  # Get last 3 from each
                txn_copy = txn.copy()
                txn_copy["account_type"] = accounts[aid]["account_type"]
                recent_transactions.append(txn_copy)

    # Sort by date
    recent_transactions.sort(key=lambda x: x["date"], reverse=True)
    recent_transactions = recent_transactions[:5]

    return render_template(
        "dashboard.html",
        full_name=session.get("full_name"),
        accounts=user_accounts,
        recent_transactions=recent_transactions,
    )


@app.route("/account/<account_id>")
def account_details(account_id):
    """Account details page with full transaction history"""
    if "username" not in session:
        return redirect(url_for("login"))

    accounts = load_json("accounts.json")
    transactions_raw = load_json("transactions.json")
    transactions = process_transactions(transactions_raw)

    if account_id not in accounts:
        return redirect(url_for("dashboard"))

    account = accounts[account_id]
    account_transactions = transactions.get(account_id, [])

    return render_template(
        "account_details.html", account_id=account_id, account=account, transactions=account_transactions
    )


@app.route("/transfer", methods=["GET", "POST"])
def transfer():
    """Transfer money form"""
    if "username" not in session:
        return redirect(url_for("login"))

    accounts = load_json("accounts.json")
    account_ids = session.get("account_ids", [])
    user_accounts = {aid: accounts[aid] for aid in account_ids if aid in accounts}

    if request.method == "POST":
        # Store transfer data in session
        session["transfer_data"] = {
            "from_account": request.form.get("from_account"),
            "to_account": request.form.get("to_account"),
            "amount": request.form.get("amount"),
            "memo": request.form.get("memo", ""),
        }
        return redirect(url_for("transfer_review"))

    return render_template("transfer.html", accounts=user_accounts)


@app.route("/transfer/review", methods=["GET", "POST"])
def transfer_review():
    """Review transfer before confirmation"""
    if "username" not in session:
        return redirect(url_for("login"))

    if "transfer_data" not in session:
        return redirect(url_for("transfer"))

    accounts = load_json("accounts.json")
    transfer_data = session["transfer_data"]

    # Get account details
    from_account = accounts.get(transfer_data["from_account"], {})
    to_account_id = transfer_data["to_account"]

    # Determine if external wire
    is_external = to_account_id not in accounts

    if request.method == "POST":
        if request.form.get("action") == "confirm":
            # Store transfer type
            session["transfer_is_external"] = is_external

            if is_external:
                # External transfer - trigger security challenge chain
                return redirect(url_for("security_account_verify"))
            else:
                # Internal transfer - skip to processing
                return redirect(url_for("transfer_processing"))
        else:
            # Cancel
            return redirect(url_for("transfer"))

    return render_template(
        "transfer_review.html", transfer_data=transfer_data, from_account=from_account, is_external=is_external
    )


@app.route("/security/account-verify", methods=["GET", "POST"])
def security_account_verify():
    """Account verification - SSN, DOB, etc."""
    if "username" not in session:
        return redirect(url_for("login"))

    if "transfer_data" not in session:
        return redirect(url_for("transfer"))

    if request.method == "POST":
        # Accept any input - no real validation
        ssn = request.form.get("ssn", "")
        dob = request.form.get("dob", "")
        maiden_name = request.form.get("maiden_name", "")
        zip_code = request.form.get("zip_code", "")

        # Track attempts
        attempts = session.get("account_verify_attempts", 0)

        # Always succeed on first 2 attempts, fake lockout on 3rd
        if attempts >= 2:
            session["account_verify_lockout"] = True
            flash("Too many verification attempts. Please wait 10 minutes.", "danger")
        else:
            if ssn and dob and maiden_name and zip_code:
                session["account_verified"] = True
                session["account_verify_attempts"] = 0
                return redirect(url_for("security_sms_verify"))
            else:
                attempts += 1
                session["account_verify_attempts"] = attempts
                flash("Please fill in all fields to verify your identity.", "warning")

    return render_template("account_verify.html")


@app.route("/security/sms-verify", methods=["GET", "POST"])
def security_sms_verify():
    """SMS verification code challenge"""
    if "username" not in session:
        return redirect(url_for("login"))

    if "transfer_data" not in session:
        return redirect(url_for("transfer"))

    # Check previous step
    if not session.get("account_verified"):
        return redirect(url_for("security_account_verify"))

    users = load_json("users.json")
    username = session.get("username")
    user_phone = users.get(username, {}).get("phone", "(313) 555-0142")

    # Handle resend button
    if request.method == "POST" and request.form.get("action") == "resend":
        resend_count = session.get("sms_resend_count", 0) + 1
        session["sms_resend_count"] = resend_count
        flash("Verification code resent successfully!", "success")
        return render_template("sms_verify.html", user_phone=user_phone, resend_count=resend_count)

    if request.method == "POST":
        code = request.form.get("code", "")

        # Hardcoded SMS verification code
        if code == "987654":
            session["sms_verified"] = True
            session["sms_resend_count"] = 0
            return redirect(url_for("security_verify"))
        else:
            flash("Invalid verification code. Please try again.", "danger")

    resend_count = session.get("sms_resend_count", 0)
    return render_template("sms_verify.html", user_phone=user_phone, resend_count=resend_count)


@app.route("/security/verify", methods=["GET", "POST"])
def security_verify():
    """Email verification code challenge"""
    if "username" not in session:
        return redirect(url_for("login"))

    if "transfer_data" not in session:
        return redirect(url_for("transfer"))

    # Check previous steps
    if not session.get("account_verified"):
        return redirect(url_for("security_account_verify"))
    if not session.get("sms_verified"):
        return redirect(url_for("security_sms_verify"))

    users = load_json("users.json")
    username = session.get("username")
    user_email = users.get(username, {}).get("email", "your email")

    if request.method == "POST":
        code = request.form.get("code", "")

        # Hardcoded verification code
        if code == "123456":
            session["security_email_verified"] = True
            return redirect(url_for("security_activity_review"))
        else:
            flash("Invalid verification code. Please try again.", "danger")

    return render_template("security_verify.html", user_email=user_email)


@app.route("/security/activity-review", methods=["GET", "POST"])
def security_activity_review():
    """Review suspicious account activity"""
    if "username" not in session:
        return redirect(url_for("login"))

    if "transfer_data" not in session:
        return redirect(url_for("transfer"))

    # Check previous steps
    if not session.get("security_email_verified"):
        return redirect(url_for("security_verify"))

    activities = load_json("suspicious_activities.json")

    if request.method == "POST":
        # Check if all activities were reviewed
        reviewed_count = 0
        for idx, activity in enumerate(activities):
            response = request.form.get(f"activity_{idx}")
            if response:
                reviewed_count += 1

        if reviewed_count == len(activities):
            session["activity_reviewed"] = True
            return redirect(url_for("security_questions"))
        else:
            flash("Please review all suspicious activities before proceeding.", "warning")

    return render_template("activity_review.html", activities=activities)


@app.route("/security/fraud-quiz", methods=["GET", "POST"])
def security_fraud_quiz():
    """Fraud prevention knowledge quiz"""
    import random

    if "username" not in session:
        return redirect(url_for("login"))

    if "transfer_data" not in session:
        return redirect(url_for("transfer"))

    # Check previous steps
    if not session.get("activity_reviewed"):
        return redirect(url_for("security_activity_review"))

    all_questions = load_json("fraud_quiz.json")

    # Initialize or get quiz questions
    if "quiz_questions" not in session:
        # Select 5 random questions
        selected = random.sample(all_questions, min(5, len(all_questions)))
        session["quiz_questions"] = selected
        session["quiz_current"] = 0
        session["quiz_score"] = 0

    quiz_questions = session["quiz_questions"]
    current_idx = session.get("quiz_current", 0)

    if current_idx >= len(quiz_questions):
        # Quiz complete
        session["quiz_completed"] = True
        session.pop("quiz_questions", None)
        session.pop("quiz_current", None)
        session.pop("quiz_score", None)
        return redirect(url_for("transfer_processing"))

    current_question = quiz_questions[current_idx]

    if request.method == "POST":
        answer = request.form.get("answer")
        if answer:
            answer_idx = int(answer)
            correct_idx = current_question["correct"]

            if answer_idx == correct_idx:
                session["quiz_score"] = session.get("quiz_score", 0) + 1
                session["quiz_current"] = current_idx + 1
                flash("Correct! Moving to next question...", "success")
                return redirect(url_for("security_fraud_quiz"))
            else:
                # Wrong answer - restart quiz
                flash("Incorrect answer. For your security, you must restart the quiz.", "danger")
                session.pop("quiz_questions", None)
                session.pop("quiz_current", None)
                session.pop("quiz_score", None)
                return redirect(url_for("security_fraud_quiz"))

    progress = ((current_idx + 1) / len(quiz_questions)) * 100

    return render_template(
        "fraud_quiz.html",
        question=current_question,
        current=current_idx + 1,
        total=len(quiz_questions),
        progress=progress,
    )


@app.route("/security/questions", methods=["GET", "POST"])
def security_questions():
    """Security question challenge"""
    if "username" not in session:
        return redirect(url_for("login"))

    if "transfer_data" not in session:
        return redirect(url_for("transfer"))

    # Check previous steps
    if not session.get("activity_reviewed"):
        return redirect(url_for("security_activity_review"))

    users = load_json("users.json")
    username = session.get("username")
    security_qa = users.get(username, {}).get("security_questions", {})
    question = security_qa.get("q1", "What is your pet's name?")
    correct_answer = security_qa.get("a1", "murphy").lower()

    if request.method == "POST":
        answer = request.form.get("answer", "").lower().strip()

        # Track attempts
        attempts = session.get("security_attempts", 0)

        if answer == correct_answer:
            # Success!
            session["security_question_verified"] = True
            session["security_attempts"] = 0
            return redirect(url_for("transfer_processing"))
        else:
            attempts += 1
            session["security_attempts"] = attempts

            if attempts >= 2:
                # Lockout after 2 failures
                session["security_lockout_time"] = (datetime.now() + timedelta(minutes=5)).isoformat()
                flash("Too many failed attempts. Your account has been temporarily locked for 5 minutes.", "danger")
            else:
                flash(f"Incorrect answer. {2 - attempts} attempts remaining.", "warning")

    # Check if locked out
    lockout_time = session.get("security_lockout_time")
    is_locked = False
    if lockout_time:
        lockout_dt = datetime.fromisoformat(lockout_time)
        if datetime.now() < lockout_dt:
            is_locked = True

    return render_template("security_questions.html", question=question, is_locked=is_locked)


@app.route("/transfer/processing")
def transfer_processing():
    """Fake processing screen with loading animation"""
    if "username" not in session:
        return redirect(url_for("login"))

    if "transfer_data" not in session:
        return redirect(url_for("transfer"))

    # For external transfers, verify security checks passed
    if session.get("transfer_is_external"):
        if not session.get("security_email_verified") or not session.get("security_question_verified"):
            return redirect(url_for("transfer"))

    return render_template("transfer_processing.html")


@app.route("/transfer/success")
def transfer_success():
    """Transfer confirmation page"""
    if "username" not in session:
        return redirect(url_for("login"))

    if "transfer_data" not in session:
        return redirect(url_for("dashboard"))

    transfer_data = session["transfer_data"]

    # Generate transaction ID
    txn_id = f"TXN-{datetime.now().strftime('%Y%m%d-%H%M%S')}"

    # Clear transfer session data
    session.pop("transfer_data", None)
    session.pop("transfer_is_external", None)
    session.pop("account_verified", None)
    session.pop("account_verify_attempts", None)
    session.pop("account_verify_lockout", None)
    session.pop("sms_verified", None)
    session.pop("sms_resend_count", None)
    session.pop("security_email_verified", None)
    session.pop("activity_reviewed", None)
    session.pop("security_question_verified", None)
    session.pop("security_attempts", None)
    session.pop("security_lockout_time", None)
    session.pop("quiz_completed", None)
    session.pop("quiz_questions", None)
    session.pop("quiz_current", None)
    session.pop("quiz_score", None)

    return render_template(
        "transfer_success.html",
        transfer_data=transfer_data,
        txn_id=txn_id,
        timestamp=datetime.now().strftime("%Y-%m-%d %I:%M %p"),
    )


@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    """Fake forgot password page"""
    if request.method == "POST":
        flash("If this email exists in our system, we've sent password reset instructions.", "info")

    return render_template("forgot_password.html")


@app.route("/bills/pay", methods=["GET", "POST"])
def pay_bills():
    """Pay bills page"""
    if "username" not in session:
        return redirect(url_for("login"))

    payees = load_json("payees.json")
    accounts = load_json("accounts.json")
    user_account_ids = session.get("account_ids", [])
    user_accounts = {aid: accounts[aid] for aid in user_account_ids if aid in accounts}

    if request.method == "POST":
        # Handle payment submission
        flash("Payment scheduled successfully! Your payment will be processed within 1-2 business days.", "success")
        return redirect(url_for("pay_bills"))

    return render_template("pay_bills.html", payees=payees, accounts=user_accounts)


@app.route("/statements")
def statements():
    """View account statements"""
    if "username" not in session:
        return redirect(url_for("login"))

    accounts = load_json("accounts.json")
    user_account_ids = session.get("account_ids", [])
    user_accounts = {aid: accounts[aid] for aid in user_account_ids if aid in accounts}

    # Generate 12 months of fake statements
    statements_data = []
    current_date = datetime.now()

    for i in range(12):
        month_date = current_date - timedelta(days=30 * i)
        statements_data.append(
            {
                "period": month_date.strftime("%B %Y"),
                "statement_date": month_date.strftime("%Y-%m-%d"),
                "month_year": month_date.strftime("%m/%Y"),
            }
        )

    return render_template("statements.html", accounts=user_accounts, statements=statements_data)


@app.route("/settings", methods=["GET", "POST"])
def settings():
    """Banking preferences and settings"""
    if "username" not in session:
        return redirect(url_for("login"))

    if request.method == "POST":
        # Fake save - just show success message
        flash("Settings updated successfully!", "success")
        return redirect(url_for("settings"))

    return render_template("settings.html")


@app.route("/logout")
def logout():
    """Logout and clear session"""
    session.clear()
    return redirect(url_for("login"))


@app.route("/account/settings", methods=["GET", "POST"])
def account_settings():
    """Account settings page - edit personal information"""
    if "username" not in session:
        return redirect(url_for("login"))

    users = load_json("users.json")
    username = session.get("username")

    # Get user data
    user_data = users.get(username, {})

    if request.method == "POST":
        # Get form data
        first_name = request.form.get("first_name", "")
        last_name = request.form.get("last_name", "")
        email = request.form.get("email", "")
        phone = request.form.get("phone", "")
        address = request.form.get("address", "")
        city = request.form.get("city", "")
        state = request.form.get("state", "")
        zip_code = request.form.get("zip", "")

        # Handle password reset
        current_password = request.form.get("current_password", "")
        new_password = request.form.get("new_password", "")
        confirm_password = request.form.get("confirm_password", "")

        # Fake validation - just show success message
        if new_password and new_password == confirm_password:
            flash("Password updated successfully!", "success")
        elif new_password and new_password != confirm_password:
            flash("New passwords do not match!", "danger")
        else:
            flash("Account information updated successfully!", "success")

        # Update session with new first name if changed
        if first_name:
            session["first_name"] = first_name
            session["last_name"] = last_name

        # In a real app, we'd save to JSON/database here
        # For scambaiting, we just fake the success

        return redirect(url_for("account_settings"))

    return render_template("account_settings.html", user=user_data)


@app.route("/rewards")
def rewards():
    """Rewards & Deals page"""
    if "username" not in session:
        return redirect(url_for("login"))
    return render_template("rewards.html")


@app.route("/tools")
def tools():
    """Tools & Investing page"""
    if "username" not in session:
        return redirect(url_for("login"))

    # Get accounts for display
    accounts = load_json("accounts.json")
    user_accounts = {}
    for account_id in session.get("account_ids", []):
        if account_id in accounts:
            user_accounts[account_id] = accounts[account_id]

    return render_template("tools.html", accounts=user_accounts)


@app.route("/security-center")
def security_center():
    """Security Center page"""
    if "username" not in session:
        return redirect(url_for("login"))
    return render_template("security_center.html")


@app.route("/help")
def help_page():
    """Help & Support page"""
    if "username" not in session:
        return redirect(url_for("login"))
    return render_template("help.html")


@app.route("/open-account", methods=["GET", "POST"])
def open_account():
    """Open a new account page"""
    # Allow viewing without login (for new customers)
    if request.method == "POST":
        # Fake application processing
        account_type = request.form.get("account_type", "checking")
        first_name = request.form.get("first_name", "")

        flash(
            f"Thank you, {first_name}! Your {account_type} account application has been submitted. "
            "You will receive an email confirmation within 1-2 business days.",
            "success",
        )

        # If logged in, redirect to dashboard; otherwise stay on page
        if "username" in session:
            return redirect(url_for("dashboard"))
        return redirect(url_for("open_account"))

    return render_template("open_account.html")


if __name__ == "__main__":
    # Run on port 80 for seamless hosts file redirect (requires admin privileges on Windows)
    # Use debug mode if .dev_mode marker exists
    try:
        app.run(host="0.0.0.0", port=80, debug=DEV_MODE)
    except PermissionError:
        if DEV_MODE:
            print("ERROR: Port 80 requires administrator privileges.")
            print("Please run as administrator or use a different port.")
            input("Press Enter to exit...")
        sys.exit(1)
    except OSError as e:
        if DEV_MODE:
            print(f"ERROR: Failed to bind to port 80: {e}")
            print("Port 80 may already be in use.")
            input("Press Enter to exit...")
        sys.exit(1)
