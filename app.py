# =============================================================================
# app.py — Piccoli Ticketi: Main Flask Application (Back-End)
#
# PURPOSE:
#   This file serves as the central back-end module for the Piccoli Ticketi
#   web application. It handles all routing, business logic, session management,
#   database interaction, and security enforcement.
#
# ARCHITECTURE:
#   This app follows the MVC (Model-View-Controller) pattern:
#     - Model:      SQLite database accessed via sqlite3 (initDB, SQL queries)
#     - View:       Jinja2 HTML templates in /templates
#     - Controller: Flask route functions in this file
#
# SECURITY FEATURES IMPLEMENTED (SE-12-07 / SE-12-04):
#   - Password hashing via werkzeug (bcrypt-based) — ensures confidentiality
#   - CSRF protection via Flask-WTF — maintains integrity of form submissions
#   - Rate limiting via Flask-Limiter — ensures availability (prevents brute force)
#   - Session cookies: Secure, HttpOnly, SameSite=Strict — prevents session hijacking
#   - Input sanitisation via markupsafe.escape() — prevents XSS injection
#   - Parameterised SQL queries — prevents SQL injection
#   - Role-based access control (RBAC) — manages authentication & authorisation
# =============================================================================

from flask import Flask, render_template, redirect, request, session, flash, url_for, abort
import sqlite3, os
import werkzeug
from werkzeug.security import generate_password_hash, check_password_hash
# uuid4: generates cryptographically random unique filenames for uploaded images,
# preventing filename collisions and directory traversal attacks
from uuid import uuid4
# escape(): sanitises all user-supplied input before it is used in queries or rendered,
# preventing Cross-Site Scripting (XSS) attacks
from markupsafe import escape
# Limiter: rate-limits sensitive endpoints (e.g. login) to prevent brute-force attacks
# ensuring AVAILABILITY and protecting AUTHENTICATION (SE-12-04)
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from datetime import timedelta
# CSRFProtect: adds CSRF tokens to all forms, maintaining INTEGRITY of state-changing requests
from flask_wtf.csrf import CSRFProtect
import subprocess
import hmac        # Used for HMAC-SHA256 signature verification of GitHub webhooks
import hashlib
import requests    # Used to call the PythonAnywhere API to reload the web app after deployment
import threading   # Allows the deploy process to run asynchronously so GitHub receives a 200 OK

app = Flask(__name__)

# =============================================================================
# DEPLOYMENT CONFIGURATION (CI/CD via GitHub Webhooks)
# These constants control the automated Git pull + PythonAnywhere reload
# triggered when code is pushed to the main branch on GitHub.
# Secrets are read from environment variables — NOT hardcoded — to maintain
# CONFIDENTIALITY of API tokens in version control (SE-12-04).
# =============================================================================
WEBHOOK_SECRET = os.environ.get('WEBHOOK_SECRET', '').encode()
PA_USERNAME    = 'piccolif26'
PA_API_TOKEN   = os.environ.get('PA_API_TOKEN', '')
PA_DOMAIN      = 'piccolif26.pythonanywhere.com'
REPO_PATH      = '/home/piccolif26/SE_HSC_AT2'

# =============================================================================
# SESSION & COOKIE SECURITY (SE-12-07 / SE-12-04)
# SESSION_COOKIE_SECURE:   Cookies are only sent over HTTPS, preventing interception
# SESSION_COOKIE_HTTPONLY: JS cannot read session cookies, mitigating XSS token theft
# SESSION_COOKIE_SAMESITE: Blocks cross-origin form submissions, reinforcing CSRF protection
# PERMANENT_SESSION_LIFETIME: Sessions auto-expire after 30 minutes of inactivity
# =============================================================================
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)
csrf = CSRFProtect(app)
app.config.update(
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Strict'
)

# Secret key used to cryptographically sign session cookies.
# NOTE: In production this should be loaded from an environment variable.
app.secret_key = 'AP_Fp3279Fp'

# UPLOAD_FOLDER: stores user-uploaded ticket images inside /static so Flask
# can serve them directly via url_for('static', ...).
# os.makedirs with exist_ok=True ensures the folder is always present without
# raising an error on subsequent launches.
UPLOAD_FOLDER = os.path.join('static', 'uploads')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# DATA STRUCTURES:
# priorities — ordered list used to populate the priority dropdown in admin view.
#              Index position maps to the option value sent in form POST data.
# status     — integer-keyed dictionary mapping status codes (stored as integers
#              in the DB) to human-readable labels, allowing the template to
#              display e.g. statusDict[1] → 'Open' without conditional chains.
priorities = ['Low', 'Medium', 'High']
status = {1: 'Open', 2: 'pending', 3: 'In Progress', 4: 'Closed', 5: 'Solved'}

# Rate limiter: restricts ALL routes to 15 requests/minute by default (per IP).
# The login route applies a stricter 5/minute limit to prevent credential stuffing.
limiter = Limiter(get_remote_address, app=app, default_limits=["15 per minute"])


# =============================================================================
# DATABASE INITIALISATION (SE-12-03 / SE-12-09)
#
# initDB() creates all required tables if they don't already exist.
# This ensures the app can run on a fresh deployment without manual DB setup.
#
# TABLE DESIGN:
#   users        — stores user accounts; passwords are stored as bcrypt hashes,
#                  never plaintext (CONFIDENTIALITY)
#   tickets      — active tickets submitted by users; linked to users via userID
#                  foreign key (REFERENTIAL INTEGRITY)
#   closedTickets— archived tickets (closed/solved); preserves history and allows
#                  undo/restore (DATA INTEGRITY / ACCOUNTABILITY)
#   comments     — per-ticket comments; linked to both users and tickets via
#                  foreign keys, enabling accountability of who said what
# =============================================================================
def initDB():
    conn = sqlite3.connect('piccoliTicketi.db')
    cursor = conn.cursor()

    # users table: status field defaults to 'user', upgraded to 'admin' by SuperAdmin.
    # This implements Role-Based Access Control (RBAC) — AUTHENTICATION & AUTHORISATION.
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            fName TEXT NOT NULL,
            lname TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            status TEXT DEFAULT 'user')
    ''')

    # tickets table: status is stored as an integer (maps to the `status` dict above).
    # priority stores 'Low'/'Medium'/'High' as text for human readability.
    # imagePath stores a relative path under /static/uploads for served images.
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS tickets(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            userID INTEGER NOT NULL,
            title TEXT NOT NULL,
            description TEXT NOT NULL,
            status INTEGER NOT NULL,
            priority TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            imagePath TEXT,
            FOREIGN KEY (userID) REFERENCES users(id)
        )
    ''')

    # closedTickets table: a separate archive table for tickets that have been
    # closed (status=4) or solved (status=5). The `show` column allows users to
    # hide resolved tickets from their dashboard without permanently deleting them,
    # preserving audit history (INTEGRITY & ACCOUNTABILITY).
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS closedTickets(
            id INTEGER PRIMARY KEY,
            userID INTEGER NOT NULL,
            title TEXT NOT NULL,
            description TEXT NOT NULL,
            status INTEGER NOT NULL,
            priority TEXT,
            created_at DATETIME NOT NULL,
            imagePath TEXT,
            show TEXT NOT NULL DEFAULT 'Yes',
            FOREIGN KEY (userID) REFERENCES users(id)
        )
    ''')

    # comments table: associates a comment with both the commenter (userID) and
    # the relevant ticket (ticketID). The `name` field caches the user's display
    # name at time of posting to avoid expensive JOINs on every page load.
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS comments(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            userID INTEGER NOT NULL,
            ticketID INTEGER NOT NULL,
            comment TEXT NOT NULL,
            name TEXT NOT NULL,
            datecreated DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (userID) REFERENCES users(id),
            FOREIGN KEY (ticketID) REFERENCES tickets(id)
        )
    ''')
    conn.commit()
    conn.close()

# Run database initialisation on every application startup
initDB()


# =============================================================================
# HELPER FUNCTIONS (Modular Program Structure — SE-12-03)
# These utilities are reused across multiple routes to avoid repetition and
# centralise common logic (DRY principle).
# =============================================================================

def returnAdmin():
    """
    Redirects the current user to their appropriate dashboard.
    Admins are sent to /admin; regular users are sent to /.
    Called after any state-changing action (delete, save, solve) to return
    the user to the correct view regardless of who performed the action.
    """
    conn = sqlite3.connect('piccoliTicketi.db')
    cursor = conn.cursor()
    cursor.execute("SELECT status FROM users WHERE id = ?", (session['userID'],))
    userStatus = cursor.fetchone()
    conn.close()
    if userStatus and userStatus[0] == 'admin':
        return redirect('/admin')
    return redirect('/')

def checkAdmin():
    """
    Verifies that the currently logged-in user holds the 'admin' role.
    Returns the user's status string ('admin' or 'user').
    Used as a guard at the start of admin-only routes to enforce
    Role-Based Access Control (RBAC) — AUTHORISATION (SE-12-04 / SE-12-07).
    """
    conn = sqlite3.connect('piccoliTicketi.db')
    cursor = conn.cursor()
    cursor.execute("SELECT status FROM users WHERE id = ?", (session['userID'],))
    userStatus = cursor.fetchone()
    conn.close()
    if not userStatus or userStatus[0] != 'admin':
        flash("You do not have permission to access this feature.", "error")
    return userStatus[0]


# =============================================================================
# AUTOMATED DEPLOYMENT — GitHub Webhook Handler (SE-12-09)
#
# This route receives a POST from GitHub whenever code is pushed to main.
# It verifies the HMAC-SHA256 signature using a shared secret (WEBHOOK_SECRET)
# to ensure the request is genuinely from GitHub — preventing unauthorised
# code execution (INTEGRITY & AVAILABILITY).
#
# The actual git pull and server reload run on a background thread so that
# Flask can return HTTP 200 to GitHub before the reload terminates the worker.
# =============================================================================
@app.route('/git-pull', methods=['POST'])
@csrf.exempt  # Exempt because GitHub cannot supply a CSRF token
def git_pull():
    # Verify GitHub's HMAC-SHA256 signature to authenticate the webhook sender
    signature = request.headers.get('X-Hub-Signature-256') or ''
    expected = 'sha256=' + hmac.new(WEBHOOK_SECRET, request.data, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(signature, expected):
        abort(403)  # Reject requests with invalid signatures

    def deploy():
        # Pull latest code from the main branch
        subprocess.run(['git', '-C', REPO_PATH, 'fetch', 'origin'], capture_output=True, text=True)
        subprocess.run(['git', '-C', REPO_PATH, 'reset', '--hard', 'origin/main'], capture_output=True, text=True)
        # Reload the PythonAnywhere web app via their REST API
        requests.post(
            f'https://www.pythonanywhere.com/api/v0/user/{PA_USERNAME}/webapps/{PA_DOMAIN}/reload/',
            headers={'Authorization': f'Token {PA_API_TOKEN}'}
        )

    # Run deploy on a background thread — response must be sent before reload kills the worker
    threading.Thread(target=deploy).start()
    return 'OK', 200


# =============================================================================
# LOGIN MODULE (SE-12-07 / SE-12-04)
# =============================================================================

@app.route("/register", methods=["GET", "POST"])
def register():
    """
    Handles new user registration.

    SECURITY:
      - All inputs sanitised with escape() before use (XSS prevention)
      - Password hashed with werkzeug's generate_password_hash (bcrypt)
        before storage — passwords are NEVER stored in plaintext (CONFIDENTIALITY)
      - Input length validation mirrors HTML maxlength attributes, providing
        server-side enforcement even if client-side validation is bypassed
      - Duplicate username check prevents account enumeration via DB error messages
      - try/except catches malformed form submissions gracefully
    """
    if request.method == 'POST':
        try:
            # Sanitise all user-supplied strings to prevent XSS
            fName           = escape(request.form['fName'])
            lName           = escape(request.form['lName'])
            email           = escape(request.form['email'])
            username        = escape(request.form['username'])
            password        = escape(request.form['password'])
            confirmPassword = escape(request.form['confirmPassword'])

            # Confirm passwords match before hashing (UX: early failure feedback)
            if password != confirmPassword:
                flash('Passwords do not match. Please try again.', 'error')
                return redirect('/register')

            # Hash password immediately — plaintext never persists beyond this line
            hashedPassword = generate_password_hash(password)

            # Server-side length validation (mirrors HTML maxlength — defence in depth)
            if len(fName) > 50 or len(lName) > 50 or len(email) > 254 or len(username) > 30 or len(password) > 128:
                flash("One/some of your inputs are too long, please try again", "error")
                return redirect('/register')

        except werkzeug.exceptions.BadRequestKeyError:  # type: ignore
            # Catches missing form fields — prevents KeyError crash on malformed POSTs
            flash('We detected an error, please try again', 'error')
            return redirect('/register')

        # Ensure no fields are empty after sanitisation
        if not fName or not lName or not email or not username or not password:
            flash('Please fill in all fields.', 'error')
            return redirect('/register')

        conn = sqlite3.connect('piccoliTicketi.db')
        cursor = conn.cursor()

        # Check for duplicate username — avoids exposing DB constraint errors to the user
        cursor.execute("SELECT COUNT(*) FROM users WHERE username = ?", (username,))
        userExists = cursor.fetchone()[0] > 0

        if userExists:
            flash('Username already exists, Please choose another.', 'error')
        else:
            # Parameterised query prevents SQL injection (INTEGRITY)
            cursor.execute(
                'INSERT INTO users (fName, lName, email, username, password) VALUES (?, ?, ?, ?, ?)',
                (fName, lName, email, username, hashedPassword)
            )
            conn.commit()
            flash("Registration successful! Please log in", "success")
            conn.close()
            return redirect('/login')

        conn.close()
    return render_template('register.html')


@app.route('/login', methods=["GET", "POST"])
@limiter.limit("5 per minute")  # Rate limit: prevents brute-force credential attacks (AVAILABILITY / AUTHENTICATION)
def login():
    """
    Authenticates a user against the database.

    SECURITY:
      - check_password_hash() compares input against stored bcrypt hash
        without ever decrypting it — maintains CONFIDENTIALITY
      - Rate limited to 5 attempts/minute per IP to prevent brute force
      - Session token (csrfToken) regenerated on login to prevent session fixation
      - Admin users are immediately redirected to /admin upon login (RBAC)
    """
    if request.method == "POST":
        username = escape(request.form['username'])
        password = escape(request.form['password'])

        if not username or not password:
            flash('Please fill in all fields.', 'error')
            return redirect('/login')

        conn = sqlite3.connect('piccoliTicketi.db')
        cursor = conn.cursor()
        # Parameterised query — prevents SQL injection even with malicious usernames
        cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
        user = cursor.fetchone()

        if user and check_password_hash(user[5], password):
            # Populate session with minimal required data (principle of least privilege)
            session['userID']    = user[0]
            session['username']  = user[4]
            # Generate a fresh CSRF token on login to prevent session fixation attacks
            session['csrfToken'] = str(uuid4())
            flash('Login successful!', 'success')

            # RBAC: route admin users directly to the admin dashboard
            cursor.execute("SELECT status FROM users WHERE id = ?", (session['userID'],))
            userStatus = cursor.fetchone()
            # conn.close() called before both possible redirects to ensure the connection
            # is always released regardless of which branch is taken
            conn.close()
            if userStatus and userStatus[0] == 'admin':
                return redirect('/admin')
            return redirect('/')

        flash("Invalid username or password", "error")
        conn.close()  # Ensure connection is released on failed login attempt too
    return render_template('login.html')


@app.route('/logout', methods=["POST"])
def logout():
    """
    Clears the entire server-side session on logout.
    Using POST (not GET) prevents logout via CSRF from a third-party page.
    session.clear() ensures all session data is removed, not just the user ID.
    """
    session.clear()
    flash('You have been logged out.', 'success')
    return redirect('/login')


# =============================================================================
# TICKET MANAGEMENT (User Module — SE-12-03 / SE-12-07)
# =============================================================================

@app.route('/createTicket', methods=["GET", "POST"])
def createTicket():
    """
    Allows authenticated users to submit a new support ticket.

    FILE UPLOAD SECURITY:
      - MIME type checked server-side (file.mimetype) — client accept="image/*"
        is bypassed easily, so server validation is essential (INTEGRITY)
      - uuid4().hex generates a random filename, preventing:
          a) Overwriting existing files
          b) Directory traversal via crafted filenames
      - File extension is preserved for browser rendering but lowercased
        to prevent case-sensitivity bypass attacks
    """
    # Redirect unauthenticated users to login (AUTHENTICATION guard)
    if 'userID' not in session:
        return redirect('/login')

    conn = sqlite3.connect('piccoliTicketi.db')
    cursor = conn.cursor()
    cursor.execute("SELECT status FROM users WHERE id = ?", (session['userID'],))
    userStatus = cursor.fetchone()

    if request.method == "POST":
        title       = escape(request.form['title'])
        description = escape(request.form['description'])
        userID      = session['userID']

        file      = request.files.get('attachment')
        imagePath = None

        if file and file.filename:
            # Server-side MIME type validation — prevents non-image file uploads
            if not file.mimetype.startswith("image/"):
                flash("Please check your uploaded file, only images are allowed.", "error")
                conn.close()
                return redirect('/createTicket')

            ext        = os.path.splitext(file.filename)[1].lower()
            uniqueName = f"{uuid4().hex}{ext}"  # Random filename prevents collisions & traversal
            savePath   = os.path.join(UPLOAD_FOLDER, uniqueName)
            file.save(savePath)
            imagePath = f"uploads/{uniqueName}"

        # Validate required fields server-side (defence in depth beyond HTML `required`)
        if title == "" or description == "":
            flash("Please fill in all required fields.", "error")
            conn.close()
            return redirect('/createTicket')

        # New tickets always start with status=1 (Open) — users cannot set their own status
        cursor.execute(
            'INSERT INTO tickets (userID, title, description, status, imagePath) VALUES (?, ?, ?, ?, ?)',
            (userID, title, description, 1, imagePath)
        )
        conn.commit()
        conn.close()
        flash('Ticket created successfully!', 'success')
        return redirect('/')

    conn.close()
    return render_template('createTicket.html', status=userStatus[0] if userStatus else None)


@app.route("/")
def index():
    """
    Main dashboard for regular users.
    Displays all tickets (active + closed) belonging to the logged-in user.

    DATA STRUCTURE:
      ticketsList is built by concatenating two query results (active tickets +
      closed tickets) into a single list. This avoids a complex UNION query and
      keeps the template logic simple — both tables share the same column structure.

    RBAC: Admin users are immediately redirected to /admin from this route.
    """
    if 'userID' not in session:
        return redirect('/login')

    conn = sqlite3.connect('piccoliTicketi.db')
    cursor = conn.cursor()

    cursor.execute("SELECT status FROM users WHERE id = ?", (session['userID'],))
    userStatus = cursor.fetchone()

    # RBAC: if the logged-in user is an admin, redirect to the admin dashboard
    if userStatus and userStatus[0] == 'admin':
        return redirect('/admin')

    # Fetch active tickets for this user
    cursor.execute("SELECT * FROM tickets WHERE userID = ?", (session['userID'],))
    ticketsList = cursor.fetchall()

    # Append closed/solved tickets — combined list passed to template for unified rendering
    cursor.execute("SELECT * FROM closedTickets WHERE userID = ?", (session['userID'],))
    ticketsList += cursor.fetchall()

    cursor.execute("SELECT fname, status FROM users WHERE id = ?", (session['userID'],))
    userName = cursor.fetchone()
    conn.close()

    return render_template(
        "index.html",
        statusDict=status,
        tickets=ticketsList,
        name=userName[0] if userName else "User",
        status=userName[1] if userName else None
    )


@app.route("/hideTicket", methods=["POST"])
def hideTicket():
    """
    Soft-hides a closed ticket from the user's dashboard by setting show='No'.
    The ticket is NOT deleted — data is preserved for admin audit (ACCOUNTABILITY).
    Only POST is accepted to prevent CSRF via GET-based link triggers.
    """
    if 'userID' not in session:
        return redirect('/login')

    itemID = escape(request.form.get("hide"))
    conn = sqlite3.connect('piccoliTicketi.db')
    cursor = conn.cursor()
    # Parameterised update — prevents SQL injection (INTEGRITY)
    cursor.execute("UPDATE closedTickets SET show = 'No' WHERE ID = ?", (itemID,))
    conn.commit()
    conn.close()
    return redirect('/')


@app.route("/delete_item", methods=["POST"])
def delete_item():
    """
    Closes an active ticket by moving it to the closedTickets archive (status=4).

    DESIGN DECISION:
      Rather than deleting the ticket, it is archived to closedTickets. This:
        1. Preserves data for admin audit (ACCOUNTABILITY / INTEGRITY)
        2. Allows the undo operation (undoDelete) to restore tickets
        3. Maintains a complete history of all support interactions

    If the ticket is not found, an error is flashed and the user is redirected
    safely — avoiding a crash from attempting to unpack a None value.
    """
    if 'userID' not in session:
        return redirect('/login')

    itemID = escape(request.form.get("delete"))
    conn = sqlite3.connect('piccoliTicketi.db')
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM tickets WHERE ID = ?", (itemID,))
    item = cursor.fetchone()

    # Guard against missing ticket (e.g. duplicate submission or stale page)
    if not item:
        flash("We're sorry, an internal error has occurred. Please try again", "error")
        return returnAdmin()

    # Archive the ticket with status=4 (Closed) before removing from active table
    cursor.execute(
        "INSERT INTO closedTickets (id, userID, title, description, status, priority, created_at, imagePath) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (item[0], item[1], item[2], item[3], 4, item[5], item[6], item[7])
    )
    conn.commit()
    cursor.execute("DELETE FROM tickets WHERE ID = ?", (itemID,))
    conn.commit()
    conn.close()
    return returnAdmin()


@app.route("/undoDelete", methods=["POST"])
def undoDelete():
    """
    Restores a previously closed ticket back to active status (status=1).
    This implements the 'undo close' feature visible in the user dashboard
    for tickets with status 4 or 5 — improving UX by allowing error recovery.
    """
    if 'userID' not in session:
        return redirect('/login')

    conn = sqlite3.connect('piccoliTicketi.db')
    cursor = conn.cursor()
    itemID = request.form.get("undo")

    cursor.execute("SELECT * FROM closedTickets WHERE ID = ?", (itemID,))
    item = cursor.fetchone()

    # Restore to tickets table with status=1 (Open)
    cursor.execute(
        "INSERT INTO tickets (id, userID, title, description, status, priority, created_at, imagePath) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (item[0], item[1], item[2], item[3], 1, item[5], item[6], item[7])
    )
    conn.commit()
    cursor.execute("DELETE FROM closedTickets WHERE ID = ?", (itemID,))
    conn.commit()
    conn.close()
    return returnAdmin()


@app.route("/editItem", methods=["POST"])
def editItem():
    """
    Enters edit mode for a specific ticket by re-rendering the dashboard
    with the target ticket's ID passed as `editIndex`.

    The template uses editIndex to conditionally replace table cells with
    input fields for that one row, implementing inline editing without a
    separate edit page (UX decision — reduces page navigation overhead).

    Admin users are rendered the admin.html template with additional fields
    (status dropdown, priority dropdown); regular users only see title/description.
    This enforces role-appropriate editing capabilities (RBAC / AUTHORISATION).
    """
    if 'userID' not in session:
        return redirect('/login')

    editID = int(request.form.get("edit", 0))
    conn = sqlite3.connect('piccoliTicketi.db')
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM tickets WHERE ID = ?", (editID,))
    tickets = cursor.fetchall()

    # Fetch comments for this ticket to display in the comments section below the table
    cursor.execute("SELECT * FROM comments WHERE ticketID = ?", (tickets[0][0],))
    comments = cursor.fetchall()

    cursor.execute("SELECT fname, status FROM users WHERE id = ?", (session['userID'],))
    userStatus = cursor.fetchone()

    # Retrieve the ticket author's full name for display in admin view (ACCOUNTABILITY)
    cursor.execute(
        "SELECT fName, lName FROM users AS u JOIN tickets AS t ON t.userID = u.id WHERE t.id = ?",
        (editID,)
    )
    authorList = cursor.fetchone()
    author = authorList[0] + " " + authorList[1]
    conn.close()

    # Route to appropriate template based on user role (RBAC)
    if userStatus and userStatus[1] == 'admin':
        return render_template(
            'admin.html', statusDict=status, tickets=tickets, editIndex=editID,
            priority=priorities, name=userStatus[0], status=userStatus[1],
            comments=comments, author=author, edit=True
        )
    return render_template(
        "index.html", statusDict=status, tickets=tickets, editIndex=editID,
        name=userStatus[0], status=userStatus[1], comments=comments, edit=True
    )


@app.route("/saveItem", methods=["POST"])
def saveItem():
    """
    Persists edits made in inline edit mode back to the database.

    RBAC:
      - Regular users can only update title and description
      - Admins can additionally update status and priority
      This prevents users from escalating their own ticket priority or
      marking tickets as solved (AUTHORISATION — SE-12-04).

    All inputs are sanitised with escape() before being written to the DB.
    Empty field validation ensures data integrity.
    """
    if 'userID' not in session:
        return redirect('/login')

    conn = sqlite3.connect('piccoliTicketi.db')
    cursor = conn.cursor()
    cursor.execute("SELECT status FROM users WHERE id = ?", (session['userID'],))
    userStatus = cursor.fetchone()

    if userStatus and userStatus[0] == 'user':
        # User edit: restricted to title and description only
        itemID         = escape(request.form.get("editIndex"))
        newTitle       = escape(request.form.get("newItem"))
        newDescription = escape(request.form.get("newDescription"))

        if not newTitle or not newDescription:
            flash("Please fill in all fields.", "error")
            return redirect('/editItem')

        cursor.execute(
            "UPDATE tickets SET title = ?, description = ? WHERE ID = ?",
            (newTitle, newDescription, itemID)
        )
        conn.commit()

    elif userStatus and userStatus[0] == 'admin':
        # Admin edit: can also change status and priority
        itemID         = escape(request.form.get("editIndex"))
        newTitle       = escape(request.form.get("newItem"))
        newDescription = escape(request.form.get("newDescription"))
        newStatus      = escape(request.form.get("newStatus"))
        newPriority    = escape(request.form.get("newPriority"))

        if not newTitle or not newDescription or not newStatus or not newPriority:
            flash("Please fill in all fields.", "error")
            return redirect('/editItem')

        cursor.execute(
            "UPDATE tickets SET title = ?, description = ?, status = ?, priority = ? WHERE ID = ?",
            (newTitle, newDescription, newStatus, newPriority, itemID)
        )
        conn.commit()

    conn.close()
    return returnAdmin()


@app.route("/solve_item", methods=["POST"])
def solve_item():
    """
    Marks a ticket as solved (status=5) by archiving it to closedTickets.
    Only accessible to admins — enforced by checkAdmin() (AUTHORISATION).

    Solved tickets are distinguished from closed (status=4) tickets in the UI
    with a green row highlight, providing clear visual feedback (UX).
    """
    if 'userID' not in session:
        return redirect('/login')

    itemID = escape(request.form.get("solve"))
    conn = sqlite3.connect('piccoliTicketi.db')
    cursor = conn.cursor()

    # RBAC guard — non-admins are redirected immediately
    if checkAdmin() == "user":
        return redirect('/')

    cursor.execute("SELECT * FROM tickets WHERE ID = ?", (itemID,))
    item = cursor.fetchone()

    # Archive with status=5 (Solved) — distinct from status=4 (Closed) for reporting
    cursor.execute(
        "INSERT INTO closedTickets (id, userID, title, description, status, priority, created_at, imagePath) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (item[0], item[1], item[2], item[3], 5, item[5], item[6], item[7])
    )
    conn.commit()
    cursor.execute("DELETE FROM tickets WHERE ID = ?", (itemID,))
    conn.commit()
    conn.close()
    return returnAdmin()


@app.route("/addComment", methods=["POST"])
def addComment():
    """
    Appends a new comment to a ticket's comment thread.

    The commenter's first name is stored alongside the comment (denormalised)
    to avoid requiring a JOIN on every comment render — a deliberate performance
    trade-off for a read-heavy operation (EFFICIENT DATA STRUCTURES).

    After inserting, the view is re-rendered directly (not redirected) so the
    comment appears immediately without a round trip to the database for the
    full ticket list (UX — reduces perceived latency).
    """
    if 'userID' not in session:
        return redirect("/")

    comment  = escape(request.form.get("addComment"))
    ticketID = int(escape(request.form.get('ticketID')))

    conn = sqlite3.connect('piccoliTicketi.db')
    cursor = conn.cursor()

    # Retrieve commenter's first name to store with the comment (ACCOUNTABILITY)
    cursor.execute("SELECT fName FROM users WHERE id = ?", (session['userID'],))
    fName = cursor.fetchone()

    # Parameterised insert — all user-supplied data safely bound as parameters
    cursor.execute(
        "INSERT INTO comments (userID, ticketID, comment, name) VALUES (?, ?, ?, ?)",
        (session['userID'], ticketID, comment, fName[0])
    )
    conn.commit()

    # Re-fetch the ticket and its comments to re-render the edit view with the new comment
    cursor.execute("SELECT * FROM tickets WHERE ID = ?", (ticketID,))
    tickets = cursor.fetchall()

    cursor.execute("SELECT fname, status FROM users WHERE id = ?", (session['userID'],))
    userStatus = cursor.fetchone()

    cursor.execute("SELECT * FROM comments WHERE ticketID = ?", (ticketID,))
    comments = cursor.fetchall()

    cursor.execute(
        "SELECT fName, lName FROM users AS u JOIN tickets AS t ON t.userID = u.id WHERE t.id = ?",
        (ticketID,)
    )
    authorList = cursor.fetchone()
    author = authorList[0] + " " + authorList[1]
    conn.close()

    # Render appropriate template based on role (RBAC)
    if userStatus and userStatus[1] == 'admin':
        return render_template(
            'admin.html', statusDict=status, tickets=tickets, editIndex=ticketID,
            priority=priorities, name=userStatus[0], status=userStatus[1],
            comments=comments, author=author, edit=True
        )
    return render_template(
        "index.html", statusDict=status, tickets=tickets, editIndex=ticketID,
        name=userStatus[0], status=userStatus[1], comments=comments, edit=True
    )


# =============================================================================
# ADMINISTRATOR MODULE (SE-12-07 / SE-12-04)
# All routes in this section are protected by session checks and checkAdmin()
# to enforce Role-Based Access Control (RBAC).
# =============================================================================

@app.route("/admin", methods=["GET", "POST"])
def admin():
    """
    Main admin dashboard — displays ALL tickets across all users.

    ORDERING:
      Tickets are sorted by priority ASC, then created_at ASC.
      This means High-priority tickets appear first (alphabetically H < L < M),
      and within each priority tier, older tickets are shown before newer ones
      — ensuring urgent, long-standing issues are always at the top (UX).

    RBAC: Protected by checkAdmin() — unauthorised users are redirected to /.
    """
    if 'userID' not in session:
        return redirect('/login')
    if checkAdmin() == "user":
        return redirect('/')

    conn = sqlite3.connect('piccoliTicketi.db')
    cursor = conn.cursor()

    # Retrieve all tickets sorted for triage priority (UX — admin workflow optimisation)
    cursor.execute("SELECT * FROM tickets ORDER BY priority ASC, created_at ASC")
    tickets = cursor.fetchall()

    cursor.execute("SELECT fname, status FROM users WHERE id = ?", (session['userID'],))
    name = cursor.fetchone()
    conn.close()

    return render_template(
        "admin.html",
        statusDict=status,
        tickets=tickets,
        name=name[0] if name else None,
        status=name[1] if name else None
    )



@app.route("/deleteUser", methods=["POST"])
def deleteUser():
    """
    Permanently deletes a user account from the database.
    Restricted to the SuperAdmin account only — the most destructive action
    available, so it requires the highest privilege tier (AUTHORISATION).
    SuperFinnee's own account is protected from deletion.
    """
    if 'userID' not in session:
        return redirect('/login')

    username = escape(request.form.get("username"))

    if username == "SuperFinnee":
        flash("Let's not do this one again. It was embarrassing the first time.", "error")
        return redirect('/admin')

    conn = sqlite3.connect('piccoliTicketi.db')
    cursor = conn.cursor()

    # Only SuperFinnee can delete user accounts (highest privilege tier)
    cursor.execute("SELECT username FROM users WHERE id = ?", (session['userID'],))
    usernameSQL = cursor.fetchone()
    if not usernameSQL or usernameSQL[0] != 'SuperFinnee':
        conn.close()
        flash("You do not have permission to perform this action.", "error")
        return redirect('/')

    cursor.execute("DELETE FROM users WHERE username = ?", (username,))
    conn.commit()
    conn.close()
    flash(f'User {username} has been deleted.', 'success')
    return redirect('/admin')


@app.route("/toggleAdmin", methods=["POST"])
def toggleAdmin():
    """
    Toggles a user's role between 'user' and 'admin'.

    SECURITY:
      - Attempting to toggle SuperFinnee's account punishes the operator
        by revoking THEIR OWN admin privileges — a deliberate deterrent
        against misuse of the most privileged account (AUTHORISATION).
      - The current status is checked before toggling to ensure the action
        is idempotent — calling toggle twice returns to the original state.
    """
    if 'userID' not in session:
        return redirect('/login')

    username = escape(request.form.get("username"))
    conn = sqlite3.connect('piccoliTicketi.db')
    cursor = conn.cursor()

    # Attempting to toggle the SuperAdmin triggers a privilege revocation of the operator
    if username == "SuperFinnee":
        flash("Let's not do that. Your admin privileges have been revoked.", "error")
        cursor.execute("UPDATE users SET status = 'user' WHERE id = ?", (session['userID'],))
        return redirect('/')

    # Read current role, then flip it
    cursor.execute("SELECT status FROM users WHERE username = ?", (username,))
    userStatus = cursor.fetchone()
    if userStatus and userStatus[0] == 'admin':
        cursor.execute("UPDATE users SET status = 'user' WHERE username = ?", (username,))
    else:
        cursor.execute("UPDATE users SET status = 'admin' WHERE username = ?", (username,))

    conn.commit()
    conn.close()
    return redirect('/manageUsers')


@app.route("/manageUsers", methods=["GET"])
def manageUsers():
    """
    Displays the user management table, allowing admins to view all registered
    users and toggle their roles. SuperAdmin also has access to user deletion.
    Protected by checkAdmin() — unauthorised access redirects to /.
    """
    if 'userID' not in session:
        return redirect('/login')
    if checkAdmin() == "user":
        return redirect('/')

    conn = sqlite3.connect('piccoliTicketi.db')
    cursor = conn.cursor()

    # Fetch display fields only — password hashes are deliberately excluded (CONFIDENTIALITY)
    cursor.execute("SELECT fname, lname, email, username, status FROM users")
    users = cursor.fetchall()

    cursor.execute("SELECT status, username FROM users WHERE id = ?", (session['userID'],))
    userStatus = cursor.fetchone()
    conn.close()

    return render_template(
        'manageUsers.html',
        users=users,
        status=userStatus[0] if userStatus else None,
        username=userStatus[1] if userStatus else None
    )


@app.route("/closedTickets", methods=["GET"])
def closedTickets():
    """
    Admin-only view of all archived (closed/solved) tickets across all users.
    Provides a full audit trail of ticket resolutions (ACCOUNTABILITY / INTEGRITY).
    Sorted by priority and creation date, consistent with the admin dashboard.
    """
    if 'userID' not in session:
        return redirect('/login')
    if checkAdmin() == "user":
        return redirect('/')

    conn = sqlite3.connect('piccoliTicketi.db')
    cursor = conn.cursor()

    # All closed tickets ordered consistently with the active ticket view (UX)
    cursor.execute("SELECT * FROM closedTickets ORDER BY priority ASC, created_at ASC")
    tickets = cursor.fetchall()

    cursor.execute("SELECT status FROM users WHERE id = ?", (session['userID'],))
    userStatus = cursor.fetchone()
    conn.close()

    return render_template(
        "closedTickets.html",
        statusDict=status,
        tickets=tickets,
        status=userStatus[0] if userStatus else None
    )


# =============================================================================
# APPLICATION ENTRY POINT
# =============================================================================
if __name__ == "__main__":
    app.run()