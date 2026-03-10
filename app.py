from flask import Flask, render_template, redirect, request, session, flash, url_for, abort
from tabnanny import check
from click import confirm
import sqlite3, os
import werkzeug
from werkzeug.security import generate_password_hash, check_password_hash
from uuid import uuid4
from markupsafe import escape 
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from datetime import timedelta
from bleach import clean
from flask_wtf.csrf import CSRFProtect
import subprocess
import hmac
import hashlib
import requests
import threading

app = Flask(__name__)

# --- CONFIG ---
WEBHOOK_SECRET = os.environ.get('WEBHOOK_SECRET', '').encode()
PA_USERNAME = 'piccolif26'
PA_API_TOKEN = os.environ.get('PA_API_TOKEN', '')
PA_DOMAIN = 'piccolif26.pythonanywhere.com'
REPO_PATH = '/home/piccolif26/SE_HSC_AT2'
#---------


app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)
csrf = CSRFProtect(app)
app.config.update(
    SESSION_COOKIE_SECURE=True, # Enforces HTTPS for session cookies
    SESSION_COOKIE_HTTPONLY=True, # Prevents client-side JS from accessing session cookies
    SESSION_COOKIE_SAMESITE='Strict' # Prevents cross-site request forgery (CSRF)
)

#@app.before_request
#def enforce_https():
#    if not request.is_secure:
#        return redirect(request.url.replace('http://', 'https://'))
        
    
def make_session_permanent():
    session.permanent = True

app.secret_key = 'AP_Fp3279Fp'
UPLOAD_FOLDER = os.path.join('static', 'uploads')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
priorities = ['Low', 'Medium', 'High']
status= {1: 'Open', 2: 'pending', 3: 'In Progress', 4: 'Closed', 5: 'Solved'}

limiter = Limiter(get_remote_address, app=app, default_limits=["5 per minute"])



def initDB():
    conn = sqlite3.connect('piccoliTicketi.db')
    cursor = conn.cursor()
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
    cursor.execute('''
            CREATE TABLE IF NOT EXISTS closedTickets(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
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
    conn.commit()
    conn.close()
    
initDB()

def returnAdmin():
    conn = sqlite3.connect('piccoliTicketi.db')
    cursor = conn.cursor()
    cursor.execute("SELECT status FROM users WHERE id = ?", (session['userID'],))
    userStatus = cursor.fetchone()
    conn.close()
    if userStatus and userStatus[0] == 'admin':
        return redirect('/admin')
    return redirect('/')

def checkAdmin():
    conn = sqlite3.connect('piccoliTicketi.db')
    cursor = conn.cursor()
    cursor.execute("SELECT status FROM users WHERE id = ?", (session['userID'],))
    userStatus = cursor.fetchone()
    if not userStatus or userStatus[0] != 'admin':
        conn.close()
        flash("You do not have permission to acess this feature.", "error")
    return userStatus[0]

@app.route('/git-pull', methods=['POST'])
@csrf.exempt
def git_pull():
    signature = request.headers.get('X-Hub-Signature-256') or ''
    expected = 'sha256=' + hmac.new(WEBHOOK_SECRET, request.data, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(signature, expected):
        abort(403)

    def deploy():
        subprocess.run(['git', '-C', REPO_PATH, 'fetch', 'origin'], capture_output=True, text=True)
        subprocess.run(['git', '-C', REPO_PATH, 'reset', '--hard', 'origin/main'], capture_output=True, text=True)
        requests.post(
            f'https://www.pythonanywhere.com/api/v0/user/{PA_USERNAME}/webapps/{PA_DOMAIN}/reload/',
            headers={'Authorization': f'Token {PA_API_TOKEN}'}
        )

    threading.Thread(target=deploy).start()
    return 'OK', 200  # GitHub gets this before the reload kills the worker

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == 'POST':
        try:
            fName = escape(request.form['fName'])
            lName = escape(request.form['lName'])
            email = escape(request.form['email'])
            username = escape(request.form['username'])
            password = escape(request.form['password'])
            confirmPassword = escape(request.form['confirmPassword'])
            if password != confirmPassword:
                flash('Passwords do not match. Please try again.', 'error')
                return redirect('/register')
            hashedPassword = generate_password_hash(password)
        except werkzeug.exceptions.BadRequestKeyError: # type: ignore
            flash(f'We detected an error, please try again', 'error')
            return redirect('/register')
        
        if not fName or not lName or not email or not username or not password:
            flash('Please fill in all fields.', 'error')
            return redirect('/register')
        
        conn = sqlite3.connect('piccoliTicketi.db')
        cursor = conn.cursor()
        #Check if username already exists
        cursor.execute("SELECT COUNT(*) FROM users WHERE username = ?", (username,))
        userExists = cursor.fetchone()[0] > 0
        
        if userExists:
            flash('Username already exists, Please choose another.', 'error')
        else:
            #Insert new user
            cursor.execute('INSERT INTO users (fName, lName, email, username, password) values (?, ?, ?, ?, ?)', (fName, lName, email, username, hashedPassword))
            conn.commit()
            flash("Registration successful! Please log in", "success")
            conn.close()
            return redirect('/login')
        
        conn.close()
    return render_template('register.html')

@app.route('/login', methods=["GET", "POST"])
@limiter.limit("5 per minute")
def login():
    if request.method == "POST":
        username = escape(request.form['username'])
        password = escape(request.form['password'])
        if not username or not password:
            flash('Please fill in all fields.', 'error')
            return redirect('/login')
        conn = sqlite3.connect('piccoliTicketi.db')
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
        user = cursor.fetchone()
        if user and check_password_hash(user[5], password):
            session['userID'] = user[0]
            session['username'] = user[4]
            session['csrfToken'] = str(uuid4())
            flash('Login successful!', 'success')
            cursor.execute("SELECT status FROM users WHERE id = ?", (session['userID'],))
            userStatus = cursor.fetchone()
            if userStatus and userStatus[0] == 'admin':
                conn.close()
                return redirect('/admin')
            conn.close()
            return redirect('/')
        flash ("Invalid username or password", "error")
    return render_template('login.html')

@app.route('/logout', methods=["POST"])
def logout():
    session.clear()
    flash('You have been logged out.', 'success')
    return redirect('/login')

@app.route('/createTicket', methods=["GET", "POST"])
def createTicket():
    if 'userID' not in session:
        return redirect('/login')
    
    conn = sqlite3.connect('piccoliTicketi.db')
    cursor = conn.cursor()
    cursor.execute("SELECT status FROM users WHERE id = ?", (session['userID'],))
    userStatus = cursor.fetchone()
    
    if request.method == "POST":
        title = escape(request.form['title'])
        description = escape(request.form['description'])
        userID = session['userID']
        
        file = request.files.get('attachment')
        imagePath = None
        
        if file and file.filename:
            if not file.mimetype.startswith("image/"):
                flash("Please check your uploaded file, only images are allowed.", "error")
                conn.close()
                return redirect('/createTicket')
            
            ext = os.path.splitext(file.filename)[1].lower()
            uniqueName = f"{uuid4().hex}{ext}"
            
            savePath = os.path.join(UPLOAD_FOLDER, uniqueName)
            file.save(savePath)
            imagePath = f"uploads/{uniqueName}"
        
        if title == "" or description == "":
            flash("Please fill in all required fields.", "error")
            conn.close()
            return redirect('/createTicket')
        
        cursor.execute('INSERT INTO tickets (userID, title, description, status, imagePath) values (?, ?, ?, ?, ?)', (userID, title, description, 1, imagePath))
        conn.commit()
        conn.close()
        
        flash('Ticket created successfully!', 'success')
        return redirect('/')
    
    conn.close()
    return render_template('createTicket.html', status=userStatus[0] if userStatus else None)

@app.route("/")
def index():    
    if 'userID' not in session:
        return redirect('/login')
    conn = sqlite3.connect('piccoliTicketi.db')
    cursor = conn.cursor()
    cursor.execute("SELECT status FROM users WHERE id = ?", (session['userID'],))
    userStatus = cursor.fetchone()
    if userStatus and userStatus[0] == 'admin':
        return redirect('/admin')
    
    cursor.execute("SELECT * FROM tickets WHERE userID = ?", (session['userID'],))
    ticketsList = cursor.fetchall()
    cursor.execute("SELECT * FROM closedTickets WHERE userID = ?", (session['userID'],))
    ticketsList += cursor.fetchall()
    cursor.execute("SELECT fname, status FROM users WHERE id = ?", (session['userID'],))
    userName = cursor.fetchone()
    conn.close()
    return render_template("index.html", statusDict=status, tickets=ticketsList, name=userName[0] if userName else "User", status=userName[1] if userName else None)

@app.route("/hideTicket", methods=["POST"])
def hideTicket():
    if 'userID' not in session:
        return redirect('/login')
    itemID = escape(request.form.get("hide"))
    conn = sqlite3.connect('piccoliTicketi.db')
    cursor = conn.cursor()
    cursor.execute("UPDATE closedTickets SET show = 'No' WHERE ID = ?", (itemID,))
    conn.commit()
    conn.close()
    return redirect('/')

@app.route("/delete_item", methods=["POST"])
def delete_item():
    if 'userID' not in session:
        return redirect('/login')
    itemID = escape(request.form.get("delete"))
    conn = sqlite3.connect('piccoliTicketi.db')
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM tickets WHERE ID = ?", (itemID,))
    item = cursor.fetchone()
    cursor.execute("INSERT INTO closedTickets (userID, title, description, status, priority, created_at, imagePath) VALUES (?, ?, ?, ?, ?, ?, ?)", (item[1], item[2], item[3], 4, item[5], item[6], item[7]))
    conn.commit()
    cursor.execute("DELETE FROM tickets WHERE ID = ?", (itemID,))
    conn.commit()
    conn.close()
    return returnAdmin()

@app.route("/undoDelete", methods=["POST"])
def undoDelete():
    if 'userID' not in session:
        return redirect('/login')
    conn = sqlite3.connect('piccoliTicketi.db')
    cursor = conn.cursor()
    itemID = request.form.get("undo")
    cursor.execute("SELECT * FROM closedTickets WHERE ID = ?", (itemID,))
    item = cursor.fetchone()
    cursor.execute("INSERT INTO tickets (userID, title, description, status, priority, created_at, imagePath) VALUES (?, ?, ?, ?, ?, ?, ?)", (item[1], item[2], item[3], 1, item[5], item[6], item[7]))
    conn.commit()
    cursor.execute("DELETE FROM closedTickets WHERE ID = ?", (itemID,))
    conn.commit()
    conn.close()
    return returnAdmin()

@app.route("/editItem", methods=["POST"])
def editItem():
    if 'userID' not in session:
        return redirect('/login')
    #global editIndex
    editID = int(request.form.get("edit", 0))
    conn = sqlite3.connect('piccoliTicketi.db')
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM tickets WHERE ID = ?", (editID,))
    tickets = cursor.fetchall()
    conn.close()
    conn = sqlite3.connect('piccoliTicketi.db')
    cursor = conn.cursor()
    cursor.execute("SELECT fname, status FROM users WHERE id = ?", (session['userID'],))
    userStatus = cursor.fetchone()
    conn.close()
    print(tickets[0], editID)
    if userStatus and userStatus[1] == 'admin':
        return render_template('admin.html', statusDict=status, tickets=tickets, editIndex=editID, priority=priorities, name=userStatus[0] if userStatus else None, status=userStatus[1] if userStatus else None)
    return render_template("index.html", statusDict=status, tickets=tickets, editIndex=editID, name=userStatus[0] if userStatus else None, status=userStatus[1] if userStatus else None)

@app.route("/saveItem", methods=["POST"])
def saveItem():
    if 'userID' not in session:
        return redirect('/login')
    conn = sqlite3.connect('piccoliTicketi.db')
    cursor = conn.cursor()
    cursor.execute("SELECT status FROM users WHERE id = ?", (session['userID'],))
    userStatus = cursor.fetchone()
    if userStatus and userStatus[0] == 'user':
        itemID = escape(request.form.get("editIndex"))
        newTitle = escape(request.form.get("newItem"))
        newDescription = escape(request.form.get("newDescription"))
        if not newTitle or not newDescription:
            flash("Please fill in all fields.", "error")
            return redirect('/editItem')
        cursor.execute("UPDATE tickets SET title = ?, description = ? WHERE ID = ?",(newTitle, newDescription, itemID))
        conn.commit()
    elif userStatus and userStatus[0] == 'admin':
        itemID = escape(request.form.get("editIndex"))
        newTitle = escape(request.form.get("newItem"))
        newDescription = escape(request.form.get("newDescription"))
        newStatus = escape(request.form.get("newStatus"))
        newPriority = escape(request.form.get("newPriority"))
        if not newTitle or not newDescription or not newStatus or not newPriority:
            flash("Please fill in all fields.", "error")
            return redirect('/editItem')
        cursor.execute("UPDATE tickets SET title = ?, description = ?, status = ?, priority = ? WHERE ID = ?",(newTitle, newDescription, newStatus, newPriority, itemID))
        conn.commit()
        
    conn.close()
    return returnAdmin()

@app.route("/solve_item", methods=["POST"])
def solve_item():
    if 'userID' not in session:
        return redirect('/login')
    itemID = escape(request.form.get("solve"))
    conn = sqlite3.connect('piccoliTicketi.db')
    cursor = conn.cursor()
    if checkAdmin() == "user":
        return redirect('/')
    cursor.execute("SELECT * FROM tickets WHERE ID = ?", (itemID,))
    item = cursor.fetchone()
    cursor.execute("INSERT INTO closedTickets (userID, title, description, status, priority, created_at, imagePath) VALUES (?, ?, ?, ?, ?, ?, ?)", (item[1], item[2], item[3], 5, item[5], item[6], item[7]))
    conn.commit()
    cursor.execute("DELETE FROM tickets WHERE ID = ?", (itemID,))
    conn.commit()
    conn.close()
    return returnAdmin()

@app.route("/admin", methods=["GET", "POST"])
def admin():
    if 'userID' not in session:
        return redirect('/login')
    if checkAdmin() == "user":
        return redirect('/')
    conn = sqlite3.connect('piccoliTicketi.db')
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM tickets ORDER BY priority ASC, created_at ASC")
    tickets = cursor.fetchall()
    cursor.execute("SELECT fname, status FROM users WHERE id = ?", (session['userID'],))
    name = cursor.fetchone()
    conn.close()
    return render_template("admin.html", statusDict=status, tickets=tickets, name=name[0] if name else None, status=name[1] if name else None)

@app.route("/deleteAdmin", methods=["POST"])
def deleteAdmin():
    if 'userID' not in session:
        return redirect('/login')
    username = escape(request.form.get("username"))
    if username == "SuperFinnee":
        flash("Don't be silly you absolute idiot.", "error")
        return redirect('/admin')
    conn = sqlite3.connect('piccoliTicketi.db')
    cursor = conn.cursor()
    cursor.execute("SELECT username FROM users WHERE id = ?", (session['userID'],))
    operatorUsername = cursor.fetchone()
    if not operatorUsername or operatorUsername[0] != 'SuperFinnee':
        conn.close()
        flash("You do not have permission to perform this action.", "error")
        return redirect('/')
    cursor.execute("UPDATE users SET status = 'user' WHERE username = ?", (username,))
    conn.commit()
    conn.close()
    return redirect('/admin')

@app.route("/deleteUser", methods=["POST"])
def deleteUser():
    if 'userID' not in session:
        return redirect('/login')
    username = escape(request.form.get("username"))
    if username == "SuperFinnee":
        flash("Let's not do this one again. It was embarrasing the first time.", "error")
        return redirect('/admin')
    conn = sqlite3.connect('piccoliTicketi.db')
    cursor = conn.cursor()
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
    if 'userID' not in session:
        return redirect('/login')
    username = escape(request.form.get("username"))
    conn = sqlite3.connect('piccoliTicketi.db')
    cursor = conn.cursor()
    if username == "SuperFinnee":
        flash("Let's not do that. Your admin privileges have been revoked.", "error")
        cursor.execute("UPDATE users SET status = 'user' WHERE id = ?", (session['userID'],))
        return redirect('/')
    
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
    if 'userID' not in session:
        return redirect('/login')
    if checkAdmin() == "user":
        return redirect('/')
    conn = sqlite3.connect('piccoliTicketi.db')
    cursor = conn.cursor()
    cursor.execute("SELECT fname, lname, email, username, status FROM users")
    users = cursor.fetchall()
    cursor.execute("SELECT status, username FROM users WHERE id = ?", (session['userID'],))
    userStatus = cursor.fetchone()
    conn.close()
    return render_template('manageUsers.html', users=users, status=userStatus[0] if userStatus else None, username=userStatus[1] if userStatus else None)

@app.route("/closedTickets", methods=["GET"])
def closedTickets():
    if 'userID' not in session:
        return redirect('/login')
    if checkAdmin() == "user":
        return redirect('/')
    conn = sqlite3.connect('piccoliTicketi.db')
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM closedTickets ORDER BY priority ASC, created_at ASC")
    tickets = cursor.fetchall()
    cursor.execute("SELECT status FROM users WHERE id = ?", (session['userID'],))
    userStatus = cursor.fetchone()
    conn.close()
    return render_template("closedTickets.html", statusDict=status, tickets=tickets, status=userStatus[0] if userStatus else None)

if __name__ == "__main__":
    app.run()