from flask import Flask, render_template, redirect, request, session, flash, url_for
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

app = Flask(__name__)

app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)
csrf = CSRFProtect(app)
app.config.update(
    SESSION_COOKIE_SECURE=True, # Enforces HTTPS for session cookies
    SESSION_COOKIE_HTTPONLY=True, # Prevents client-side JS from accessing session cookies
    SESSION_COOKIE_SAMESITE='Strict' # Prevents cross-site request forgery (CSRF)
)

@app.before_request
def enforce_https():
    if not request.is_secure:
        return redirect(request.url.replace('http://', 'https://'))
        
    
def make_session_permanent():
    session.permanent = True

app.secret_key = 'AP_Fp3279Fp'
UPLOAD_FOLDER = os.path.join('static', 'uploads')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
priorities = ['Low', 'Medium', 'High']

#limiter = Limiter(get_remote_address, app=app, default_limits=["5 per minute"]) ---------- Implemented in the Limiter initialization, not here to avoid interfering with testing and development



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
            status TEXT NOT NULL,
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
            status TEXT NOT NULL,
            priority TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            imagePath TEXT,
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

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == 'POST':
        try:
            fName = escape(request.form['fName'])
            lName = escape(request.form['lName'])
            email = escape(request.form['email'])
            username = escape(request.form['username'])
            password = escape(request.form['password'])
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
#@limiter.limit("5 per minute") ---------------------------------- Implemented in the Limiter initialization, not here to avoid interfering with testing and development
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
    if request.method == "POST":
        title = escape(request.form['title'])
        description = escape(request.form['description'])
        userID = session['userID']
        
        file = request.files.get('attachment')
        imagePath = None
        
        if file and file.filename:
            if not file.mimetype.startswith("image/"):
                flash("Please check your uploaded file, only images are allowed.", "error")
                return redirect('/createTicket')
            
            ext = os.path.splitext(file.filename)[1].lower()
            uniqueName = f"{uuid4().hex}{ext}"
            
            savePath = os.path.join(UPLOAD_FOLDER, uniqueName)
            file.save(savePath)
            imagePath = f"uploads/{uniqueName}"
        
        if title == "" or description == "":
            flash("Please fill in all required fields.", "error")
            return redirect('/createTicket')
        
        conn = sqlite3.connect('piccoliTicketi.db')
        cursor = conn.cursor()
        cursor.execute('INSERT INTO tickets (userID, title, description, status, imagePath) values (?, ?, ?, ?, ?)', (userID, title, description, 'Open', imagePath))
        conn.commit()
        conn.close()
        
        flash('Ticket created successfully!', 'success')
        return redirect('/')
    return render_template('createTicket.html')

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
    cursor.execute("SELECT fname FROM users WHERE id = ?", (session['userID'],))
    userName = cursor.fetchone()
    conn.close()
    return render_template("index.html", tickets=ticketsList, name=userName[0] if userName else "User")

@app.route("/delete_item", methods=["POST"])
def delete_item():
    
    itemID = escape(request.form.get("delete"))
    conn = sqlite3.connect('piccoliTicketi.db')
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM tickets WHERE ID = ?", (itemID,))
    item = cursor.fetchone()
    cursor.execute("INSERT INTO closedTickets (userID, title, description, status, priority, created_at, imagePath) VALUES (?, ?, ?, ?, ?, ?, ?)", (item[1], item[2], item[3], "Closed", item[5], item[6], item[7]))
    conn.commit()
    cursor.execute("DELETE FROM tickets WHERE ID = ?", (itemID,))
    conn.commit()
    conn.close()
    return returnAdmin()

@app.route("/undoDelete", methods=["POST"])
def undoDelete():
    conn = sqlite3.connect('piccoliTicketi.db')
    cursor = conn.cursor()
    cursor.execute("SELECT status FROM users WHERE id = ?", (session['userID'],))
    userStatus = cursor.fetchone()
    if userStatus and userStatus[0] == 'admin':
        cursor.execute("SELECT * FROM closedTickets ORDER BY id DESC LIMIT 1")
        item = cursor.fetchone()
        cursor.execute("INSERT INTO tickets (userID, title, description, status, priority, created_at, imagePath) VALUES (?, ?, ?, ?, ?, ?, ?)", (item[1], item[2], item[3], "open", item[5], item[6], item[7]))
        conn.commit()
        cursor.execute("DELETE FROM closedTickets WHERE ID = ?", (item[0],))
        conn.commit()
        conn.close()
        return redirect("/admin")
    itemID = escape(request.form.get("undo"))
    cursor.execute("SELECT * FROM closedTickets WHERE ID = ?", (itemID,))
    item = cursor.fetchone()
    cursor.execute("INSERT INTO tickets (userID, title, description, status, priority, created_at, imagePath) VALUES (?, ?, ?, ?, ?, ?, ?)", (item[1], item[2], item[3], "open", item[5], item[6], item[7]))
    conn.commit()
    cursor.execute("DELETE FROM closedTickets WHERE ID = ?", (itemID,))
    conn.commit()
    conn.close()
    return returnAdmin()

@app.route("/editItem", methods=["POST"])
def editItem():
    #global editIndex
    editID = escape(int(request.form.get("edit", 0)))
    conn = sqlite3.connect('piccoliTicketi.db')
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM tickets WHERE ID = ?", (editID,))
    tickets = cursor.fetchall()
    conn.close()
    conn = sqlite3.connect('piccoliTicketi.db')
    cursor = conn.cursor()
    cursor.execute("SELECT status FROM users WHERE id = ?", (session['userID'],))
    userStatus = cursor.fetchone()
    conn.close()
    if userStatus and userStatus[0] == 'admin':
        return render_template('admin.html', tickets=tickets, editIndex=editID, priority=priorities)
    return render_template("index.html", tickets=tickets, editIndex=editID)

@app.route("/saveItem", methods=["POST"])
def saveItem():
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
    itemID = escape(request.form.get("solve"))
    conn = sqlite3.connect('piccoliTicketi.db')
    cursor = conn.cursor()
    cursor.execute("SELECT status FROM users WHERE id = ?", (session['userID'],))
    userStatus = cursor.fetchone()
    if userStatus and userStatus[0] != 'admin':
        flash("You do not have permission to perform this action.", "error")
        conn.close()
        return redirect('/')
    cursor.execute("SELECT * FROM tickets WHERE ID = ?", (itemID,))
    item = cursor.fetchone()
    cursor.execute("INSERT INTO closedTickets (userID, title, description, status, priority, created_at, imagePath) VALUES (?, ?, ?, ?, ?, ?, ?)", (item[1], item[2], item[3], "Solved", item[5], item[6], item[7]))
    conn.commit()
    cursor.execute("DELETE FROM tickets WHERE ID = ?", (itemID,))
    conn.commit()
    conn.close()
    return returnAdmin()

@app.route("/admin", methods=["GET", "POST"])
def admin():
    if 'userID' not in session:
        return redirect('/login')
    conn = sqlite3.connect('piccoliTicketi.db')
    cursor = conn.cursor()
    cursor.execute("SELECT status FROM users WHERE id = ?", (session['userID'],))
    userStatus = cursor.fetchone()
    if not userStatus or userStatus[0] != 'admin':
        conn.close()
        flash("You do not have permission to access this page.", "error")
        return redirect('/')
    cursor.execute("SELECT * FROM tickets ORDER BY priority ASC, created_at ASC")
    tickets = cursor.fetchall()
    cursor.execute("SELECT fname FROM users WHERE id = ?", (session['userID'],))
    name = cursor.fetchone()
    conn.close()
    return render_template("admin.html", tickets=tickets, name=name[0] if name else None)

@app.route("/deleteAdmin", methods=["POST"])
def deleteAdmin():
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

@app.route("/createAdmin", methods=["GET", "POST"])
def createAdmin():
    conn = sqlite3.connect('piccoliTicketi.db')
    cursor = conn.cursor()
    cursor.execute("SELECT status FROM users WHERE id = ?", (session['userID'],))
    userStatus = cursor.fetchone()
    if not userStatus or userStatus[0] != 'admin':
        conn.close()
        flash("You do not have permission to acess this page.", "error")
        return redirect('/')
    if request.method == "POST":
        user = escape(request.form.get('username'))
        cursor.execute("UPDATE users SET status = 'admin' WHERE username = ?", (user,))
        conn.commit()
        conn.close()
        return redirect('/admin')
    cursor.execute("SELECT username FROM users WHERE id = ?", (session['userID'],))
    username = cursor.fetchone()
    conn.close()
    return render_template('createAdmin.html', username=username[0] if username else None)

if __name__ == "__main__":
    app.run(debug=True, ssl_context=("C:\\Users\\piccolif26\\OneDrive\\Documents\\12SE_Web_Dev\\SE_HSC_AT2\\localhost+3.pem", "C:\\Users\\piccolif26\\OneDrive\\Documents\\12SE_Web_Dev\\SE_HSC_AT2\\localhost+3-key.pem"))
    