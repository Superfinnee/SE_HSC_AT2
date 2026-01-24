from flask import Flask, render_template, redirect, request, session, flash
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = 'AP_Fp3279Fp'

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
            attatchments BLOB,
            FOREIGN KEY (userID) REFERENCES users(id)
        )
    ''')
    conn.commit()
    conn.close()
    
initDB()

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == 'POST':
        fName = request.form['fName']
        lName = request.form['lName']
        email = request.form['email']
        username = request.form['username']
        password = request.form['password']
        hashedPassword = generate_password_hash(password)
        conn = sqlite3.connect('piccoliTicketi.db')
        cursor = conn.cursor()
        #Check if username already exists
        cursor.execute("SELECT COUNT(*) FROM users WHERE username = ?", (username,))
        userExists = cursor.fetchone()[0] > 0
        
        if userExists:
            flash("Username already exists.", 'error')
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
def login():
    if request.method == "POST":
        username = request.form['username']
        password = request.form['password']
        conn = sqlite3.connect('piccoliTicketi.db')
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
        user = cursor.fetchone()
        print(user)
        conn.close()
        if user and check_password_hash(user[5], password):
            session['userID'] = user[0]
            session['username'] = user[4]
            flash('Login successful!', 'success')
            return redirect('/')
        flash ("Invalid username or password", "error")
    return render_template('login.html')

@app.route('/createTicket', methods=["GET", "POST"])
def createTicket():
    if 'userID' not in session:
        return redirect('/login')
    if request.method == "POST":
        title = request.form['title']
        description = request.form['description']
        userID = session['userID']
        attachment = request.form.get('attachment', None)
        conn = sqlite3.connect('piccoliTicketi.db')
        cursor = conn.cursor()
        cursor.execute('INSERT INTO tickets (userID, title, description, status, attachment) values (?, ?, ?, ?, ?)', (userID, title, description, 'Open', attachment))
        conn.commit()
        conn.close()
        flash('Ticket created successfully!', 'success')
        return redirect('/')
    return render_template('createTicket.html')




@app.route("/")
def index():    
    if 'userID' not in session:
        return redirect('/login')
    return render_template("index.html")

if __name__ == "__main__":
    app.run(debug=True)