from flask import Flask, render_template, redirect, request, session, flash
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = 'AP_Fp3279Fp'

def initDB():
    conn = sqlite3.connect('app.db')
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            fName TEXT NOT NULL,
            lname TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL)
    ''')
    conn.commit()
    conn.close()
    
initDB()

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == 'POST':
        fName = request.form['fName']
        lName = request.form['fName']
        email = request.form['email']
        username = request.form['username']
        password = request.form['password']
        hashedPassword = generate_password_hash(password)
        conn = sqlite3.connect('app.db')
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
        conn = sqlite3.connect('app.db')
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

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'success')
    return redirect('/login')

#To create a new admin user, paste <a href="/admin">admin</a> in the index.html file and click it once while logged in as the user you want to make admin.
#Also unccoment below:
'''@app.route("/admin")
def admin():
    conn = sqlite3.connect('piccoliTicketi.db')
    cursor = conn.cursor()
    cursor.execute("UPDATE users SET status = 'admin' WHERE username = ?", (session['username'],))
    conn.commit()
    conn.close()
    return redirect('/')'''

@app.route("/")
def index():    
    if 'userID' not in session:
        return redirect('/login')
    return render_template("index.html")

if __name__ == "__main__":
    app.run(debug=True)