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


@app.route("/")
def index():    
    return render_template("index.html")

if __name__ == "__main__":
    app.run(debug=True)