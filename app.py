from flask import Flask, render_template, redirect, request, session, flash
import sqlite3, os
from werkzeug.security import generate_password_hash, check_password_hash
from uuid import uuid4


app = Flask(__name__)
app.secret_key = 'AP_Fp3279Fp'
UPLOAD_FOLDER = os.path.join('static', 'uploads')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

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

@app.route('/createTicket', methods=["GET", "POST"])
def createTicket():
    if 'userID' not in session:
        return redirect('/login')
    if request.method == "POST":
        title = request.form['title']
        description = request.form['description']
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
    conn.close()
    return render_template("index.html", tickets=ticketsList)

@app.route("/delete_item", methods=["POST"])
def delete_item():
    #recordIndex = int(request.form.get("delete"))
    #toDoList.pop(recordIndex)
    
    itemID = request.form.get("delete")
    conn = sqlite3.connect('piccoliTicketi.db')
    cursor = conn.cursor()
    cursor.execute("DELETE FROM tickets WHERE ID = ?", (itemID,))
    conn.commit()
    conn.close()
        
    return redirect("/")

@app.route("/editItem", methods=["POST"])
def editItem():
    #global editIndex
    editID = int(request.form.get("edit", 0))
    conn = sqlite3.connect('piccoliTicketi.db')
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM tickets")
    tickets = cursor.fetchall()
    conn.close()
    return render_template("index.html", tickets=tickets, editIndex=editID)

@app.route("/saveItem", methods=["POST"])
def saveItem():
    #global edit_Index
    #recordIndex = int(request.form.get("editIndex"))
    itemID = request.form.get("editIndex") 
    newTitle = request.form.get("newItem")
    newDescription = request.form.get("newDescription")
    
    #toDoList[recordIndex]["item"] = newItem
    #toDoList[recordIndex]["priority"] = newPriority
    
    conn = sqlite3.connect('piccoliTicketi.db')
    cursor = conn.cursor()
    cursor.execute(
        "UPDATE tickets SET title = ? WHERE ID = ?",(newTitle, itemID)
    )
    conn.commit()
    cursor.execute("UPDATE tickets SET description = ? WHERE ID = ?",(newDescription, itemID))
    conn.commit()
    conn.close()
    
    #edit_Index = None
    return redirect("/")

@app.route("/admin", methods=["GET", "POST"])
def admin():
    if 'userID' not in session:
        return redirect('/login')
    conn = sqlite3.connect('piccoliTicketi.db')
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM tickets ORDER BY created_at ASC, priority DESC")
    tickets = cursor.fetchall()
    conn.close()
    return render_template("admin.html", tickets=tickets)

if __name__ == "__main__":
    app.run(debug=True)