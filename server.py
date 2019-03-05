from flask import Flask, render_template, request, redirect, session, flash
from mysqlconnection import connectToMySQL
import re
from flask_bcrypt import Bcrypt

app = Flask(__name__)
app.secret_key = "thisisnotasecretkey"
bcrypt = Bcrypt(app)
EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9.+_-]+@[a-zA-Z0-9._-]+\.[a-zA-Z]+$')
PASS_REGEX = re.compile(r'^(?=.*\d)(?=.*[a-z])(?=.*[A-Z]).{8,20}$')

@app.route('/')
def index():
    return render_template("index.html")

@app.route('/register', methods=['POST'])
def register():
    session.clear()
    if len(request.form['fname']) < 2:
        flash("Please enter a first name that is two characters or longer")

    if len(request.form['lname']) < 2:
        flash("Please enter a last name that is two characters or longer")

    mysql = connectToMySQL("login_reg")
    if not EMAIL_REGEX.match(request.form['email']):
        flash("Email is not valid!")

    query = "SELECT email FROM user_data WHERE EXISTS (SELECT email FROM user_data WHERE email=%(em)s);"
    data = {
        "em": request.form['email']
    }

    if mysql.query_db(query, data):
        flash("That email already exists")

    if not PASS_REGEX.match(request.form['pass']):
        flash("Password must be between 8 and 20 characters long contain at least one uppercase letter, one lowercase letter, and one number")

    if request.form['pass'] != request.form['cpass']:
        flash("Passwords must match!")

    if not '_flashes' in session.keys(): 
        pw_hash = bcrypt.generate_password_hash(request.form['pass'])
        mysql = connectToMySQL("login_reg")
        query = "INSERT INTO user_data (first_name, last_name, email, password) VALUES (%(fn)s, %(ln)s, %(em)s, %(pw)s);"
        data = {
            "fn": request.form['fname'],
            "ln": request.form['lname'],
            "em": request.form['email'],
            "pw": pw_hash
        }
        user_id = mysql.query_db(query, data)
        flash("CONGRATULATIONS YOU SUCCESSFULLY CREATED AN ACCOUNT!!!!!")
        flash("YEWWW TIME TO GET SENDY WITH IT BAYBAY")

        mysql = connectToMySQL("login_reg")
        query = "SELECT * FROM user_data WHERE id = %(id)s;"
        data = {
            "id": user_id
        }
        cur_user = mysql.query_db(query, data)

        if 'user' not in session:
            session['user'] = cur_user
        else:
            session['user'] = cur_user

        return redirect("/success")

    print("*"*100)
    return redirect("/")

@app.route('/login', methods=['POST'])
def login():
    mysql = connectToMySQL("login_reg")
    query = "SELECT * FROM user_data WHERE email=%(em)s;"
    data = {
        "em": request.form['email'],
    }
    session['user'] = mysql.query_db(query, data)

    if session['user']:
        if bcrypt.check_password_hash(session['user'][0]['password'], request.form['pass']):
            return redirect("/success")
    
    flash("We couldn't log you in please try again", "error")
    return redirect('/')

    # if mysql.query_db(query, data) and bcrypt.check_password_hash(pw_hash, )

@app.route('/logout')
def logout():
    session.clear()
    return redirect('/')

@app.route('/success')
def success():
    if session:
        return render_template('success.html')
    flash("You need to be logged in!")
    return redirect('/')

if __name__ == "__main__":
    app.run(debug=True)