from flask import Flask, render_template, request, session, flash, redirect, jsonify
from mysqlconnection import connectToMySQL
from flask_bcrypt import Bcrypt
import re

app = Flask(__name__)
app.secret_key = "fatey243278923hewrjekwbfdjksfdso"
bcrypt = Bcrypt(app)
PASSWORD_REGEX = '\d.*[A-Z]|[A-Z].*\d'

#---------------- RENDER ROUTES --------------------#
@app.route('/')
def index():
    if not '_flashes' in session.keys():
        # reset session to prevent user go back to /wall without login/registration
        # and remove previous input data
        session['login_user'] = 0
        session['input_data'] = {}
    if not 'login_user' in session:
        session['login_user']= 0
    if not "input_data" in session:
        session['input_data'] = {}
    users = db_get_users()
    print(users)
    return render_template('login.html', input_data = session['input_data'])

@app.route('/wall')
def display_private_wall():
    if session['login_user'] == 0:
        return redirect('/')
    user = db_get_user(session['login_user'])[0]
    sendto_list = db_get_sendtolist_from_user(user['first_name'])
    messages = db_get_messages_by_recipient(user['id'])
    print(f"user = {user}")
    print(f"messages = {messages}")
    return render_template('wall.html', user = user, messages = messages, sendto_list = sendto_list)

@app.route("/danger")
def display_danger():
    print(session)
    return render_template("danger.html", suspicious_action = session['suspicious_action'])

#---------------- REDIRECT/POST ROUTES --------------#
@app.route('/register', methods=['POST'])
def register():
    print(request.form)
    session['input_data'] = {
        "first_name": request.form['first_name'],
        "last_name": request.form["last_name"],
        "email": request.form["email"]
    }

    # check if that email is in database
    user = db_get_user_by_email(request.form['email'])
    if user != ():
        flash("This email is already used. Please enter another one!")
        return redirect('/')

    # check if password has at least 1 number and 1 uppercase letter
    if not re.match(PASSWORD_REGEX, request.form['password']):
        flash("Password should have at least 1 number and 1 uppercase letter")
        return redirect('/')

    # check if password is matched
    if request.form['password'] != request.form['confirm_password']:
        flash("Passwords do not match. Please enter again!")
        return redirect('/')

    # hash password
    password_hash = bcrypt.generate_password_hash(request.form['password'])

    # add to the database
    userInfo = {
        'first_name': request.form['first_name'],
        'last_name': request.form['last_name'],
        'email': request.form['email'],
        'password_hash': password_hash,
    }
    userId = db_add_user(userInfo)

    # save user id in session
    session['login_user'] = userId
    return redirect('/wall')

@app.route('/send_message', methods=['POST'])
def send_message():
    # add message to the database
    db_add_message(request.form)
    return redirect('/wall')

@app.route('/delete_message', methods=['POST'])
def delete_message():
    # get recipient_id of the message from the form and form the database
    form_recipient_id = int(request.form['recipient_id'])
    db_recipient_id = db_get_recipient_of_message(request.form['message_id'])
    if db_recipient_id:
        db_recipient_id = db_recipient_id[0]['recipient_id']
    else:
        db_recipient_id = 0

    # redirect to /danger route if user tried to delete other person's message
    if session['login_user'] != form_recipient_id or \
        db_recipient_id != form_recipient_id:
        session['suspicious_action'] = {
            'message_id': request.form['message_id'],
            'ip': request.remote_addr,
        }
        # reset 'login_id' and 'input_data' in session 
        # to prevent user go back to the wall without login again
        session.pop('login_user')
        session.pop('input_data') 
        return redirect('/danger')

    # Everything seems fine, delete the message
    db_delete_message(int(request.form['message_id']))
    return redirect('/wall')

@app.route('/login', methods=['POST'])
def login():
    #retrieve data from the database based on the email
    user = db_get_user_by_email(request.form['email'])
    if user:
        # check password
        if bcrypt.check_password_hash(user[0]['password_hash'], request.form['password']):
            # log this user in and store data in session
            session['login_user'] = user[0]['id']
            return redirect('/wall')
    flash("You cannot log in. Please check your email and password again!")
    return redirect('/')

@app.route('/logout')
def logout():
    # clear session
    session.clear()
    return redirect('/')

#----------------- DATABASE FUNCTIONS ---------------#
#-----------------------------------------------------
#                   Users
#-----------------------------------------------------
def db_get_users():
    mysql = connectToMySQL("private_wall_users")
    return mysql.query_db("SELECT * FROM users")

def db_get_user(uid):
    mysql = connectToMySQL("private_wall_users")
    query = "SELECT * FROM users WHERE users.id=%(id)s"
    data = {
        'id': uid
    }
    return mysql.query_db(query, data)

def db_get_user_by_email(email):
    mysql = connectToMySQL("private_wall_users")
    query = "SELECT * FROM users WHERE users.email=%(email)s"
    data = {
        'email': email
    }
    return mysql.query_db(query, data)

def db_get_sendtolist_from_user(username):
    mysql = connectToMySQL("private_wall_users")
    query = "SELECT users.id, CONCAT(users.first_name, ' ', users.last_name) as full_name \
        FROM users WHERE users.first_name != %(username)s"
    data = {'username': username}
    return mysql.query_db(query, data)

def db_add_user(userInfo):
    mysql = connectToMySQL("private_wall_users")
    query = "INSERT INTO users (first_name, last_name, email, password_hash)\
        VALUES (%(fn)s, %(ln)s, %(email)s, %(pw_hash)s)"
    data = {
        'fn': userInfo['first_name'],
        'ln': userInfo['last_name'],
        'email': userInfo['email'],
        'pw_hash': userInfo['password_hash'],
    }
    return mysql.query_db(query, data)

#-----------------------------------------------------
#                  Messages 
#-----------------------------------------------------
def db_get_messages():
    mysql = connectToMySQL("private_wall_users")
    return query("SELECT * FROM messages")

def db_get_message_by_id(mid):
    mysql = connectToMySQL("private_wall_users")
    query = "SELECT * FROM messages WHERE messages.id = %(mid)s"
    data = {'mid': mid}
    return mysql.query_db(query, data)

def db_get_messages_by_recipient(uid):
    mysql = connectToMySQL("private_wall_users")
    query = "SELECT messages.id, messages.sender_id, messages.recipient_id, users.first_name as sender, messages.message, messages.created_at \
                FROM messages \
                JOIN users ON users.id = messages.sender_id AND messages.recipient_id = %(uid)s"
    data = {'uid': uid}
    return mysql.query_db(query, data)

def db_get_recipient_of_message(mid):
    mysql = connectToMySQL("private_wall_users")
    query = "SELECT messages.recipient_id FROM messages WHERE messages.id = %(mid)s"
    data = {'mid': mid}
    return mysql.query_db(query, data)

def db_add_message(messageInfo):
    mysql = connectToMySQL("private_wall_users")
    query = "INSERT INTO messages (message, sender_id, recipient_id)\
        VALUES (%(message)s, %(s_id)s, %(r_id)s)"
    data = {
        'message': messageInfo['message'],
        's_id': messageInfo['sender_id'],
        'r_id': messageInfo['recipient_id']
    }
    return mysql.query_db(query, data)

def db_delete_message(mid):
    mysql = connectToMySQL("private_wall_users")
    query = "DELETE FROM messages WHERE messages.id = %(mid)s"
    data = {'mid': mid}
    return mysql.query_db(query, data)


if __name__ == "__main__":
    app.run(debug=True)


