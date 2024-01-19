from flask import Flask, render_template, request, redirect, url_for
import sqlite3
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField
from wtforms.validators import InputRequired
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'

# Configure logging
import logging as logger
logger.basicConfig(level=logger.INFO)

# Database initialization
conn = sqlite3.connect('users.db')
cursor = conn.cursor()
cursor.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        firstname TEXT NOT NULL,
        lastname TEXT NOT NULL,
        dob TEXT NOT NULL,
        gender TEXT NOT NULL,
        username TEXT NOT NULL,
        password TEXT NOT NULL,
        country TEXT NOT NULL
    )
''')
conn.commit()
conn.close()

class RegistrationForm(FlaskForm):
    firstname = StringField('First Name', validators=[InputRequired()])
    lastname = StringField('Last Name', validators=[InputRequired()])
    dob = StringField('Date of Birth', validators=[InputRequired()])
    gender = StringField('Gender', validators=[InputRequired()])
    username = StringField('Username', validators=[InputRequired()])
    password = PasswordField('Password', validators=[InputRequired()])
    country = StringField('Country', validators=[InputRequired()])

@app.route('/')
def login():
    return render_template('login.html')

@app.route('/signup')
def signup():
    form = RegistrationForm()
    return render_template('signup.html', form=form)

@app.route('/register', methods=['POST'])
def register():
    form = RegistrationForm(request.form)

    if form.validate():
        firstname = form.firstname.data
        lastname = form.lastname.data
        dob = form.dob.data
        gender = form.gender.data
        username = form.username.data
        password = generate_password_hash(form.password.data, method='pbkdf2:sha256')
        country = form.country.data

        logger.info(f"Received registration form data: {firstname}, {lastname}, {dob}, {gender}, {username}, {password}, {country}")

        try:
            conn = sqlite3.connect('users.db')
            cursor = conn.cursor()
            cursor.execute('INSERT INTO users (firstname, lastname, dob, gender, username, password, country) VALUES (?, ?, ?, ?, ?, ?, ?)',
                            (firstname, lastname, dob, gender, username, password, country))
            conn.commit()
            logger.info("User successfully registered.")
            
            # Debugging print statements
            print("Redirecting to login...")
            
            # Redirect to the login route after successful registration
            return redirect(url_for('registration_success',firstname=firstname))
        except Exception as e:
            logger.error(f"Error with database operations during registration: {e}")
        finally:
            conn.close()

    else:
        logger.warning(f"Form validation errors during registration: {form.errors}")
        return render_template('signup.html', form=form)

@app.route('/registration_success')
def registration_success():
    firstname = request.args.get('firstname', '')
    logger.info(f"User registration successful. Redirecting to registration success page for {firstname}")
    return render_template('registration_success.html', firstname=firstname)

@app.route('/authenticate', methods=['POST'])
def authenticate():
    username = request.form['username']
    password = request.form['password']

    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM users WHERE username = ?', (username,))
    user = cursor.fetchone()
    conn.close()

    if user and check_password_hash(user[6], password):
        logger.info(f"User {username} successfully authenticated.")
        return render_template('welcome.html', firstname=user[1])
    else:
        logger.warning(f"Failed authentication attempt for user {username}. Invalid login credentials.")
        return "Invalid login credentials"

if __name__ == '__main__':
    app.run(debug=True)
