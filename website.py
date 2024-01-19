import logging
from flask import Flask, render_template, request, redirect, url_for
import sqlite3
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField
from wtforms.validators import DataRequired
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'

# Configure logging
logging.basicConfig(filename='app.log', level=logging.DEBUG, format='%(asctime)s [%(levelname)s] %(message)s')

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
    firstname = StringField('First Name', validators=[DataRequired()])
    lastname = StringField('Last Name', validators=[DataRequired()])
    dob = StringField('Date of Birth', validators=[DataRequired()])
    gender = StringField('Gender', validators=[DataRequired()])
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    country = StringField('Country', validators=[DataRequired()])

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

        logging.info(f"Received form data: {firstname}, {lastname}, {dob}, {gender}, {username}, {password}, {country}")

        try:
            conn = sqlite3.connect('users.db')
            cursor = conn.cursor()
            cursor.execute('INSERT INTO users (firstname, lastname, dob, gender, username, password, country) VALUES (?, ?, ?, ?, ?, ?, ?)',
                            (firstname, lastname, dob, gender, username, password, country))
            conn.commit()
            logging.info("User successfully registered.")
            # Redirect to the registration_success route with the firstname parameter
            #return redirect(url_for('registration_success', firstname=firstname))
            return redirect('http://myapp.local/registration_success?firstname=' + firstname)
        except Exception as e:
            logging.error(f"Error with database operations: {e}")
        finally:
            conn.close()

    else:
        logging.warning(f"Form validation errors: {form.errors}")
        return render_template('signup.html', form=form)

@app.route('/registration_success')
def registration_success():
    firstname = request.args.get('firstname', '')
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
        return render_template('welcome.html', firstname=user[1])
    else:
        return "Invalid login credentials"

if __name__ == '__main__':
    app.run(host='myapp.local', port=5000, debug=True)
