import secrets

import string

from cryptography.fernet import Fernet
from flask import Flask, render_template, request, redirect, session, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_wtf.csrf import CSRFProtect

app = Flask(__name__)

app.secret_key = "passwordmanager123"
csrf = CSRFProtect(app)

app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///password_manager.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)
key = b"XJAB6gLNfiTHZ3vPzm3zr70HIiKCdDdcrh3ddteujyI="
cipher = Fernet(key)

def generate_password():
    

    characters = string.ascii_letters + string.digits + "!@#$%"

    password = ""

    for i in range(12):
        password += secrets.choice(characters)

    return password

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100))
    email = db.Column(db.String(120), unique=True)
    password = db.Column(db.String(200))


class Password(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    website = db.Column(db.String(100))
    username = db.Column(db.String(100))
    password = db.Column(db.String(200))
    user_id = db.Column(db.Integer)


@app.route("/", methods=["GET", "POST"])
def register():

    if request.method == "POST":

        username = request.form["username"]
        email = request.form["email"]
        password = request.form["password"]

        hashed_password = generate_password_hash(password)

        new_user = User(
            username=username,
            email=email,
            password=hashed_password
        )

        db.session.add(new_user)
        db.session.commit()

        return redirect("/login")

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        email = request.form["email"]
        password = request.form["password"]

        user = User.query.filter_by(email=email).first()

        if user and check_password_hash(user.password, password):
            session["user_id"] = user.id
            return redirect("/dashboard")

        flash("Invalid Email or Password")
        return redirect("/login")

    return render_template("login.html")

@app.route("/dashboard")
def dashboard():
 
    if "user_id" not in session:
        return redirect("/login")

    return render_template("dashboard.html")

@app.route("/logout")
def logout():

    session.clear()

    return redirect("/login")

@app.route("/add-password", methods=["GET", "POST"])
def add_password():

    if "user_id" not in session:
        return redirect("/login")

    if request.method == "POST":

        website = request.form["website"]
        username = request.form["username"]
        password = request.form["password"]
        encrypted_password = cipher.encrypt(password.encode()).decode()

        new_password = Password(
            website=website,
            username=username,
            password=encrypted_password,
            user_id=session["user_id"]
        )

        db.session.add(new_password)
        db.session.commit()

        flash("Password saved successfully!")
        return redirect("/view-passwords")

    return render_template("add_password.html")


@app.route("/view-passwords")
def view_passwords():

    if "user_id" not in session:
        return redirect("/login")

    passwords = Password.query.filter_by(user_id=session["user_id"]).all()

    for item in passwords:
        item.password = cipher.decrypt(item.password.encode()).decode()

    return render_template(
        "view_passwords.html",
        passwords=passwords
    )


@app.route("/delete-password/<int:id>")
def delete_password(id):

    if "user_id" not in session:
        return redirect("/login")

    

    password = Password.query.filter_by(id=id, user_id=session["user_id"]).first()

    if password:
        db.session.delete(password)
        db.session.commit()
    
    return redirect("/view-passwords")

@app.route("/generate-password")
def password_generator():

    if "user_id" not in session:
        return redirect("/login")

    password = generate_password()

    return password

if __name__ == "__main__":

    with app.app_context():
        db.create_all()

    app.run(debug=True)
