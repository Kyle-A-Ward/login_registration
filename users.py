from flask import render_template, redirect, request, session, flash
from flask_app import app
from flask_app.models import user
from flask_bcrypt import Bcrypt
bcrypt = Bcrypt(app)

@app.route('/')
def users():
    users = user.User.get_all()
    return render_template("login.html", all_users=users)

@app.route('/create', methods=["POST"])
def registration():
    if not user.User.validate_user_reg(request.form):
        return redirect('/')
    
    pw_hash = bcrypt.generate_password_hash(request.form['password'])
    pw_hash2 = bcrypt.generate_password_hash(request.form['password'])
    data = {
        "id" : id,
        "first_name" : request.form["first_name"],
        "last_name": request.form["last_name"],
        "email": request.form["email"],
        "password": pw_hash,
        "confirm_pass": pw_hash2,
    }
    user_id = user.User.save(data)
    session['user_id'] = user_id
    return redirect('/dashboard')

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect('/')
    data = {
        'id' : session['user_id']
    }
    return render_template("dashboard.html", logged_in_user = user.User.get_by_id(data))

@app.route('/login', methods=["POST"])
def login():
    if not user.User.validate_login(request.form):
        return redirect('/')
    data = { "email" : request.form["email"] }
    user_in_db = user.User.get_by_email(data)
    if not user_in_db:
        flash("Invalid Email/Password")
        return redirect("/")
    if not bcrypt.check_password_hash(user_in_db.password, request.form['password']):
        flash("Invalid Email/Password")
        return redirect('/')
    session['user_id'] = user_in_db.id
    return redirect("/dashboard")

@app.route('/logout')
def logout():
    session.clear()
    return redirect("/")