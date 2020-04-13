import os
from flask import Flask, render_template, request, flash, redirect
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_login import login_required, logout_user, current_user, login_user
import markdown2
import requests

from .models import User
from . import db, create_app, login_manager
from .visit_link import q, visit_url

app = create_app()

# configure login_manager {{{1 #
@login_manager.user_loader
def load_user(user_id):
    """Check if user is logged-in on every page load."""
    if user_id is not None:
        return User.query.get(user_id)
    return None


@login_manager.unauthorized_handler
def unauthorized():
    """Redirect unauthorized users to Login page."""
    flash("You must be logged in to view that page.")
    return redirect("/login")


# 1}}} #

# configure routes {{{1 #
@app.route("/")
def index():
    if current_user.is_authenticated:
        return redirect("/profile")
    return render_template("index.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if current_user.is_authenticated:
        return redirect("/profile")

    if request.method == "POST":
        # register user
        id = request.form.get("username")
        password = request.form.get("password")
        existing_user = User.query.filter_by(id=id).first()  # Check if user exists
        if existing_user is None:
            user = User(id=id)
            user.set_password(password)
            user.notes = ""
            db.session.add(user)
            db.session.commit()  # Create new user
            login_user(user)  # Log in as newly created user
            return redirect("/profile")
        flash("A user already exists with that name already exists.")
        return redirect("/register")
    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect("/profile")

    if request.args.get("username"):
        # register user
        id = request.args.get("username")
        password = request.args.get("password")
        user = User.query.filter_by(id=id).first()
        if user and user.check_password(password=password):
            login_user(user)
            return redirect("/profile")

        flash("Incorrect creds")
        return redirect("/login")
    return render_template("login.html")


@app.route("/visit_link", methods=["GET", "POST"])
def visit_link():
    if request.method == "POST":
        url = request.form.get("url")
        job = q.enqueue(visit_url, url, result_ttl=600)
        flash("Our admin will visit the url soon.")
        return render_template("visit_link.html", job_id=job.id)

    return render_template("visit_link.html")


@app.route("/status")
def status():
    job_id = request.args.get("job_id")
    job = q.fetch_job(job_id)
    status = job.get_status()
    return render_template("status.html", status=status)


@app.route("/profile")
@login_required
def profile():
    return render_template("profile.html", current_user=current_user)


@app.route("/update_notes", methods=["POST"])
@login_required
def update_notes():
    # markdown support!!
    current_user.notes = markdown2.markdown(request.form.get("notes"), safe_mode=True)
    db.session.commit()
    return redirect("/profile")


@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect("/")


# 1}}} #
