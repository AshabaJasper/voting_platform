# app.py

from flask import Flask, render_template, redirect, url_for, flash, request, abort
from flask_wtf.csrf import CSRFProtect
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, TextAreaField
from datetime import datetime
from wtforms.validators import DataRequired, Email, Length
from flask_login import (
    LoginManager,
    login_user,
    login_required,
    logout_user,
    current_user,
)
from werkzeug.security import generate_password_hash, check_password_hash

# Import db and migrate from extensions.py
from extensions import db, migrate
# Import models from models.py
from models import User, Entity

# Initialize Flask app
app = Flask(__name__)

# Configuration
app.config["SECRET_KEY"] = "your_very_secret_key_here"
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///voting_platform.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

# Initialize CSRF Protection
csrf = CSRFProtect(app)

# Initialize extensions with app
db.init_app(app)
migrate.init_app(app, db)

# Initialize Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

# Flask-Login user loader function
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Define the LoginForm
class LoginForm(FlaskForm):
    name = StringField(
        "Name", validators=[DataRequired(), Length(min=2, max=100)]
    )
    email = StringField(
        "Email", validators=[DataRequired(), Email(), Length(max=120)]
    )
    phone_number = StringField(
        "Phone Number", validators=[DataRequired(), Length(min=10, max=20)]
    )
    special_code = StringField(
        "Special Code", validators=[DataRequired(), Length(min=4, max=50)]
    )
    submit = SubmitField("Login")

# Define the AddEntityForm
class AddEntityForm(FlaskForm):
    name = StringField(
        "Name", validators=[DataRequired(), Length(min=1, max=100)]
    )
    description = TextAreaField(
        "Description", validators=[DataRequired(), Length(min=1)]
    )
    category = StringField(
        "Category", validators=[DataRequired(), Length(min=1, max=100)]
    )
    submit = SubmitField("Add Entity")

# Define the EditEntityForm
class EditEntityForm(FlaskForm):
    name = StringField(
        "Name", validators=[DataRequired(), Length(min=1, max=100)]
    )
    description = TextAreaField(
        "Description", validators=[DataRequired(), Length(min=1)]
    )
    category = StringField(
        "Category", validators=[DataRequired(), Length(min=1, max=100)]
    )
    submit = SubmitField("Update Entity")

# Define the DeleteEntityForm
class DeleteEntityForm(FlaskForm):
    submit = SubmitField("Delete")

# Home route
@app.route("/")
def home():
    return redirect(url_for("login"))

# Login route
@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        # Redirect based on user role
        if current_user.role == "admin":
            return redirect(url_for("admin_dashboard"))
        else:
            return redirect(url_for("voter_dashboard"))

    form = LoginForm()
    if form.validate_on_submit():
        email = form.email.data
        special_code = form.special_code.data

        # Check if user exists and validate special code
        user = User.query.filter_by(email=email).first()

        if not user or user.special_code != special_code:
            flash("Invalid email or special code.", "danger")
            return redirect(url_for("login"))

        # Log in the user
        login_user(user)

        # Redirect based on user role
        if user.role == "admin":
            return redirect(url_for("admin_dashboard"))
        else:
            return redirect(url_for("voter_dashboard"))

    # If GET request or form validation fails
    return render_template("login.html", form=form)

@app.route("/voter_dashboard")
@login_required
def voter_dashboard():
    if current_user.role != "voter":
        flash("Access unauthorized.", "danger")
        return redirect(url_for("login"))

    entities = Entity.query.all()
    current_year = datetime.now().year

    return render_template("voter_dashboard.html", entities=entities, current_year=current_year)

@app.route('/vote/<int:entity_id>', methods=['POST'])
@login_required
def vote(entity_id):
    if current_user.role != 'voter':
        flash('Access unauthorized.', 'danger')
        return redirect(url_for('login'))

    if current_user.has_voted:
        flash('You have already voted.', 'info')
        return redirect(url_for('voter_dashboard'))

    entity = Entity.query.get_or_404(entity_id)
    entity.vote_count += 1
    current_user.has_voted = True
    db.session.commit()

    flash('Your vote has been recorded. Thank you!', 'success')
    return redirect(url_for('voter_dashboard'))


@app.route("/admin_dashboard", methods=["GET", "POST"])
@login_required
def admin_dashboard():
    if current_user.role != "admin":
        flash("Access unauthorized.", "danger")
        return redirect(url_for("login"))

    entities = Entity.query.all()
    delete_form = DeleteEntityForm()

    # Calculate total voters
    total_voters = User.query.filter_by(role='voter').count()

    # Calculate total votes cast
    total_votes = db.session.query(db.func.sum(Entity.vote_count)).scalar() or 0

    return render_template(
        "admin_dashboard.html",
        entities=entities,
        delete_form=delete_form,
        total_voters=total_voters,
        total_votes=total_votes
    )

# Route to add new entity
@app.route("/add_entity", methods=["GET", "POST"])
@login_required
def add_entity():
    if current_user.role != "admin":
        flash("Access unauthorized.", "danger")
        return redirect(url_for("login"))

    form = AddEntityForm()
    if form.validate_on_submit():
        name = form.name.data
        description = form.description.data
        category = form.category.data

        # Create and save new entity
        entity = Entity(name=name, description=description, category=category)
        db.session.add(entity)
        db.session.commit()

        flash("Entity added successfully!", "success")
        return redirect(url_for("admin_dashboard"))

    return render_template("add_entity.html", form=form)

# Route to edit an existing entity
@app.route("/edit_entity/<int:entity_id>", methods=["GET", "POST"])
@login_required
def edit_entity(entity_id):
    if current_user.role != "admin":
        flash("Access unauthorized.", "danger")
        return redirect(url_for("login"))

    entity = Entity.query.get_or_404(entity_id)
    form = EditEntityForm(obj=entity)

    if form.validate_on_submit():
        entity.name = form.name.data
        entity.description = form.description.data
        entity.category = form.category.data

        db.session.commit()
        flash("Entity updated successfully!", "success")
        return redirect(url_for("admin_dashboard"))

    return render_template("edit_entity.html", form=form, entity=entity)

# Route to delete an existing entity
@app.route("/delete_entity/<int:entity_id>", methods=["POST"])
@login_required
def delete_entity(entity_id):
    if current_user.role != "admin":
        flash("Access unauthorized.", "danger")
        return redirect(url_for("login"))

    entity = Entity.query.get_or_404(entity_id)
    db.session.delete(entity)
    db.session.commit()
    flash("Entity deleted successfully!", "success")
    return redirect(url_for("admin_dashboard"))

# Logout route
@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("You have been logged out.", "info")
    return redirect(url_for("login"))


# 404 Error Handler
@app.errorhandler(404)
def page_not_found(e):
    return render_template("404.html"), 404

# 500 Error Handler
@app.errorhandler(500)
def internal_server_error(e):
    return render_template("500.html"), 500

if __name__ == "__main__":
    app.run(debug=True)
