from flask import (
    Flask,
    render_template,
    redirect,
    request,
    url_for,
    flash,
    jsonify,
    abort,
)
from flask_sqlalchemy import SQLAlchemy
from flask_login import (
    LoginManager,
    UserMixin,
    login_user,
    logout_user,
    login_required,
    current_user,
)
from werkzeug.security import generate_password_hash, check_password_hash
import os

app = Flask(__name__, template_folder=".")
app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", "your_secret_key")
app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv("DATABASE_URL", "sqlite:///users.db")
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = True

# Initialize extensions
db = SQLAlchemy()
login_manager = LoginManager()

# Bind the app to the extensions
db.init_app(app)
login_manager.init_app(app)


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    is_owner = db.Column(db.Boolean, default=False)
    is_member = db.Column(db.Boolean, default=False)  # New column for Members
    is_trusted_editor = db.Column(
        db.Boolean, default=False
    )  # New column for Trusted Editors

    def __repr__(self):
        return f"<User {self.username}>"


# User loader for Flask-Login
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# Routes
@app.route("/")
def index():
    return "Hello, Flask on Glitch!"


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for("dashboard"))
        else:
            flash("Invalid credentials!", "danger")
            return redirect(url_for("login"))
    return render_template("login.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        existing_user = User.query.filter_by(username=username).first()

        if existing_user:
            flash("Username already exists!", "danger")
            return redirect(url_for("register"))

        hashed_password = generate_password_hash(password, method="pbkdf2:sha256")
        new_user = User(username=username, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()

        flash("Registration successful! Please log in.", "success")
        return redirect(url_for("login"))
    return render_template("register.html")


@app.route("/api/data")
@login_required
def api_data():
    return jsonify({"message": f"Hello, {current_user.username}! Here's your data."})


@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("You have been logged out.", "success")
    return redirect(url_for("login"))


@app.route("/dashboard")
@login_required
def dashboard():
    return render_template("dashboard.html", name=current_user.username)


@app.route("/admin")
@login_required
def admin_panel():
    if not current_user.is_admin:
        abort(403)  # Forbidden access
    return "Welcome, Admin!"


@app.route("/members")
@login_required
def members():
    if not current_user.is_member and not current_user.is_owner:
        flash("You need to be a member to access this page.")
        return redirect(url_for("dashboard"))
    return render_template("members.html")  # Create this template


@app.route("/trusted-editors")
@login_required
def trusted_editors():
    if not current_user.is_trusted_editor and not current_user.is_owner:
        flash("You need to be a trusted editor to access this page.")
        return redirect(url_for("dashboard"))
    return render_template("trusted_editors.html")  # Create this template


# Promote a regular user to a member (for admins and above)
@app.route("/admin/promote_user/<int:user_id>", methods=["POST"])
@login_required
def promote_user(user_id):
    user = User.query.get_or_404(user_id)

    if current_user.is_owner:
        if user.is_trusted_editor:
            user.is_admin = True
            db.session.commit()
            flash(f"{user.username} has been promoted to Admin.", "success")
        elif user.is_member:
            user.is_trusted_editor = True
            db.session.commit()
            flash(f"{user.username} has been promoted to Trusted Editor.", "success")
        else:
            user.is_member = True
            db.session.commit()
            flash(f"{user.username} has been promoted to Member.", "success")
    elif current_user.is_admin:
        if user.is_member:
            user.is_trusted_editor = True
            db.session.commit()
            flash(f"{user.username} has been promoted to Trusted Editor.", "success")
        else:
            user.is_member = True
            db.session.commit()
            flash(f"{user.username} has been promoted to Member.", "success")
    else:
        flash("You do not have permission to perform this action.", "danger")

    return redirect(url_for("manage_users"))  # <-- Add this return statement


@app.route("/admin/demote_user/<int:user_id>", methods=["POST"])
@login_required
def demote_user(user_id):
    user = User.query.get_or_404(user_id)

    if user.is_owner:
        # Owners cannot be demoted
        flash("You cannot demote the owner!", "danger")
    elif current_user.is_admin:
        if user.is_admin:
            # Admins can demote other admins to Trusted Editor
            user.is_admin = False
            user.is_trusted_editor = True
            db.session.commit()
            flash(f"{user.username} has been demoted to Trusted Editor.", "success")
        elif user.is_trusted_editor:
            # Admins can demote Trusted Editors to Member
            user.is_trusted_editor = False
            user.is_member = True
            db.session.commit()
            flash(f"{user.username} has been demoted to Member.", "success")
        elif user.is_member:
            # Admins can demote Members to Regular User
            user.is_member = False
            db.session.commit()
            flash(f"{user.username} has been demoted to Regular User.", "success")
        else:
            flash("Invalid demotion request.", "danger")
    elif current_user.is_trusted_editor:
        # Trusted Editors can only demote Members to Regular User
        if user.is_member:
            user.is_member = False
            db.session.commit()
            flash(f"{user.username} has been demoted to Regular User.", "success")
        else:
            flash("You do not have permission to demote this user.", "danger")
    else:
        flash("You do not have permission to perform this action.", "danger")

    return redirect(url_for("manage_users"))


# Prevent owner from being demoted (no route needed for this, but logic in the page to hide buttons for the owner)
@app.route("/admin/manage_users", methods=["GET"])
@login_required
def manage_users():
    users = User.query.all()
    return render_template("manage_users.html", users=users)


# Ensure database tables are created before running the app
if __name__ == "__main__":
    with app.app_context():
        db.create_all()  # Create tables if they don't exist
    app.run(host="0.0.0.0", port=3000)
