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
from functools import wraps  # <-- Add this import
import os
import re


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


class SubmittedURL(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    url = db.Column(db.Text, nullable=False)
    tags = db.Column(db.Text, nullable=False)  # Comma-separated tags
    submitted_by = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    created_at = db.Column(db.DateTime, default=db.func.current_timestamp())

    user = db.relationship("User", backref=db.backref("submitted_urls", lazy=True))

    def __repr__(self):
        return f"<SubmittedURL {self.url}>"


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


@app.route("/browse-urls")
@login_required
def browse_urls():
    users = User.query.all()
    """
    Displays URLs based on user role:
    - Trusted Editors and above: All URLs
    - Members: Only URLs with the 'public' tag
    - Regular users: No access
    """
    if current_user.is_trusted_editor or current_user.is_admin or current_user.is_owner:
        urls = SubmittedURL.query.all()  # Trusted Editors and above can see everything
    elif current_user.is_member:
        # Members can only see URLs tagged as 'public'
        urls = SubmittedURL.query.filter(SubmittedURL.tags.contains("public")).all()
    else:
        flash("You do not have access to browse URLs.", "danger")
        return redirect(url_for("dashboard"))

    return render_template("browse_urls.html", urls=urls, users=users)


@app.route("/browse-urls/default", methods=["GET"])
@login_required
def browse_urls_default():
    """
    Returns the default list of URLs based on the user's role:
    - Trusted Editors and above: All URLs
    - Members: Only URLs with the 'public' tag
    """
    if current_user.is_trusted_editor or current_user.is_admin or current_user.is_owner:
        urls = SubmittedURL.query.all()  # Trusted Editors and above can see everything
    elif current_user.is_member:
        urls = SubmittedURL.query.filter(SubmittedURL.tags.contains("public")).all()
    else:
        return jsonify({"error": "You do not have access to this feature."}), 403

    # Format the results as JSON
    results = [
        {
            "id": url.id,
            "url": url.url,
            "tags": url.tags.split(","),
            "submitted_by": User.query.get(url.submitted_by).username,
            "created_at": url.created_at.isoformat(),
        }
        for url in urls
    ]
    return jsonify(results)


# Decorator for restricting access to Trusted Editors and above
def trusted_editor_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not (
            current_user.is_trusted_editor
            or current_user.is_admin
            or current_user.is_owner
        ):
            flash(
                "You need to be a Trusted Editor or above to access this page.",
                "danger",
            )
            return redirect(url_for("dashboard"))
        return f(*args, **kwargs)

    return decorated_function


@app.route("/trusted-editors/submit-url", methods=["GET", "POST"])
@trusted_editor_required
def submit_url():
    if request.method == "POST":
        url = request.form.get("url")
        tags = request.form.get("tags")

        if not url or not tags:
            flash("Both URL and tags are required.", "warning")
        else:
            new_url = SubmittedURL(url=url, tags=tags, submitted_by=current_user.id)
            db.session.add(new_url)
            db.session.commit()
            flash("URL submitted successfully!", "success")
            return redirect(url_for("submit_url"))

    return render_template("submit_url.html")


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


from urllib.parse import urlparse


def matches_domain(url, pattern):
    """Check if the URL matches the given domain pattern."""
    parsed_url = urlparse(url)
    domain = parsed_url.netloc
    path = parsed_url.path

    # Convert wildcard pattern to a regex
    regex_pattern = pattern.replace(".", r"\.").replace("*", ".*")
    return re.match(regex_pattern, f"{domain}{path}") is not None


import re


def filter_items(items, query):
    """Filter items based on the query."""
    operators = {
        "AND": lambda tags, query_tags: all(tag in tags for tag in query_tags),
        "OR": lambda tags, query_tags: any(tag in tags for tag in query_tags),
        "NOT": lambda tags, query_tags: all(tag not in tags for tag in query_tags),
    }

    # Parse the query
    match = re.match(
        r"\{\{\s*(.*?)\s*\}\}\s*(AND|OR|NOT)?\s*\{\{\s*(.*?)\s*\}\}?|(NOT\s+)?domain:\s*([\S]+)|\{\{\s*(.*?)\s*\}\}",
        query,
        re.IGNORECASE,
    )
    if not match:
        return {
            "error": "Invalid query format. Use '{{ tag }}', '{{ tag }} AND {{ tag }}', 'domain:*', or similar."
        }

    # Single tag filtering
    if match.group(6):
        single_tag = match.group(6).strip()
        return [
            item
            for item in items
            if single_tag in [tag.strip() for tag in item.tags.split(",")]
        ]

    # Domain filtering
    if match.group(4) or match.group(5):
        is_not = bool(match.group(4))  # Detect if 'NOT' is present
        domain_pattern = match.group(5)
        return [
            item
            for item in items
            if (
                not matches_domain(item.url, domain_pattern)
                if is_not
                else matches_domain(item.url, domain_pattern)
            )
        ]

    # Tag filtering with operators
    tag1, operator, tag2 = match.group(1), match.group(2), match.group(3)
    if not operator or operator not in operators:
        return {"error": f"Operator '{operator}' not supported."}

    query_tags = [tag1.strip(), tag2.strip()]
    return [
        item
        for item in items
        if operators[operator](
            [tag.strip() for tag in item.tags.split(",")], query_tags
        )
    ]


@app.route("/search", methods=["GET"])
@login_required
def search():
    """
    Search endpoint for filtering URLs based on a query.
    Trusted Editors and above get full search access.
    Members can only see results with the 'public' tag.
    """
    query = request.args.get("q")
    if not query:
        return jsonify({"error": "Query parameter 'q' is required."}), 400

    # Get all URLs from the database
    all_items = SubmittedURL.query.all()

    # Apply access restrictions
    if current_user.is_trusted_editor or current_user.is_admin or current_user.is_owner:
        # Trusted Editors and above get full access
        filtered_items = filter_items(all_items, query)
    elif current_user.is_member:
        # Members only get results containing the 'public' tag
        public_items = [
            item
            for item in all_items
            if "public" in [tag.strip() for tag in item.tags.split(",")]
        ]
        filtered_items = filter_items(public_items, query)
    else:
        # Non-members cannot access the search
        return jsonify({"error": "You do not have access to this feature."}), 403

    # If filter_items returns an error, pass it through
    if isinstance(filtered_items, dict) and "error" in filtered_items:
        return jsonify(filtered_items), 400

    # Format the results as JSON
    results = [
        {
            "id": item.id,
            "url": item.url,
            "tags": item.tags.split(","),
            "submitted_by": User.query.get(item.submitted_by).username,
            "created_at": item.created_at.isoformat(),
        }
        for item in filtered_items
    ]
    return jsonify(results)


@app.route("/edit-tags/<int:url_id>", methods=["POST"])
@login_required
def edit_tags(url_id):
    """
    Allows Trusted Editors and above to modify the tags of a submitted URL.
    """
    # Only Trusted Editors, Admins, and Owners can edit tags
    if not (
        current_user.is_trusted_editor or current_user.is_admin or current_user.is_owner
    ):
        flash("You do not have permission to edit tags.", "danger")
        return redirect(url_for("dashboard"))

    # Get the URL object from the database
    url_entry = SubmittedURL.query.get_or_404(url_id)

    # Get the new tags from the request form or query parameter
    new_tags = request.form.get("tags") or request.args.get("t")

    if not new_tags:
        flash("Tags cannot be empty.", "warning")
        return redirect(url_for("browse_urls"))

    # Split the tags into a list and validate them
    tags_list = [tag.strip() for tag in new_tags.split(",")]

    # Check if the 'remove-requested' tag is being removed
    if (
        "remove-requested" not in tags_list
        and "remove-requested" in url_entry.tags.split(",")
    ):
        if not (current_user.is_admin or current_user.is_owner):
            flash(
                "Only admins and owners can remove the 'remove-requested' tag.",
                "warning",
            )
            return redirect(url_for("browse_urls"))

    # Update the tags and save the changes to the database
    url_entry.tags = ",".join(tags_list)  # Join the tags
    db.session.commit()

    flash("Tags updated successfully!", "success")
    return redirect(url_for("browse_urls"))  # Return to the browse URLs page


@app.route("/manage-url/<int:url_id>", methods=["POST"])
@login_required
def manage_url(url_id):
    """
    Allows Admins and above to delete a URL.
    Trusted Editors can add the 'remove-requested' tag.
    All others are denied access.
    """
    # Get the URL object from the database
    url_entry = SubmittedURL.query.get_or_404(url_id)

    if current_user.is_admin or current_user.is_owner:
        # Admins and Owners: Delete the URL
        db.session.delete(url_entry)
        db.session.commit()
        flash("URL has been successfully deleted.", "success")
    elif current_user.is_trusted_editor:
        # Trusted Editors: Add 'remove-requested' tag
        tags = [tag.strip() for tag in (url_entry.tags or "").split(",")]
        if "remove-requested" not in tags:
            tags.append("remove-requested")
            url_entry.tags = ",".join(tags)  # Update tags in the database
            db.session.commit()
            flash("'Remove-requested' tag has been added to the URL.", "success")
        else:
            flash("'Remove-requested' tag is already present.", "info")
    else:
        # All others: Deny access
        flash("You do not have permission to manage this URL.", "danger")
        return redirect(url_for("dashboard"))

    return redirect(url_for("browse_urls"))


# Ensure database tables are created before running the app
if __name__ == "__main__":
    with app.app_context():
        db.create_all()  # Create tables if they don't exist
    app.run(host="0.0.0.0", port=3000)
