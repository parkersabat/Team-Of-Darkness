from server import app, db, User  # Import your Flask app, database, and User model


def promote_owners():
    with app.app_context():  # Ensure we're inside the Flask app context
        owners = User.query.filter_by(is_owner=True).all()

        for owner in owners:
            owner.is_admin = True
            owner.is_trusted_editor = True
            owner.is_member = True

        db.session.commit()
        print(f"Promoted {len(owners)} owners to Admin, Trusted Editor, and Member.")


if __name__ == "__main__":
    promote_owners()
