import os

from mynotes.main import app
from mynotes import db
from mynotes.models import User

# init db
with app.app_context():
    if db.session.query(User).count() == 0:
        admin_user = User()
        admin_user.id = "admin"
        admin_user.notes = os.environ.get("FLAG")
        admin_user.set_password(os.environ.get("ADMIN_PASS"))
        db.session.add(admin_user)
        db.session.commit()


if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000)
