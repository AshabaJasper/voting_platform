# models.py

from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from extensions import db  # Import db from extensions.py

# Define the Entity model
class Entity(db.Model):
    __tablename__ = 'entity'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    picture = db.Column(db.String(200), nullable=True)  # Optional URL/path for an image
    category = db.Column(db.String(50), nullable=False)
    vote_count = db.Column(db.Integer, default=0)

    def __repr__(self):
        return f"<Entity {self.name}>"

# Define the User model
class User(db.Model, UserMixin):
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    phone_number = db.Column(db.String(20), nullable=False)
    special_code = db.Column(db.String(50), nullable=False)
    role = db.Column(db.String(10), nullable=False)  # 'voter' or 'admin'
    has_voted = db.Column(db.Boolean, default=False)
    password_hash = db.Column(db.String(128))
    role = db.Column(db.String(10), nullable=False)

    # Password methods
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def __repr__(self):
        return f"<User {self.name}>"
