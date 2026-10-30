"""Data model: Users, Files and per-file Shares.

Authorization is modelled explicitly (owner + share grants) so the
files blueprint can enforce object-level checks against IDOR (CWE-639).
"""
from datetime import datetime

from flask_login import UserMixin
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

from . import db

_ph = PasswordHasher()  # Argon2id — memory-hard password hashing


class User(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    is_admin = db.Column(db.Boolean, default=False, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    files = db.relationship("File", backref="owner", lazy=True,
                            cascade="all, delete-orphan")

    def set_password(self, password: str) -> None:
        self.password_hash = _ph.hash(password)

    def check_password(self, password: str) -> bool:
        try:
            return _ph.verify(self.password_hash, password)
        except VerifyMismatchError:
            return False


class File(db.Model):
    __tablename__ = "files"
    id = db.Column(db.Integer, primary_key=True)
    # stored_name is a server-generated UUID name; original_name is display only.
    stored_name = db.Column(db.String(128), unique=True, nullable=False)
    original_name = db.Column(db.String(256), nullable=False)
    owner_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False, index=True)
    size = db.Column(db.Integer, default=0)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    shares = db.relationship("Share", backref="file", lazy=True,
                             cascade="all, delete-orphan")

    def is_accessible_by(self, user) -> bool:
        """Object-level authorization: owner OR an explicit share grantee."""
        if user is None or not user.is_authenticated:
            return False
        if self.owner_id == user.id or user.is_admin:
            return True
        return any(s.grantee_id == user.id for s in self.shares)


class Share(db.Model):
    __tablename__ = "shares"
    id = db.Column(db.Integer, primary_key=True)
    file_id = db.Column(db.Integer, db.ForeignKey("files.id"), nullable=False, index=True)
    grantee_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False, index=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    __table_args__ = (db.UniqueConstraint("file_id", "grantee_id", name="uq_share"),)
