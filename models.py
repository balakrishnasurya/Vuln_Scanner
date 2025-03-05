from flask_login import UserMixin
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import json

db = SQLAlchemy()

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    scans = db.relationship('ScanResult', backref='user', lazy=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class ScanResult(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    url = db.Column(db.String(500), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    results_json = db.Column(db.Text, nullable=False)  # Store results as JSON
    severity_counts = db.Column(db.Text)  # Store severity distribution
    vulnerability_types = db.Column(db.Text)  # Store vulnerability types
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    report_path = db.Column(db.String(500))  # Path to stored PDF report

    @property
    def results(self):
        return json.loads(self.results_json)

    @results.setter
    def results(self, value):
        self.results_json = json.dumps(value)

    @property
    def severity_distribution(self):
        return json.loads(self.severity_counts) if self.severity_counts else {}

    @severity_distribution.setter
    def severity_distribution(self, value):
        self.severity_counts = json.dumps(value)

    @property
    def vulnerability_distribution(self):
        return json.loads(self.vulnerability_types) if self.vulnerability_types else {}

    @vulnerability_distribution.setter
    def vulnerability_distribution(self, value):
        self.vulnerability_types = json.dumps(value)