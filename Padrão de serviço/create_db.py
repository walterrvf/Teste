from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash
import os

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)

class PDF(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    file_path = db.Column(db.String(255), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship('User', backref='pdfs')

if __name__ == '__main__':
    with app.app_context():
        if not os.path.exists('site.db'):
            db.create_all()


        user2 = User(username='sb046020', password=generate_password_hash('sb046020'), is_admin=False)


        pdf2 = PDF(file_path='/PDF/W.pdf', user_id=user2.id)

        db.session.commit()

    print("Banco de dados e registros inseridos com sucesso!")
