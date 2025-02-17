from flask import Flask, render_template, request, redirect, url_for, flash, session, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from datetime import datetime
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key'  # Change this to a secure secret key
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['UPLOAD_FOLDER'] = 'uploads'
ALLOWED_EXTENSIONS = {'pdf'}

# Ensure upload directory exists
if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Database Models
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    role = db.Column(db.String(20), nullable=False)  # 'examiner' or 'student'

class Paper(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    question_paper = db.Column(db.String(255), nullable=False)
    answer_key = db.Column(db.String(255), nullable=False)
    examiner_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

class Submission(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    paper_id = db.Column(db.Integer, db.ForeignKey('paper.id'), nullable=False)
    student_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    answer_pdf = db.Column(db.String(255), nullable=False)
    submitted_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# Routes
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        
        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password')
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        role = request.form['role']
        
        if User.query.filter_by(username=username).first():
            flash('Username already exists')
            return redirect(url_for('register'))
        
        hashed_password = generate_password_hash(password)
        new_user = User(username=username, password=hashed_password, role=role)
        db.session.add(new_user)
        db.session.commit()
        
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/dashboard')
@login_required
def dashboard():
    if current_user.role == 'examiner':
        papers = Paper.query.filter_by(examiner_id=current_user.id).all()
        return render_template('examiner_dashboard.html', papers=papers)
    else:
        papers = Paper.query.all()
        submissions = Submission.query.filter_by(student_id=current_user.id).all()
        return render_template('student_dashboard.html', papers=papers, submissions=submissions)

@app.route('/upload', methods=['POST'])
@login_required
def upload():
    if current_user.role != 'examiner':
        flash('Only examiners can upload papers')
        return redirect(url_for('dashboard'))
    
    question_paper = request.files['question_paper']
    answer_key = request.files['answer_key']
    
    if question_paper and answer_key and allowed_file(question_paper.filename) and allowed_file(answer_key.filename):
        question_filename = secure_filename(question_paper.filename)
        answer_filename = secure_filename(answer_key.filename)
        
        question_paper.save(os.path.join(app.config['UPLOAD_FOLDER'], question_filename))
        answer_key.save(os.path.join(app.config['UPLOAD_FOLDER'], answer_filename))
        
        new_paper = Paper(
            question_paper=question_filename,
            answer_key=answer_filename,
            examiner_id=current_user.id
        )
        db.session.add(new_paper)
        db.session.commit()
        
        flash('Files uploaded successfully')
    else:
        flash('Invalid file format. Only PDF files are allowed.')
    
    return redirect(url_for('dashboard'))

@app.route('/submit/<int:paper_id>', methods=['POST'])
@login_required
def submit_answer(paper_id):
    if current_user.role != 'student':
        flash('Only students can submit answers')
        return redirect(url_for('dashboard'))
    
    answer_pdf = request.files['answer_pdf']
    
    if answer_pdf and allowed_file(answer_pdf.filename):
        filename = secure_filename(answer_pdf.filename)
        answer_pdf.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        
        submission = Submission(
            paper_id=paper_id,
            student_id=current_user.id,
            answer_pdf=filename
        )
        db.session.add(submission)
        db.session.commit()
        
        flash('Answer submitted successfully')
    else:
        flash('Invalid file format. Only PDF files are allowed.')
    
    return redirect(url_for('dashboard'))

@app.route('/uploads/<filename>')
@login_required
def view_file(filename):
    # Security check to ensure user has permission to view this file
    if current_user.role == 'examiner':
        # Check if the file belongs to this examiner
        paper = Paper.query.filter(
            (Paper.question_paper == filename) | (Paper.answer_key == filename),
            Paper.examiner_id == current_user.id
        ).first()
        
        if paper:
            return send_from_directory(app.config['UPLOAD_FOLDER'], filename)
    elif current_user.role == 'student':
        # Students can view question papers from any paper
        paper = Paper.query.filter_by(question_paper=filename).first()
        if paper:
            return send_from_directory(app.config['UPLOAD_FOLDER'], filename)
        
        # Students can only view their own submissions
        submission = Submission.query.filter_by(
            student_id=current_user.id,
            answer_pdf=filename
        ).first()
        if submission:
            return send_from_directory(app.config['UPLOAD_FOLDER'], filename)
    
    # If user doesn't have permission or file not found
    flash('Access denied or file not found')
    return redirect(url_for('dashboard'))

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)