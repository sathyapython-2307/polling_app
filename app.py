from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_wtf import FlaskForm
from flask_socketio import SocketIO, emit
from wtforms import StringField, PasswordField, SubmitField, RadioField, TextAreaField
from wtforms.validators import DataRequired, Length
from werkzeug.security import generate_password_hash, check_password_hash
import redis
from datetime import datetime
from dotenv import load_dotenv
import os

load_dotenv()

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URI')
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
socketio = SocketIO(app)
redis_client = redis.from_url(os.getenv('REDIS_URL'))

# Models
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128))
    is_admin = db.Column(db.Boolean, default=False)
    votes = db.relationship('Vote', backref='user', lazy=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Poll(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    question = db.Column(db.String(200), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    created_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    creator = db.relationship('User', backref='polls')
    options = db.relationship('PollOption', backref='poll', lazy=True)

class PollOption(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.String(100), nullable=False)
    poll_id = db.Column(db.Integer, db.ForeignKey('poll.id'), nullable=False)
    votes = db.relationship('Vote', backref='option', lazy=True)

class Vote(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    option_id = db.Column(db.Integer, db.ForeignKey('poll_option.id'), nullable=False)
    voted_at = db.Column(db.DateTime, default=datetime.utcnow)

# Forms
class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Sign In')

class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=4, max=64)])
    email = StringField('Email', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6)])
    submit = SubmitField('Register')

class PollForm(FlaskForm):
    question = StringField('Question', validators=[DataRequired()])
    options = TextAreaField('Options (one per line)', validators=[DataRequired()])
    submit = SubmitField('Create Poll')

class VoteForm(FlaskForm):
    option = RadioField('Choices', coerce=int, validators=[DataRequired()])
    submit = SubmitField('Vote')

@login_manager.user_loader
def load_user(id):
    return User.query.get(int(id))

def get_poll_results(poll_id):
    results = {}
    poll = Poll.query.get(poll_id)
    for option in poll.options:
        vote_count = redis_client.get(f'poll:{poll_id}:option:{option.id}') or 0
        results[option.text] = int(vote_count)
    return results

@app.route('/')
def index():
    polls = Poll.query.order_by(Poll.created_at.desc()).all()
    return render_template('index.html', polls=polls)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user is None or not user.check_password(form.password.data):
            flash('Invalid username or password')
            return redirect(url_for('login'))
        login_user(user)
        return redirect(url_for('index'))
    return render_template('login.html', form=form)

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(username=form.username.data, email=form.email.data)
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.commit()
        flash('Congratulations, you are now a registered user!')
        return redirect(url_for('login'))
    return render_template('register.html', form=form)

@app.route('/poll/<int:poll_id>', methods=['GET', 'POST'])
@login_required
def view_poll(poll_id):
    poll = Poll.query.get_or_404(poll_id)
    form = VoteForm()
    
    # Check if user already voted
    has_voted = Vote.query.filter_by(user_id=current_user.id, option_id=db.session.query(PollOption.id).filter_by(poll_id=poll_id)).first()
    
    # Populate choices
    form.option.choices = [(option.id, option.text) for option in poll.options]
    
    if form.validate_on_submit() and not has_voted:
        option_id = form.option.data
        vote = Vote(user_id=current_user.id, option_id=option_id)
        db.session.add(vote)
        
        # Update Redis cache
        redis_key = f'poll:{poll_id}:option:{option_id}'
        redis_client.incr(redis_key)
        
        db.session.commit()
        
        # Emit real-time update
        results = get_poll_results(poll_id)
        socketio.emit('update_results', {
            'poll_id': poll_id,
            'results': results
        })
        
        flash('Your vote has been recorded!')
        return redirect(url_for('view_poll', poll_id=poll_id))
    
    results = get_poll_results(poll_id)
    return render_template('view_poll.html', poll=poll, form=form, results=results, has_voted=has_voted)

@app.route('/create_poll', methods=['GET', 'POST'])
@login_required
def create_poll():
    if not current_user.is_admin:
        flash('Only admins can create polls')
        return redirect(url_for('index'))
    
    form = PollForm()
    if form.validate_on_submit():
        poll = Poll(question=form.question.data, created_by=current_user.id)
        db.session.add(poll)
        db.session.commit()
        
        options = [opt.strip() for opt in form.options.data.split('\n') if opt.strip()]
        for opt in options:
            option = PollOption(text=opt, poll_id=poll.id)
            db.session.add(option)
            redis_client.set(f'poll:{poll.id}:option:{option.id}', 0)
        
        db.session.commit()
        flash('Poll created successfully!')
        return redirect(url_for('index'))
    
    return render_template('create_poll.html', form=form)

@app.route('/admin')
@login_required
def admin_dashboard():
    if not current_user.is_admin:
        flash('You do not have permission to access this page')
        return redirect(url_for('index'))
    
    polls = Poll.query.order_by(Poll.created_at.desc()).all()
    users = User.query.order_by(User.username).all()
    
    poll_data = []
    for poll in polls:
        total_votes = sum(int(redis_client.get(f'poll:{poll.id}:option:{option.id}') or 0) for option in poll.options)
        poll_data.append({
            'poll': poll,
            'total_votes': total_votes
        })
    
    return render_template('admin.html', polls=poll_data, users=users)

@socketio.on('connect')
def handle_connect():
    print('Client connected')

@socketio.on('disconnect')
def handle_disconnect():
    print('Client disconnected')

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        
        # Create admin user if none exists
        if User.query.filter_by(is_admin=True).count() == 0:
            admin = User(
                username='admin',
                email='admin@example.com',
                is_admin=True
            )
            admin.set_password('admin123')
            db.session.add(admin)
            db.session.commit()
    
    socketio.run(app, debug=True)
