from flask import Flask, render_template, redirect, url_for, request, flash
from flask_socketio import SocketIO, emit
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config['SECRET_KEY'] = '123456'  # 更改为你的密钥
socketio = SocketIO(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# 用户存储在这个字典中
users = {}

class User(UserMixin):
    def __init__(self, username):
        self.username = username

@login_manager.user_loader
def load_user(username):
    return User(username) if username in users else None

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if username in users:
            flash('用户名已存在！')
        else:
            users[username] = generate_password_hash(password)
            flash('注册成功，请登录！')
            return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user_password = users.get(username)

        if user_password and check_password_hash(user_password, password):
            user = User(username)
            login_user(user)
            return redirect(url_for('index'))

        flash('用户名或密码错误！')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

@socketio.on('send message')
def handle_message(msg):
    username = current_user.username if current_user.is_authenticated else '匿名'
    emit('receive message', f'{username}: {msg}', broadcast=True)

if __name__ == '__main__':
    socketio.run(app, host='0.0.0.0', port=32767, allow_unsafe_werkzeug=True)

