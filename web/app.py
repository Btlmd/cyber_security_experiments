from flask import Flask, make_response, render_template, request, redirect, url_for
import sqlite3
import os

from markupsafe import escape

UNSAFE_VAR = os.getenv('UNSAFE', None).strip()
UNSAFE = True
if UNSAFE_VAR is None:
    UNSAFE = False
if UNSAFE_VAR == '0':
    UNSAFE = False

print("UNSAFE MODE:", UNSAFE)

# if os.path.exists('test.db'):
#     os.remove('test.db')

# Connect Database
def connect_db():
    db = sqlite3.connect('test.db')
    return db

# Initialize Database
def init_db():
    db = connect_db()
    db.cursor().execute('CREATE TABLE IF NOT EXISTS comments '
                        '(id INTEGER PRIMARY KEY, '
                        'comment TEXT, '
                        'username TEXT)')
    db.cursor().execute('CREATE TABLE IF NOT EXISTS users '
                        '(id INTEGER PRIMARY KEY, '
                        'username TEXT, '
                        'password TEXT)')
    db.cursor().execute('CREATE TABLE IF NOT EXISTS sessions '
                        '(id INTEGER PRIMARY KEY, '
                        'username TEXT, '
                        'session_id TEXT,'
                        'csrf_token TEXT)')
    db.commit()

    # 创建默认用户 lambda, 密码为 11452
    db.cursor().execute('INSERT INTO users (username, password) '
                        'VALUES (?, ?)', ('lambda', '11452'))
    db.commit()

init_db()

# Add A Comment
def add_comment(comment, request) -> bool:
    db = connect_db()

    # check session
    session_id = request.cookies.get('session')
    csrf_token = request.form.get('csrf_token')
    print(session_id)
    if session_id is None:
        user_token = None
    else:
        user_token = db.cursor().execute('SELECT username, csrf_token FROM sessions WHERE session_id=?', (session_id,)).fetchone()
    match = False
    
    username = None
    if user_token is not None:
        username, token = user_token
        if token == csrf_token:
            match = True

    if not UNSAFE:
        if username is not None and not match:
            print('CSRF Token Error')
            return True

    if UNSAFE:
        if username is None:
            db.cursor().executescript(
    	        f"INSERT INTO comments (username, comment) VALUES (NULL, '{comment}')"
            )
        else:
            db.cursor().executescript(
                f"INSERT INTO comments (username, comment) VALUES ('{username}', '{comment}')"
            )
    else:
        db.cursor().execute('INSERT INTO comments (username, comment) VALUES (?, ?)', (username, comment))
    db.commit()
    return False

# Get Comments By Search Query
def get_comments(search_query=None):
    db = connect_db()
    results = []
    get_all_query = 'SELECT comment, username FROM comments'
    for comment, username in db.cursor().execute(get_all_query).fetchall():
        if search_query is None or search_query in comment:
            results.append([comment, username])
    return results

# Init Flask
app = Flask(__name__)

# Default
@app.route('/', methods=['GET', 'POST'])
def index():
    # CSRF Demo Site
    print(request.headers['Host'])
    host = request.headers.get('Host')
    if host and 'csrf.test' in host:
        return render_template('csrf.html')
    
    # Site Index
    csrf_warning = False
    if request.method == 'POST':
        comment = request.form['comment']
        if comment:
            csrf_warning = add_comment(comment, request)


    search_query = request.args.get('q')

    session_id = request.cookies.get('session')
    db = connect_db()
    user_token = db.cursor().execute('SELECT username, csrf_token FROM sessions WHERE session_id=?', (session_id,)).fetchone()

    if user_token is None:
        user, token = None, None
    else:
        user, token = user_token
        

    message = request.cookies.get('message')

    if csrf_warning:
        if message is None:
            message = 'CSRF Token Mismatch!'
        else:
            message += '<br />CSRF Token Mismatch!'

    comments = get_comments(search_query)

    if not UNSAFE: # XSS escape
        if search_query is not None:
            search_query = escape(search_query)
        comments = [
            [escape(comment), escape(username) if username is not None else None] 
            for comment, username in comments
        ]
    res =  render_template('index.html',
                           comments=comments,
                           search_query=search_query,
                           user=user,
                           token=token,
                           message=message)
        
    res = make_response(res)
    res.set_cookie('message', '', expires=0)

    return res

# Login
@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username')
    password = request.form.get('password')
    
    db = connect_db()
    user = db.cursor().execute('SELECT username FROM users WHERE username=? AND password=?', (username, password)).fetchone()

    res = redirect(url_for('index'))
    if user is not None:
        # create session
        session_id = os.urandom(16).hex()
        csrf_token = os.urandom(16).hex()
        db.cursor().execute('INSERT INTO sessions (username, session_id, csrf_token) VALUES (?, ?, ?)', (username, session_id, csrf_token))
        db.commit()

        res.set_cookie('session', session_id)
        res.set_cookie('message', 'Login Success!')
    else:
        res.set_cookie('message', 'Login Failed!')
    return res
                                        
# Logout
@app.route('/logout', methods=['POST', 'GET'])
def logout():
    res = redirect(url_for('index'))

    # delete session
    session_id = request.cookies.get('session')
    db = connect_db()
    db.cursor().execute('DELETE FROM sessions WHERE session_id=?', (session_id,))
    db.commit()

    res.set_cookie('session', '', expires=0)
    return res

@app.route('/login', methods=['GET'])
def login_page():
    return render_template('login.html')