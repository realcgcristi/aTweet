from flask import Flask, render_template, request, redirect, url_for, session, g, flash
import sqlite3
import os
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from datetime import datetime
from flask import current_app
from flask import jsonify
import markdown
import re
import bleach

def render_markdown(text):
    html = markdown.markdown(text, extensions=['nl2br'])
    allowed_tags = ['p', 'br', 'strong', 'em', 'a', 'ul', 'ol', 'li']
    allowed_attributes = {'a': ['href', 'title']}
    return bleach.clean(html, tags=allowed_tags, attributes=allowed_attributes, strip=True)


def process_tweet_content(content):
    content = re.sub(r'#(\w+)', r'<a href="/hashtag/\1" class="hashtag">#\1</a>', content)
    content = re.sub(r'@(\w+)', r'<a href="/profile/\1" class="mention">@\1</a>', content)
    
    return content

app = Flask(__name__)
def get_user_by_id(user_id):
    db = get_db()
    user = db.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
    return dict(user) if user else None

def init_jinja_env(app):
    app.jinja_env.globals.update(get_user_by_id=get_user_by_id)

app = Flask(__name__)
app.secret_key = 'verysecretok'
init_jinja_env(app)

@app.template_filter('replace_mentions')
def replace_mentions(content):
    return bleach.linkify(re.sub(r'@(\w+)', r'<a href="/profile/\1">@\1</a>', content))

DATABASE = 'db.sqlite3'
UPLOAD_FOLDER = 'static/uploads/'
app.config['UPLOAD_FOLDER'] = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'static', 'uploads')
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

def add_rendered_content_column():
    db = get_db()
    try:
        db.execute('ALTER TABLE tweets ADD COLUMN rendered_content TEXT')
        db.commit()
        print("Added rendered_content column to tweets table")
    except sqlite3.OperationalError as e:
        if "duplicate column name" in str(e):
            print("rendered_content column already exists")
        else:
            raise e


def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row
    return db


def create_tables():
    db = get_db()
    db.execute('''CREATE TABLE IF NOT EXISTS users (
       id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL UNIQUE,
        password TEXT NOT NULL,
        email TEXT NOT NULL,
        pfp TEXT,
        banner TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )''')
    

    cursor = db.execute("PRAGMA table_info(users)")
    columns = [column[1] for column in cursor.fetchall()]
    
    if 'created_at' not in columns:

        db.execute('ALTER TABLE users RENAME TO users_old')
        

        db.execute('''CREATE TABLE users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL,
            email TEXT NOT NULL,
            pfp TEXT,
            banner TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )''')
        

        cursor = db.execute("PRAGMA table_info(users_old)")
        old_columns = [column[1] for column in cursor.fetchall()]
        

        insert_columns = ['id', 'username', 'password']
        select_columns = ['id', 'username', 'password']
        
        if 'email' in old_columns:
            insert_columns.append('email')
            select_columns.append('email')
        else:
            insert_columns.append('email')
            select_columns.append("'example@email.com' AS email")
        
        if 'pfp' in old_columns:
            insert_columns.append('pfp')
            select_columns.append('pfp')
        
        if 'banner' in old_columns:
            insert_columns.append('banner')
            select_columns.append('banner')
        

        db.execute(f'''
            INSERT INTO users({', '.join(insert_columns)}) 
            SELECT {', '.join(select_columns)} FROM users_old
        ''')
        

        db.execute('DROP TABLE users_old')
        
        db.commit()


    db.execute('''CREATE TABLE IF NOT EXISTS tweets (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        content TEXT NOT NULL,
        user_id INTEGER,
        likes INTEGER DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(user_id) REFERENCES users(id)
    )''')
    db.execute('''CREATE TABLE IF NOT EXISTS comments (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        content TEXT NOT NULL,
        tweet_id INTEGER,
        user_id INTEGER,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(tweet_id) REFERENCES tweets(id),
        FOREIGN KEY(user_id) REFERENCES users(id)
    )''')
    db.execute('''CREATE TABLE IF NOT EXISTS likes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        tweet_id INTEGER,
        FOREIGN KEY(user_id) REFERENCES users(id),
        FOREIGN KEY(tweet_id) REFERENCES tweets(id),
        UNIQUE(user_id, tweet_id)
    )''')
    db.execute('''CREATE TABLE IF NOT EXISTS group_members (
        group_id INTEGER,
        user_id INTEGER,
        joined_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (group_id) REFERENCES groups (id),
        FOREIGN KEY (user_id) REFERENCES users (id),
        PRIMARY KEY (group_id, user_id)
    )''')
    db.execute('''CREATE TABLE IF NOT EXISTS messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        sender_id INTEGER,
        receiver_id INTEGER,
        content TEXT,
        image TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (sender_id) REFERENCES users (id),
        FOREIGN KEY (receiver_id) REFERENCES users (id)
    )''')
    db.execute('''CREATE TABLE IF NOT EXISTS posts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        group_id INTEGER,
        content TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users (id),
        FOREIGN KEY (group_id) REFERENCES groups (id)
    )''')
    db.execute('''CREATE TABLE IF NOT EXISTS groups (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        description TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        avatar TEXT,
        vanity_url TEXT
    )''')
    

    cursor = db.execute("PRAGMA table_info(groups)")
    columns = [column[1] for column in cursor.fetchall()]
    
    if 'vanity_url' not in columns:

        db.execute('''CREATE TABLE groups_new (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            description TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            avatar TEXT,
            vanity_url TEXT UNIQUE
        )''')
        

        db.execute('INSERT INTO groups_new SELECT id, name, description, created_at, avatar, NULL FROM groups')
        

        db.execute('DROP TABLE groups')
        

        db.execute('ALTER TABLE groups_new RENAME TO groups')


    db.execute('CREATE UNIQUE INDEX IF NOT EXISTS idx_groups_vanity_url ON groups (vanity_url)')
    

    cursor = db.execute("PRAGMA table_info(users)")
    columns = [column[1] for column in cursor.fetchall()]
    if 'created_at' not in columns:
       add_rendered_content_column()
       update_existing_tweets()
       db.commit()

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()



def add_columns():
    db = get_db()
    try:
        db.execute('ALTER TABLE users ADD COLUMN pfp TEXT')
    except sqlite3.OperationalError:
        pass  

    try:
        db.execute('ALTER TABLE tweets ADD COLUMN likes INTEGER DEFAULT 0')
    except sqlite3.OperationalError:
        pass 

    try:
        db.execute('ALTER TABLE users ADD COLUMN banner TEXT')
    except sqlite3.OperationalError:
        pass  

    try:
        db.execute('ALTER TABLE messages ADD COLUMN image TEXT')
    except sqlite3.OperationalError:
        pass 

    try:
        db.execute('''
            CREATE TABLE IF NOT EXISTS followers (
                follower_id INTEGER,
                followed_id INTEGER,
                FOREIGN KEY (follower_id) REFERENCES users (id),
                FOREIGN KEY (followed_id) REFERENCES users (id),
                PRIMARY KEY (follower_id, followed_id)
            )
        ''')
    except sqlite3.OperationalError:
        pass



def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        password = generate_password_hash(request.form['password'])
        email = request.form['email']

        restricted_usernames = ['avery', 'cgcristi', 'cg', 'ceegee']
        if username.lower() in restricted_usernames:
            flash('This username is not allowed. Please choose a different one.', 'error')
            return render_template('signup.html')

        db = get_db()
        try:
            db.execute('INSERT INTO users (username, password, email) VALUES (?, ?, ?)', (username, password, email))
            db.commit()
            flash('Account created successfully. Please log in.', 'success')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('Username already exists. Please choose a different one.', 'error')
    
    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        db = get_db()
        user = db.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        
        if user and check_password_hash(user['password'], password):
            session['user_id'] = user['id']
            session['username'] = user['username']
            if not user['pfp']:
                return redirect(url_for('profile', username=user['username']))
            return redirect(url_for('index'))
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    session.pop('username', None)
    session.pop('pfp', None)
    return redirect(url_for('login'))

@app.route('/')
def index():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    db = get_db()
    tweets = db.execute('''
        SELECT t.*, u.username, u.pfp as user_pfp,
               COALESCE(t.rendered_content, t.content) as displayed_content
        FROM tweets t
        JOIN users u ON t.user_id = u.id
        ORDER BY t.created_at DESC
    ''').fetchall()

    tweets = [dict(tweet) for tweet in tweets]
    for tweet in tweets:
        tweet['created_at'] = datetime.strptime(tweet['created_at'], '%Y-%m-%d %H:%M:%S')
        tweet['displayed_content'] = bleach.clean(tweet['displayed_content'], strip=True)

    liked_tweet_ids = {like['tweet_id'] for like in db.execute('SELECT tweet_id FROM likes WHERE user_id = ?', (session['user_id'],)).fetchall()}
    user = db.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],)).fetchone()

    if user is None:
        flash('User not found. Please log in again.', 'error')
        return redirect(url_for('logout'))

    user = dict(user)
    user['created_at'] = datetime.strptime(user['created_at'], '%Y-%m-%d %H:%M:%S')

    return render_template('index.html', tweets=tweets, liked_tweet_ids=liked_tweet_ids, user=user, get_user_by_id=get_user_by_id)


def update_existing_tweets():
    db = get_db()
    tweets = db.execute('SELECT id, content FROM tweets WHERE rendered_content IS NULL').fetchall()
    for tweet in tweets:
        rendered_content = render_markdown(tweet['content'])
        db.execute('UPDATE tweets SET rendered_content = ? WHERE id = ?', (rendered_content, tweet['id']))
    db.commit()
    print(f"Updated {len(tweets)} existing tweets with rendered content")

    
@app.route('/tweet', methods=['POST'])
def tweet():
    if 'user_id' in session:
        content = request.form['content']
        if len(content) > 280:
            return redirect(url_for('index'))
        processed_content = process_tweet_content(content)
        rendered_content = render_markdown(processed_content)
        image = request.files.get('image')
        db = get_db()
        if image and allowed_file(image.filename):
            filename = secure_filename(image.filename)
            image.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            db.execute('INSERT INTO tweets (content, rendered_content, user_id, image) VALUES (?, ?, ?, ?)',
                       (content, rendered_content, session['user_id'], filename))
        else:
            db.execute('INSERT INTO tweets (content, rendered_content, user_id) VALUES (?, ?, ?)',
                       (content, rendered_content, session['user_id']))
        db.commit()
    return redirect(url_for('index'))

@app.route('/retweet/<int:tweet_id>', methods=['POST'])
def retweet(tweet_id):
    if 'user_id' in session:
        db = get_db()
        original_tweet = db.execute('SELECT * FROM tweets WHERE id = ?', (tweet_id,)).fetchone()
        if original_tweet:
            db.execute('INSERT INTO tweets (content, rendered_content, user_id, original_tweet_id) VALUES (?, ?, ?, ?)',
                       (original_tweet['content'], original_tweet['rendered_content'], session['user_id'], tweet_id))
            db.commit()
    return redirect(url_for('index'))

@app.route('/search', methods=['GET'])
def search():
    query = request.args.get('q', '')
    db = get_db()
    users = db.execute('SELECT * FROM users WHERE username LIKE ? LIMIT 10', ('%' + query + '%',)).fetchall()
    return render_template('search_results.html', users=users, query=query)

@app.route('/hashtag/<hashtag>')
def hashtag(hashtag):
    db = get_db()
    tweets = db.execute('''
        SELECT t.*, u.username, u.pfp as user_pfp
        FROM tweets t
        JOIN users u ON t.user_id = u.id
        WHERE t.content LIKE ?
        ORDER BY t.created_at DESC
    ''', ('%#' + hashtag + '%',)).fetchall()
    return render_template('hashtag.html', tweets=tweets, hashtag=hashtag)

@app.route('/tweet/<int:tweet_id>')
def tweet_detail(tweet_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    db = get_db()
    tweet = db.execute('SELECT t.id, t.content, u.username, u.pfp, t.likes FROM tweets t JOIN users u ON t.user_id = u.id WHERE t.id = ?', (tweet_id,)).fetchone()
    comments = db.execute('SELECT c.content, u.username FROM comments c JOIN users u ON c.user_id = u.id WHERE c.tweet_id = ?', (tweet_id,)).fetchall()
    liked_tweet_ids = {like['tweet_id'] for like in db.execute('SELECT tweet_id FROM likes WHERE user_id = ?', (session['user_id'],)).fetchall()}
    return render_template('tweet_detail.html', tweet=tweet, comments=comments, liked_tweet_ids=liked_tweet_ids)

@app.route('/comment/<int:tweet_id>', methods=['POST'])
def comment(tweet_id):
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'User not logged in'})
    
    content = request.form['content']
    db = get_db()
    db.execute('INSERT INTO comments (content, tweet_id, user_id) VALUES (?, ?, ?)', (content, tweet_id, session['user_id']))
    db.commit()
    return jsonify({'success': True})


@app.route('/like/<int:tweet_id>', methods=['POST'])
def like(tweet_id):
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'User not logged in'}), 401

    db = get_db()
    user_id = session['user_id']
    
    try:
        existing_like = db.execute('SELECT * FROM likes WHERE user_id = ? AND tweet_id = ?', (user_id, tweet_id)).fetchone()
        
        if existing_like:
            db.execute('DELETE FROM likes WHERE user_id = ? AND tweet_id = ?', (user_id, tweet_id))
            db.execute('UPDATE tweets SET likes = likes - 1 WHERE id = ?', (tweet_id,))
        else:
            db.execute('INSERT INTO likes (user_id, tweet_id) VALUES (?, ?)', (user_id, tweet_id))
            db.execute('UPDATE tweets SET likes = likes + 1 WHERE id = ?', (tweet_id,))

        db.commit()
        updated_likes = db.execute('SELECT likes FROM tweets WHERE id = ?', (tweet_id,)).fetchone()['likes']
        return jsonify({'success': True, 'likes': updated_likes})
    except Exception as e:
        db.rollback()
        print(f"Error in like route: {str(e)}")  
        return jsonify({'success': False, 'message': 'An error occurred while processing your request'}), 500

@app.route('/profile/<username>')
def profile(username):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    db = get_db()
    user = db.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
    if not user:
        abort(404)

    user = dict(user)
    
    if 'created_at' not in user or not user['created_at']:
        first_tweet = db.execute('SELECT MIN(created_at) as first_tweet_date FROM tweets WHERE user_id = ?', (user['id'],)).fetchone()
        if first_tweet and first_tweet['first_tweet_date']:
            user['created_at'] = datetime.strptime(first_tweet['first_tweet_date'], '%Y-%m-%d %H:%M:%S')
        else:
            user['created_at'] = datetime.now()  
    else:
        user['created_at'] = datetime.strptime(user['created_at'], '%Y-%m-%d %H:%M:%S')
    
    tweets = db.execute('SELECT * FROM tweets WHERE user_id = ? ORDER BY created_at DESC', (user['id'],)).fetchall()
    tweets = [dict(tweet) for tweet in tweets]
    for tweet in tweets:
        tweet['created_at'] = datetime.strptime(tweet['created_at'], '%Y-%m-%d %H:%M:%S')

    return render_template('profile.html', user=user, tweets=tweets, get_user_by_id=get_user_by_id)


@app.route('/change_profile_picture', methods=['POST'])
def change_profile_picture():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user_id = session['user_id']

    if 'profile_picture' in request.files:
        file = request.files['profile_picture']
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(file_path)

            db = get_db()
            db.execute("UPDATE users SET pfp = ? WHERE id = ?", (filename, user_id))
            db.commit()
            flash("Profile picture updated successfully.")
        else:
            flash("Invalid file type. Please upload a PNG, JPG, JPEG, or GIF.")
    else:
        flash("No file uploaded.")

    return redirect(url_for('profile'))

@app.route('/change_banner', methods=['POST'])
def change_banner():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    user_id = session['user_id']
    if 'banner' in request.files:
        file = request.files['banner']
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(file_path)
            
            db = get_db()
            db.execute("UPDATE users SET banner = ? WHERE id = ?", (filename, user_id))
            db.commit()
            flash("Banner updated successfully.")
        else:
            flash("Invalid file type. Please upload a PNG, JPG, JPEG, or GIF.")
    else:
        flash("No file uploaded.")

    return redirect(url_for('profile'))

@app.route('/edit_tweet/<int:tweet_id>', methods=['GET', 'POST'])
def edit_tweet(tweet_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    db = get_db()
    tweet = db.execute('SELECT * FROM tweets WHERE id = ? AND user_id = ?', (tweet_id, session['user_id'])).fetchone()

    if request.method == 'POST':
        new_content = request.form['content']
        db.execute('UPDATE tweets SET content = ? WHERE id = ?', (new_content, tweet_id))
        db.commit()
        return redirect(url_for('index'))

    return render_template('edit_tweet.html', tweet=tweet)

@app.route('/delete_tweet/<int:tweet_id>', methods=['POST'])
def delete_tweet(tweet_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    db = get_db()
    db.execute('DELETE FROM tweets WHERE id = ? AND user_id = ?', (tweet_id, session['user_id']))
    db.commit()
    return redirect(url_for('index'))

@app.route('/groups')
def groups():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    db = get_db()
    search_query = request.args.get('search', '')
    if search_query:
        groups = db.execute('SELECT * FROM groups WHERE name LIKE ? ORDER BY name', ('%' + search_query + '%',)).fetchall()
    else:
        groups = db.execute('SELECT * FROM groups ORDER BY name').fetchall()
    return render_template('g.html', groups=groups, get_user_by_id=get_user_by_id, search_query=search_query)

@app.route('/new_group', methods=['POST'])
def new_group():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    name = request.form['group_name']
    vanity_url = request.form['vanity_url']
    description = request.form['description']
    
    db = get_db()
    try:
        db.execute('INSERT INTO groups (name, vanity_url, description) VALUES (?, ?, ?)', (name, vanity_url, description))
        db.commit()
        
        group_id = db.execute('SELECT last_insert_rowid()').fetchone()[0]
        db.execute('INSERT INTO group_members (group_id, user_id) VALUES (?, ?)', (group_id, session['user_id']))
        db.commit()
        
        if 'group_picture' in request.files:
            file = request.files['group_picture']
            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file.save(file_path)
                db.execute('UPDATE groups SET avatar = ? WHERE id = ?', (filename, group_id))
                db.commit()
        
        flash('Group created successfully!', 'success')
    except sqlite3.IntegrityError:
        flash('Group name or vanity URL already exists. Please choose a different one.', 'error')
    
    return redirect(url_for('groups'))

@app.route('/group/<vanity_url>')
def group_detail(vanity_url):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    db = get_db()
    group = db.execute('SELECT * FROM groups WHERE vanity_url = ?', (vanity_url,)).fetchone()
    if not group:
        abort(404)
    
    posts = db.execute('''
        SELECT p.*, u.username, u.pfp
        FROM posts p
        JOIN users u ON p.user_id = u.id
        WHERE p.group_id = ?
        ORDER BY p.created_at DESC
    ''', (group['id'],)).fetchall()
    
    is_member = db.execute('SELECT * FROM group_members WHERE group_id = ? AND user_id = ?', 
                           (group['id'], session['user_id'])).fetchone() is not None
    
    return render_template('group_detail.html', group=group, posts=posts, is_member=is_member, get_user_by_id=get_user_by_id)


@app.route('/join_group/<int:group_id>', methods=['POST'])
def join_group(group_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    db = get_db()
    db.execute('INSERT INTO group_members (group_id, user_id) VALUES (?, ?)', (group_id, session['user_id']))
    db.commit()
    
    group = db.execute('SELECT vanity_url FROM groups WHERE id = ?', (group_id,)).fetchone()
    flash('You have joined the group!', 'success')
    return redirect(url_for('group_detail', vanity_url=group['vanity_url']))

@app.route('/leave_group/<int:group_id>', methods=['POST'])
def leave_group(group_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    db = get_db()
    db.execute('DELETE FROM group_members WHERE user_id = ? AND group_id = ?', (session['user_id'], group_id))
    db.commit()
    group = db.execute('SELECT * FROM groups WHERE id = ?', (group_id,)).fetchone()
    return redirect(url_for('group_detail', vanity_url=group['vanity_url']))

@app.route('/post_in_group/<int:group_id>', methods=['POST'])
def post_in_group(group_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    db = get_db()
    is_member = db.execute('SELECT * FROM group_members WHERE group_id = ? AND user_id = ?', 
                           (group_id, session['user_id'])).fetchone() is not None
    
    if not is_member:
        flash('You must be a member of the group to post.', 'error')
    else:
        content = request.form['content']
        db.execute('INSERT INTO posts (user_id, group_id, content) VALUES (?, ?, ?)', 
                   (session['user_id'], group_id, content))
        db.commit()
        flash('Your post has been added to the group!', 'success')
    
    group = db.execute('SELECT vanity_url FROM groups WHERE id = ?', (group_id,)).fetchone()
    return redirect(url_for('group_detail', vanity_url=group['vanity_url']))


@app.route('/dms')
def dms():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    db = get_db()
    page = request.args.get('page', 1, type=int)
    per_page = 10
    offset = (page - 1) * per_page
    
    conversations = db.execute('''
        SELECT DISTINCT
            CASE
                WHEN sender_id = ? THEN receiver_id
                ELSE sender_id
            END AS other_user_id,
            MAX(created_at) as last_message_time
        FROM messages
        WHERE sender_id = ? OR receiver_id = ?
        GROUP BY other_user_id
        ORDER BY last_message_time DESC
        LIMIT ? OFFSET ?
    ''', (session['user_id'], session['user_id'], session['user_id'], per_page, offset)).fetchall()
    
    dms = []
    for conv in conversations:
        other_user = get_user_by_id(conv['other_user_id'])
        dms.append({
            'username': other_user['username'],
            'pfp': other_user['pfp']
        })
    
    has_more = len(dms) == per_page
    return render_template('dm.html', dms=dms, page=page, has_more=has_more)

@app.route('/dm/<username>')
def dm_conversation(username):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    db = get_db()
    other_user = db.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
    if not other_user:
        abort(404)
    
    messages = db.execute('''
        SELECT m.*, u.username, u.pfp
        FROM messages m
        JOIN users u ON m.sender_id = u.id
        WHERE (m.sender_id = ? AND m.receiver_id = ?) OR (m.sender_id = ? AND m.receiver_id = ?)
        ORDER BY m.created_at ASC
    ''', (session['user_id'], other_user['id'], other_user['id'], session['user_id'])).fetchall()
    
    return render_template('dm_conversation.html', other_user=other_user, messages=messages)


@app.route('/edit_group/<int:group_id>', methods=['GET', 'POST'])
def edit_group(group_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    db = get_db()
    group = db.execute('SELECT * FROM groups WHERE id = ?', (group_id,)).fetchone()
    
    if request.method == 'POST':
        name = request.form['name']
        description = request.form['description']
        
        db.execute('UPDATE groups SET name = ?, description = ? WHERE id = ?', (name, description, group_id))
        db.commit()
        
        flash('Group updated successfully!', 'success')
        return redirect(url_for('group_detail', vanity_url=group['vanity_url']))
    
    return render_template('edit_group.html', group=group)


@app.route('/dm/<username>/send', methods=['POST'])
def send_message(username):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    content = request.form['content']
    image = request.files.get('image')
    
    db = get_db()
    receiver = db.execute('SELECT id FROM users WHERE username = ?', (username,)).fetchone()
    
    if receiver:
        image_filename = None
        if image and allowed_file(image.filename):
            image_filename = secure_filename(image.filename)
            image.save(os.path.join(app.config['UPLOAD_FOLDER'], image_filename))
        
        db.execute('INSERT INTO messages (sender_id, receiver_id, content, image, created_at) VALUES (?, ?, ?, ?, ?)',
                   (session['user_id'], receiver['id'], content, image_filename, datetime.now()))
        db.commit()
    
    return redirect(url_for('dm_conversation', username=username))

@app.route('/check_new_messages/<username>', methods=['GET'])
def check_new_messages(username):
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Unauthorized'})
    
    db = get_db()
    other_user = db.execute('SELECT id FROM users WHERE username = ?', (username,)).fetchone()
    
    if not other_user:
        return jsonify({'success': False, 'message': 'User not found'})
    
    last_message_id = request.args.get('last_message_id', 0, type=int)
    
    new_messages = db.execute('''
        SELECT m.*, u.username, u.pfp
        FROM messages m
        JOIN users u ON m.sender_id = u.id
        WHERE ((m.sender_id = ? AND m.receiver_id = ?) OR (m.sender_id = ? AND m.receiver_id = ?))
        AND m.id > ?
        ORDER BY m.created_at ASC
    ''', (session['user_id'], other_user['id'], other_user['id'], session['user_id'], last_message_id)).fetchall()
    
    if new_messages:
        return jsonify({
            'success': True,
            'messages': [{
                'id': message['id'],
                'content': message['content'],
                'sender_id': message['sender_id'],
                'username': message['username'],
                'pfp': message['pfp'],
                'created_at': message['created_at'],
                'image': message['image']
            } for message in new_messages]
        })
    else:
        return jsonify({'success': False, 'message': 'No new messages'})
    
@app.route('/delete_group/<int:group_id>', methods=['POST'])
def delete_group(group_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    db = get_db()
    db.execute('DELETE FROM groups WHERE id = ?', (group_id,))
    db.commit()
    
    return redirect(url_for('groups'))

@app.route('/start_dm', methods=['POST'])
def start_dm():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    username = request.form['username']
    return redirect(url_for('dm_conversation', username=username))

@app.route('/edit_message/<int:message_id>', methods=['POST'])
def edit_message(message_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    db = get_db()
    message = db.execute('SELECT * FROM messages WHERE id = ? AND sender_id = ?', (message_id, session['user_id'])).fetchone()
    if not message:
        abort(404)
    
    new_content = request.form['content']
    db.execute('UPDATE messages SET content = ? WHERE id = ?', (new_content, message_id))
    db.commit()
    
    return redirect(url_for('dm_conversation', username=request.form['username']))

@app.route('/delete_message/<int:message_id>', methods=['POST'])
def delete_message(message_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    db = get_db()
    db.execute('DELETE FROM messages WHERE id = ? AND sender_id = ?', (message_id, session['user_id']))
    db.commit()
    
    return redirect(url_for('dm_conversation', username=request.form['username']))

@app.route('/admin')
def admin_panel():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    user = get_user_by_id(session['user_id'])
    if not user or user['username'] != '123':
        return redirect(url_for('login'))
    
    db = get_db()
    users = db.execute('SELECT * FROM users ORDER BY created_at DESC').fetchall()
    tweets = db.execute('''
        SELECT t.*, u.username 
        FROM tweets t 
        JOIN users u ON t.user_id = u.id 
        ORDER BY t.created_at DESC
    ''').fetchall()
    groups = db.execute('''
        SELECT g.*, COUNT(gm.user_id) as member_count 
        FROM groups g 
        LEFT JOIN group_members gm ON g.id = gm.group_id 
        GROUP BY g.id 
        ORDER BY g.created_at DESC
    ''').fetchall()

    user_count = db.execute('SELECT COUNT(*) as count FROM users').fetchone()['count']
    tweet_count = db.execute('SELECT COUNT(*) as count FROM tweets').fetchone()['count']
    group_count = db.execute('SELECT COUNT(*) as count FROM groups').fetchone()['count']

    return render_template('admin_panel.html', 
                           users=users, 
                           tweets=tweets, 
                           groups=groups, 
                           user_count=user_count, 
                           tweet_count=tweet_count, 
                           group_count=group_count)

def get_all_users():
    db = get_db()
    users = db.execute('SELECT * FROM users').fetchall()
    return [dict(user) for user in users]

def get_all_tweets():
    db = get_db()
    tweets = db.execute('SELECT t.*, u.username FROM tweets t JOIN users u ON t.user_id = u.id ORDER BY t.created_at DESC').fetchall()
    return [dict(tweet) for tweet in tweets]

def get_all_groups():
    db = get_db()
    groups = db.execute('SELECT * FROM groups ORDER BY created_at DESC').fetchall()
    return [dict(group) for group in groups]

@app.route('/admin/delete_user/<int:user_id>', methods=['POST'])
def delete_user(user_id):
    if 'user_id' not in session or get_user_by_id(session['user_id']).username != 'avery':
        return jsonify({'success': False, 'message': 'Unauthorized'})
    
    db = get_db()
    db.execute('DELETE FROM users WHERE id = ?', (user_id,))
    db.commit()
    return jsonify({'success': True})

@app.route('/admin/delete_tweet/<int:tweet_id>', methods=['POST'])
def delete_tweet_admin(tweet_id):
    if 'user_id' not in session or get_user_by_id(session['user_id']).username != 'avery':
        return jsonify({'success': False, 'message': 'Unauthorized'})
    
    db = get_db()
    db.execute('DELETE FROM tweets WHERE id = ?', (tweet_id,))
    db.commit()
    return jsonify({'success': True})

@app.route('/admin/delete_group/<int:group_id>', methods=['POST'])
def delete_group_admin(group_id):
    if 'user_id' not in session or get_user_by_id(session['user_id'])['username'] != 'avery':
        return jsonify({'success': False, 'message': 'Unauthorized'})
    
    db = get_db()
    db.execute('DELETE FROM groups WHERE id = ?', (group_id,))
    db.execute('DELETE FROM group_members WHERE group_id = ?', (group_id,))
    db.execute('DELETE FROM posts WHERE group_id = ?', (group_id,))
    db.commit()
    return jsonify({'success': True})


if __name__ == '__main__':
    app.run(debug=True, port=4771)
