import sqlite3

# Connect to the database
conn = sqlite3.connect('db.sqlite3')
cursor = conn.cursor()

# Keep users 'avery' and 'asd'
cursor.execute("SELECT id FROM users WHERE username IN ('avery', 'asd')")
keep_user_ids = [row[0] for row in cursor.fetchall()]

# Delete all users except 'avery' and 'asd'
cursor.execute("DELETE FROM users WHERE id NOT IN ({})".format(','.join('?' * len(keep_user_ids))), keep_user_ids)

# Get avery's user id
cursor.execute("SELECT id FROM users WHERE username = 'avery'")
avery_id = cursor.fetchone()[0]

# Keep only the first two tweets from 'avery' and delete all other tweets
cursor.execute("""
    DELETE FROM tweets 
    WHERE id NOT IN (
        SELECT id FROM tweets 
        WHERE user_id = ? 
        ORDER BY created_at ASC 
        LIMIT 2
    )
""", (avery_id,))

# Delete all likes
cursor.execute("DELETE FROM likes")

# Delete all comments
cursor.execute("DELETE FROM comments")

# Delete all messages
cursor.execute("DELETE FROM messages")

# Delete all groups
cursor.execute("DELETE FROM groups")

# Delete all group members
cursor.execute("DELETE FROM group_members")

# Delete all posts
cursor.execute("DELETE FROM posts")

# Commit the changes and close the connection
conn.commit()
conn.close()

print("Database cleaned successfully.")