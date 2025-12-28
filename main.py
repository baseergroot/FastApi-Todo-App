# main.py
from fastapi import FastAPI, Response, Request
from pydantic import BaseModel
import sqlite3
from jose import JWTError, jwt
from datetime import datetime, timedelta,timezone
import bcrypt
import json

app = FastAPI()
connection = sqlite3.connect("todo.db")
# connection.row_factory = sqlite3.Row
cursor = connection.cursor()

SECRET_KEY = "c3230e4792278d3b0450ef8c70e41f0eba73211deeabdcd7c2cf674dfd5831fa" # openssl rand -hex 32
ALGORITHM = "HS256"

class Token(BaseModel):
    access_token: str
    token_type: str


# this function will create the token
# for particular data
def create_access_token(data: dict):
    to_encode = data.copy()
    
    # expire time of the token
    expire = datetime.now(timezone.utc) + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    
    # return the generated token
    return encoded_jwt

def decode_access_token(token: str):
    # Decode using the same secret and algorithm
    payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    return payload

# print(create_access_token({"name": " uhdd"}))

cursor.execute('''
  CREATE TABLE IF NOT EXISTS users (
    user_id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT,
    username TEXT UNIQUE,
    password TEXT
  )
''')

cursor.execute('''
  CREATE TABLE IF NOT EXISTS todos (
    todo_id INTEGER PRIMARY KEY AUTOINCREMENT,
    todo TEXT NOT NULL,
    -- Add the foreign key here to link to a specific user
    user_id INTEGER NOT NULL, 
    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE
  )
''')

@app.get("/")
def read_root():
    return {"message": "Hello, FastAPI + uv! by baseer"}

class Todo(BaseModel):
    todo: str
    token: str

@app.get("/todos/{token}")
async def get_todos(token: str):
    payload = decode_access_token(token)
    cursor.execute("""
    SELECT * FROM todos WHERE user_id = ?
    """, (payload["user_id"],))
    todos = cursor.fetchall()
    todos_array = []
    for todo in todos:
        new_todo = list(todo)
        new_todo.pop()

        
        todos_array.append(new_todo)

    # print("array", todos_array)
    return {"todos": todos_array}

# @app.get("/test/{token}")
# async def get_todos(token: str):
#     payload = decode_access_token(token)
#     cursor.execute("""
#     SELECT * FROM todos WHERE user_id = ?
#     """, (payload["user_id"],))
#     todos = cursor.fetchall()
#     todos_array = []
#     for todo in todos:
#         new_todo = list(todo)
#         new_todo.pop()

        
#         todos_array.append(new_todo)

#     # print("array", todos_array)
#     return {"todos": todos_array}


@app.post("/todos/create")
async def create_todo(item: Todo, request: Request):
    token = item.token
    payload = decode_access_token(token)
    cursor.execute("INSERT INTO todos (todo, user_id) VALUES (?, ?)", (item.todo, payload['user_id']))
    connection.commit()
    print(item.todo)
    return item

@app.patch("/todos/update/{todo_id}")
async def update_todo(todo_id: int, updated_todo):
    cursor.execute("UPDATE todos SET todo = ? WHERE `todo_id = ?", (updated_todo, todo_id,))
    connection.commit()
    return todo_id
    

@app.delete("/todos/delete/{todo_id}")
async def delete_todo(todo_id: int):
    cursor.execute("DELETE FROM todos WHERE todo_id = ?", (todo_id,))
    connection.commit()
    return todo_id

# password hashing
def hash_password(password: str):
    # Convert string to bytes
    pwd_bytes = password.encode('utf-8')

    print("bytes: ", pwd_bytes)
    # Generate salt and hash
    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(pwd_bytes, salt)
    return hashed_password.decode('utf-8')  # Store this string in your DB

# --- Verifying (bcrypt.compare equivalent) ---
def verify_password(plain_password: str, hashed_password: str):
    password_byte_enc = plain_password.encode('utf-8')
    hashed_password_bytes = hashed_password.encode('utf-8')
    return bcrypt.checkpw(password_byte_enc, hashed_password_bytes)

class Signup(BaseModel):
    name: str
    username: str
    password: str

@app.post("/auth/signup")
async def signup(signup: Signup, response: Response):
    print("signup route called")
    hashed_password = hash_password(signup.password)
    print("hashed passwd", hashed_password)
    cursor.execute("INSERT INTO users (name, username, password) VALUES (?,?,?)", (signup.name, signup.username, hashed_password))
    connection.commit()

    cursor.execute("SELECT * FROM users WHERE username = ?", (signup.username,))

    user = cursor.fetchone()
    response.set_cookie(key="token", value=create_access_token({"user_id": user[0],"name": signup.name, "username": signup.username}))
    # print(create_access_token({"username": username}), user[0])
    return { "success": True, "message": "user created", "token": create_access_token({"user_id": user[0],"name": signup.name, "username": signup.username}) }

class Login(BaseModel):
    username: str
    password: str

@app.post("/auth/login")
async def login(login: Login, response: Response):
    cursor.execute("SELECT * FROM users WHERE username = ?", (login.username,))
    user = cursor.fetchone()
    if not user:
        return "User not exist"
    print(user)
    correct_password = verify_password(login.password, user[3])
    if not correct_password:
        return "Wrong credintials"
    response.set_cookie(key="token", value=create_access_token({"user_id": user[0],"name": user[1], "username": login.username}))
    return { "success": True, "message": "Logged in Success", "token": create_access_token({"user_id": user[0],"name": user[1], "username": login.username})}

class Check(BaseModel):
    token: str

@app.post("/auth/check")
async def get_profile(request: Request, check: Check):
    token = check.token
    if not token:
        print("message", "token is empty")
        return {"success": False, "message": "token is empty"}
    payload = decode_access_token(token)
    print(token, payload)
    if not payload["user_id"]:
        print("message", "token is invalid")
        return {"success": False, "message": "token is invalid"}
     # 2. Use JSON_GROUP_ARRAY to nest todos inside the user record
    
    cursor.execute("SELECT user_id, name, username FROM users WHERE user_id = ?", (payload["user_id"],))
    user = cursor.fetchone()

    return {"user": user}


# get todos for logged in user
