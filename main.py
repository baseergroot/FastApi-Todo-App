
# main.py
from fastapi import FastAPI, Response, Request
from pydantic import BaseModel
import sqlite3
from jose import JWTError, jwt
from datetime import datetime, timedelta,timezone
import bcrypt
import json
import psycopg2
from dotenv import load_dotenv
import os

load_dotenv()
DATABASE_URL = os.getenv("DATABASE_URL")
app = FastAPI()


connection = None
cursor = None


SECRET_KEY = os.getenv("SECRET_KEY") # openssl rand -hex 32
ALGORITHM = os.getenv("ALGORITHM")

class Token(BaseModel):
    access_token: str
    token_type: str


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


@app.on_event("startup")
def startup():
    global connection, cursor

    connection = psycopg2.connect(DATABASE_URL)
    cursor = connection.cursor()

    cursor.execute("""
      CREATE TABLE IF NOT EXISTS users (
        user_id SERIAL PRIMARY KEY,
        name TEXT,
        username TEXT UNIQUE,
        password TEXT
      )
    """)

    cursor.execute("""
      CREATE TABLE IF NOT EXISTS todos (
        todo_id SERIAL PRIMARY KEY,
        todo TEXT NOT NULL,
        user_id INTEGER NOT NULL,
        FOREIGN KEY (user_id)
          REFERENCES users(user_id)
          ON DELETE CASCADE
      )
    """)

    connection.commit()

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
    SELECT * FROM todos WHERE user_id = %s
    """, (payload["user_id"],))
    todos = cursor.fetchall()
    todos_array = []
    for todo in todos:
        new_todo = list(todo)
        new_todo.pop()

        
        todos_array.append(new_todo)

    # print("array", todos_array)
    return {"todos": todos_array}


@app.post("/todos/create")
async def create_todo(item: Todo, request: Request):
    token = item.token
    payload = decode_access_token(token)
    cursor.execute("INSERT INTO todos (todo, user_id) VALUES (%s, %s)", (item.todo, payload['user_id']))
    connection.commit()
    print(item.todo)
    return item

@app.patch("/todos/update/{todo_id}")
async def update_todo(todo_id: int, updated_todo):
    cursor.execute("UPDATE todos SET todo = %s WHERE `todo_id = %s", (updated_todo, todo_id,))
    connection.commit()
    return todo_id


@app.delete("/todos/delete/{todo_id}")
async def delete_todo(todo_id: int):
    cursor.execute("DELETE FROM todos WHERE todo_id = %s", (todo_id,))
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
    cursor.execute("INSERT INTO users (name, username, password) VALUES (%s,%s,%s)", (signup.name, signup.username, hashed_password))
    connection.commit()

    cursor.execute("SELECT * FROM users WHERE username = %s", (signup.username,))

    user = cursor.fetchone()
    response.set_cookie(key="token", value=create_access_token({"user_id": user[0],"name": signup.name, "username": signup.username}))
    # print(create_access_token({"username": username}), user[0])
    return { "success": True, "message": "user created", "token": create_access_token({"user_id": user[0],"name": signup.name, "username": signup.username}) }

class Login(BaseModel):
    username: str
    password: str

@app.post("/auth/login")
async def login(login: Login, response: Response):
    cursor.execute("SELECT * FROM users WHERE username = %s", (login.username,))
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
    
    cursor.execute("SELECT user_id, name, username FROM users WHERE user_id = %s", (payload["user_id"],))
    user = cursor.fetchone()

    return {"user": user}


