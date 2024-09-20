import aiosqlite
from passlib.context import CryptContext
from datetime import datetime, timedelta, timezone
from jose import jwt

pwd_context = CryptContext(schemes=["pbkdf2_sha256"], deprecated="auto")

DB_PATH = "database.db"


SECRET_KEY = "DATAENCRYPTIONSTANDARDISABESTSYMMETRIC-KEYALGORITHMFORTHEENCRYPTION"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
REFRESH_TOKEN_EXPIRE_DAYS = 30


async def init_db():
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute('''CREATE TABLE IF NOT EXISTS users (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            username TEXT UNIQUE NOT NULL,
                            password TEXT NOT NULL,
                            full_name TEXT)''')

        await db.execute('''CREATE TABLE IF NOT EXISTS tokens (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            user_id INTEGER NOT NULL,
                            access_token TEXT NOT NULL,
                            refresh_token TEXT NOT NULL,
                            access_expires_at TEXT NOT NULL,
                            refresh_expires_at TEXT NOT NULL,
                            FOREIGN KEY (user_id) REFERENCES users (id))''')

        await db.commit()


class User:
    @staticmethod
    async def create(username, password, full_name):
        hashed_password = pwd_context.hash(password)
        async with aiosqlite.connect(DB_PATH) as db:
            await db.execute("INSERT INTO users (username, password, full_name) VALUES (?, ?, ?)",
                             (username, hashed_password, full_name))
            await db.commit()

    @staticmethod
    async def authenticate(username, password):
        async with aiosqlite.connect(DB_PATH) as db:
            async with db.execute("SELECT username, password FROM users WHERE username = ?", (username,)) as cursor:
                user = await cursor.fetchone()
                if user and pwd_context.verify(password, user[1]):
                    return True
        return False

    @staticmethod
    async def get_user_by_id(user_id):
        async with aiosqlite.connect(DB_PATH) as db:
            async with db.execute("SELECT * FROM users WHERE id = ?", (user_id,)) as cursor:
                return await cursor.fetchone()

    @staticmethod
    async def get_user_id(username: str):
        async with aiosqlite.connect(DB_PATH) as db:
            async with db.execute("SELECT id FROM users WHERE username = ?", (username,)) as cursor:
                row = await cursor.fetchone()
                return row[0]

    @staticmethod
    async def save_tokens(user_id: int, access_token: str, refresh_token: str):
        access_expires_at = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        refresh_expires_at = datetime.now(timezone.utc) + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)

        async with aiosqlite.connect(DB_PATH) as db:
            await db.execute('''
                INSERT INTO tokens (user_id, access_token, refresh_token, access_expires_at, refresh_expires_at) 
                VALUES (?, ?, ?, ?, ?)
            ''', (user_id, access_token, refresh_token, access_expires_at.isoformat(), refresh_expires_at.isoformat()))
            await db.commit()

    @staticmethod
    async def update_access_token(user_id: int, new_access_token: str):
        new_access_expires_at = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)

        async with aiosqlite.connect(DB_PATH) as db:
            await db.execute('''
                UPDATE tokens 
                SET access_token = ?, access_expires_at = ?
                WHERE user_id = ?
            ''', (new_access_token, new_access_expires_at.isoformat(), user_id))
            await db.commit()

    @staticmethod
    def create_access_token(username: str):
        to_encode = {"sub": username}
        expire = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        to_encode.update({"exp": expire})
        encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
        return encoded_jwt

    @staticmethod
    def create_refresh_token(username: str):
        to_encode = {"sub": username}
        expire = datetime.now(timezone.utc) + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
        to_encode.update({"exp": expire})
        encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
        return encoded_jwt

    @staticmethod
    async def verify_refresh_token(refresh_token: str):
        try:
            payload = jwt.decode(refresh_token, SECRET_KEY, algorithms=[ALGORITHM])
            if payload['exp'] < datetime.now(timezone.utc).timestamp():
                raise jwt.ExpiredSignatureError("Refresh token has expired")
            username = payload.get("sub")
            if not username:
                raise jwt.InvalidTokenError("Invalid token")
            return username
        except jwt.ExpiredSignatureError as e:
            raise e
        except jwt.InvalidTokenError as e:
            raise e
