import aiosqlite
from pydantic import BaseModel, Field, condecimal, constr
from typing import List, Optional, Literal, Dict, Any
from passlib.context import CryptContext
from datetime import datetime, timedelta, timezone
from jose import jwt, JWTError, ExpiredSignatureError
from fastapi import HTTPException, status, Depends
from fastapi.security import OAuth2PasswordBearer


pwd_context = CryptContext(schemes=["pbkdf2_sha256"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")
DB_PATH = "database.db"
SECRET_KEY = "DATAENCRYPTIONSTANDARDISABESTSYMMETRIC-KEYALGORITHMFORTHEENCRYPTION"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60*24
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

        await db.execute('''CREATE TABLE IF NOT EXISTS bills (
                            id TEXT PRIMARY KEY,
                            user_id INTEGER NOT NULL,
                            created_at REAL NOT NULL,
                            total REAL NOT NULL,
                            payment_type TEXT NOT NULL,
                            payment_amount REAL NOT NULL,
                            notes TEXT,
                            FOREIGN KEY (user_id) REFERENCES users (id))''')

        await db.execute('''CREATE TABLE IF NOT EXISTS bill_products (
                            bill_id TEXT,
                            name TEXT NOT NULL,
                            price REAL NOT NULL,
                            quantity REAL NOT NULL,
                            FOREIGN KEY (bill_id) REFERENCES bills (id))''')
        await db.commit()


class UserCreate(BaseModel):
    username: str = Field(..., min_length=3, max_length=50)
    password: str = Field(..., min_length=8)
    full_name: str = Field(..., min_length=3, max_length=100)


class UserAuthenticate(BaseModel):
    username: str
    password: str


class RefreshToken(BaseModel):
    refresh_token: str


class Product(BaseModel):
    name: str = Field(..., min_length=1)
    price: Optional[condecimal(gt=0)]  # Вартість повинна бути більше 0
    quantity: condecimal(gt=0)  # Кількість/вага повинна бути більше 0


class ProductResponse(BaseModel):
    name: str
    price: float
    quantity: float
    total: float


class Payment(BaseModel):
    type: Literal["cash", "card", "nano"]  # Тип повинен бути "cash" або "card"
    amount: condecimal(gt=0)  # Сума повинна бути більше 0


class BillCreate(BaseModel):
    products: List[Product]
    payment: Payment
    notes: Optional[str] = None


class BillResponse(BaseModel):
    id: str
    products: List[ProductResponse]
    payment: Payment
    total: float
    change: float
    created_at: str
    notes: Optional[str] = None
    url: str

    @classmethod
    def from_receipt(cls, receipt_entry: Dict[str, Any]):
        receipt_entry["change"] = receipt_entry["payment"]["amount"] - receipt_entry["total"] if receipt_entry["payment"]["type"] == "cash" else 0
        receipt_entry["created_at"] = datetime.fromtimestamp(receipt_entry["created_at"]).strftime("%d.%m.%Y %H:%M")
        products = []
        for product in receipt_entry["products"]:
            if isinstance(product, Product):
                product_dict = product.model_dump()
                product_dict["total"] = float(product.price) * float(product.quantity)
            else:
                product["total"] = float(product["price"]) * float(product["quantity"])
                product_dict = product
            products.append(product_dict)
        receipt_entry["products"] = products
        receipt_entry["url"] = f'http://127.0.0.1:8000/bill/{receipt_entry["id"]}'
        return cls(**receipt_entry)


class User:
    @staticmethod
    async def create(user: UserCreate):
        hashed_password = pwd_context.hash(user.password)
        async with aiosqlite.connect(DB_PATH) as db:
            await db.execute("INSERT INTO users (username, password, full_name) VALUES (?, ?, ?)",
                             (user.username, hashed_password, user.full_name))
            await db.commit()

    @staticmethod
    async def authenticate(username: str, password: str):
        async with aiosqlite.connect(DB_PATH) as db:
            async with db.execute("SELECT username, password FROM users WHERE username = ?", (username,)) as cursor:
                user = await cursor.fetchone()
                if user and pwd_context.verify(password, user[1]):
                    return True
        return False

    @staticmethod
    async def get_user_id(username: str):
        async with aiosqlite.connect(DB_PATH) as db:
            async with db.execute("SELECT id FROM users WHERE username = ?", (username,)) as cursor:
                return await cursor.fetchone()


class Token:
    @staticmethod
    async def save_tokens(user_id: tuple, access_token: str, refresh_token: str):
        access_expires_at = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        refresh_expires_at = datetime.now(timezone.utc) + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)

        async with aiosqlite.connect(DB_PATH) as db:
            await db.execute('''
                INSERT INTO tokens (user_id, access_token, refresh_token, access_expires_at, refresh_expires_at) 
                VALUES (?, ?, ?, ?, ?)
            ''', (user_id[0], access_token, refresh_token, access_expires_at.isoformat(), refresh_expires_at.isoformat()))
            await db.commit()

    @staticmethod
    async def update_access_token(user_id: tuple, new_access_token: str):
        new_access_expires_at = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)

        async with aiosqlite.connect(DB_PATH) as db:
            await db.execute('''
                UPDATE tokens 
                SET access_token = ?, access_expires_at = ?
                WHERE user_id = ?
            ''', (new_access_token, new_access_expires_at.isoformat(), user_id[0]))
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
                raise ExpiredSignatureError("Refresh token has expired")
            return payload.get("sub")
        except ExpiredSignatureError as e:
            raise HTTPException(status_code=401, detail="Refresh token has expired")
        except JWTError as e:
            raise HTTPException(status_code=401, detail="Invalid token signature")

    @staticmethod
    async def verify_access_token(token: str) -> str:
        try:
            payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
            return payload.get("sub")
        except JWTError:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")

    @staticmethod
    async def get_current_user(token: str = Depends(oauth2_scheme)) -> int:
        username = await Token.verify_access_token(token)
        if not username:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token credentials")

        user_id = await User.get_user_id(username)
        if not user_id:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found")
        return user_id


class Bill:
    @staticmethod
    async def save_bill(bill_data: dict):
        async with aiosqlite.connect(DB_PATH) as db:
            await db.execute('''
                INSERT INTO bills (id, user_id, created_at, total, payment_type, payment_amount, notes)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (bill_data['id'],
                  bill_data['user_id'][0],
                  bill_data['created_at'],
                  float(bill_data['total']),
                  bill_data['payment']['type'],
                  float(bill_data['payment']['amount']),
                  bill_data.get('notes')))

            for product in bill_data['products']:
                await db.execute('''
                    INSERT INTO bill_products (bill_id, name, price, quantity)
                    VALUES (?, ?, ?, ?)
                ''', (bill_data['id'],
                      product.name,
                      float(product.price),
                      float(product.quantity)))

            await db.commit()

    @staticmethod
    async def get_filtered_bills(
        user_id: int,
        date_from: Optional[str] = None,
        date_to: Optional[str] = None,
        min_total: Optional[float] = None,
        max_total: Optional[float] = None,
        payment_type: Optional[str] = None,
        limit: int = 10,
        offset: int = 0
    ) -> List[BillResponse]:

        query = "SELECT * FROM bills WHERE user_id = ?"
        params = [user_id[0]]

        if date_from:
            date_from_timestamp = datetime.strptime(date_from, "%Y-%m-%d").timestamp()
            query += " AND created_at >= ?"
            params.append(date_from_timestamp)
        if date_to:
            date_to_timestamp = datetime.strptime(date_to, "%Y-%m-%d").timestamp()
            query += " AND created_at <= ?"
            params.append(date_to_timestamp)
        if min_total is not None:
            query += " AND total >= ?"
            params.append(min_total)
        if max_total is not None:
            query += " AND total <= ?"
            params.append(max_total)
        if payment_type:
            query += " AND payment_type = ?"
            params.append(payment_type)

        query += " LIMIT ? OFFSET ?"
        params.extend([limit, offset])

        async with aiosqlite.connect(DB_PATH) as db:
            cursor = await db.execute(query, params)
            rows = await cursor.fetchall()
            bills = []
            for row in rows:
                bill = {
                    "id": row[0],
                    "user_id": row[1],
                    "created_at": row[2],
                    "total": row[3],
                    "payment": {"type": row[4], "amount": row[5]},
                    "notes": row[6],
                    "products": []
                }

                product_cursor = await db.execute("SELECT name, price, quantity FROM bill_products WHERE bill_id = ?", (bill["id"],))
                products = await product_cursor.fetchall()
                for product in products:
                    bill["products"].append({
                        "name": product[0],
                        "price": product[1],
                        "quantity": product[2],
                    })

                bills.append(BillResponse.from_receipt(bill))

            return bills

    @staticmethod
    async def get_bill_by_id(bill_id: str) -> Optional[BillResponse]:
        async with aiosqlite.connect(DB_PATH) as db:
            cursor = await db.execute("SELECT * FROM bills WHERE id = ?", (bill_id,))
            row = await cursor.fetchone()

            if not row:
                return None
            receipt = {
                "id": row[0],
                "user_id": row[1],
                "created_at": row[2],
                "total": row[3],
                "payment": {"type": row[4], "amount": row[5]},
                "notes": row[6],
                "products": []
            }

            product_cursor = await db.execute("SELECT name, price, quantity FROM bill_products WHERE bill_id = ?", (bill_id,))
            products = await product_cursor.fetchall()
            for product in products:
                receipt["products"].append({
                    "name": product[0],
                    "price": product[1],
                    "quantity": product[2],
                    "total": product[1] * product[2]
                })

            return BillResponse.from_receipt(receipt)

    @staticmethod
    async def get_user_by_bill_id(bill_id: str) -> Dict[str, str]:
        """
        Отримує інформацію про користувача (username та full_name) на основі bill_id
        """
        async with aiosqlite.connect(DB_PATH) as db:
            # Спочатку отримуємо user_id з таблиці bills
            cursor = await db.execute("SELECT user_id FROM bills WHERE id = ?", (bill_id,))
            bill_row = await cursor.fetchone()
            
            if not bill_row:
                raise HTTPException(status_code=404, detail="Bill not found")

            user_id = bill_row[0]

            # Тепер отримуємо username та full_name з таблиці users
            user_cursor = await db.execute("SELECT username, full_name FROM users WHERE id = ?", (user_id,))
            user_info = await user_cursor.fetchone()
            
            if not user_info:
                raise HTTPException(status_code=404, detail="User not found")

            return {"username": user_info[0], "full_name": user_info[1]}