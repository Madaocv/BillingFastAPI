import asyncpg
from pydantic import BaseModel, Field, condecimal, constr
from typing import List, Optional, Literal, Dict, Any
from passlib.context import CryptContext
from datetime import datetime, timedelta, timezone
from jose import jwt, JWTError, ExpiredSignatureError
from fastapi import HTTPException, status, Depends
from fastapi.security import OAuth2PasswordBearer
import os

pwd_context = CryptContext(schemes=["pbkdf2_sha256"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://myuser:mypassword@localhost:5432/mydatabase")
SECRET_KEY = "DATAENCRYPTIONSTANDARDISABESTSYMMETRIC-KEYALGORITHMFORTHEENCRYPTION"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24
REFRESH_TOKEN_EXPIRE_DAYS = 30


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
    price: Optional[condecimal(gt=0)]
    quantity: condecimal(gt=0)


class ProductResponse(BaseModel):
    name: str
    price: float
    quantity: float
    total: float


class Payment(BaseModel):
    type: Literal["cash", "card", "nano"]
    amount: condecimal(gt=0)


class BillCreate(BaseModel):
    products: List[Product]
    payment: Payment
    notes: Optional[str] = None


class BillResponse(BaseModel):
    id: int
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
        if isinstance(receipt_entry["created_at"], datetime):
            receipt_entry["created_at"] = receipt_entry["created_at"].strftime("%d.%m.%Y %H:%M")
        else:
            # Якщо це все ще timestamp, перетворити його
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


async def init_db():
    conn = await asyncpg.connect(DATABASE_URL)
    await conn.execute('''CREATE TABLE IF NOT EXISTS users (
                            id SERIAL PRIMARY KEY,
                            username TEXT UNIQUE NOT NULL,
                            password TEXT NOT NULL,
                            full_name TEXT)''')

    await conn.execute('''CREATE TABLE IF NOT EXISTS tokens (
                            id SERIAL PRIMARY KEY,
                            user_id INTEGER NOT NULL REFERENCES users(id),
                            access_token TEXT NOT NULL,
                            refresh_token TEXT NOT NULL,
                            access_expires_at TIMESTAMPTZ NOT NULL,
                            refresh_expires_at TIMESTAMPTZ NOT NULL)''')

    await conn.execute('''CREATE TABLE IF NOT EXISTS bills (
                            id INTEGER PRIMARY KEY,
                            user_id INTEGER NOT NULL REFERENCES users(id),
                            created_at TIMESTAMPTZ NOT NULL,
                            total NUMERIC NOT NULL,
                            payment_type TEXT NOT NULL,
                            payment_amount NUMERIC NOT NULL,
                            notes TEXT)''')

    await conn.execute('''CREATE TABLE IF NOT EXISTS bill_products (
                            bill_id INTEGER REFERENCES bills(id),
                            name TEXT NOT NULL,
                            price NUMERIC NOT NULL,
                            quantity NUMERIC NOT NULL)''')
    await conn.close()


class User:
    @staticmethod
    async def create(user: UserCreate):
        hashed_password = pwd_context.hash(user.password)
        conn = await asyncpg.connect(DATABASE_URL)
        await conn.execute("INSERT INTO users (username, password, full_name) VALUES ($1, $2, $3)",
                           user.username, hashed_password, user.full_name)
        await conn.close()

    @staticmethod
    async def authenticate(username: str, password: str):
        conn = await asyncpg.connect(DATABASE_URL)
        user = await conn.fetchrow("SELECT password FROM users WHERE username = $1", username)
        await conn.close()
        if user and pwd_context.verify(password, user['password']):
            return True
        return False

    @staticmethod
    async def get_user_id(username: str):
        conn = await asyncpg.connect(DATABASE_URL)
        user = await conn.fetchrow("SELECT id FROM users WHERE username = $1", username)
        await conn.close()
        return user['id'] if user else None


class Bill:
    @staticmethod
    async def save_bill(bill_data: dict):
        conn = await asyncpg.connect(DATABASE_URL)
        await conn.execute('''
            INSERT INTO bills (id, user_id, created_at, total, payment_type, payment_amount, notes)
            VALUES ($1, $2, $3, $4, $5, $6, $7)
        ''', bill_data['id'], bill_data['user_id'], datetime.fromtimestamp(bill_data['created_at']),
            bill_data['total'], bill_data['payment']['type'], bill_data['payment']['amount'], bill_data.get('notes'))

        for product in bill_data['products']:
            await conn.execute('''
                INSERT INTO bill_products (bill_id, name, price, quantity)
                VALUES ($1, $2, $3, $4)
            ''', bill_data['id'], product.name, product.price, product.quantity)

        await conn.close()

    @staticmethod
    async def get_filtered_bills(user_id: int, date_from: Optional[str] = None, date_to: Optional[str] = None, 
                                 min_total: Optional[float] = None, max_total: Optional[float] = None,
                                 payment_type: Optional[str] = None, limit: int = 10, offset: int = 0) -> List[BillResponse]:
        
        query = "SELECT * FROM bills WHERE user_id = $1"
        params = [user_id]

        if date_from:
            try:
                date_from_datetime = datetime.strptime(date_from, "%Y-%m-%d")
            except ValueError:
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                                    detail="Неправильна дата у параметрі 'date_from'. Перевірте формат і коректність.")
            date_from_datetime = datetime.strptime(date_from, "%Y-%m-%d")
            query += f" AND created_at >= ${len(params) + 1}"
            params.append(date_from_datetime)
        
        if date_to:
            try:
                date_to_datetime = datetime.strptime(date_to, "%Y-%m-%d")
            except ValueError:
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                                    detail="Неправильна дата у параметрі 'date_to'. Перевірте формат і коректність.")
            date_to_datetime = datetime.strptime(date_to, "%Y-%m-%d")
            query += f" AND created_at <= ${len(params) + 1}"
            params.append(date_to_datetime)
        
        if min_total is not None:
            query += f" AND total >= ${len(params) + 1}"
            params.append(float(min_total))
        
        if max_total is not None:
            query += f" AND total <= ${len(params) + 1}"
            params.append(float(max_total))
        
        if payment_type:
            query += f" AND payment_type = ${len(params) + 1}"
            params.append(str(payment_type))

        query += f" LIMIT ${len(params) + 1} OFFSET ${len(params) + 2}"
        params.extend([limit, offset])

        conn = await asyncpg.connect(DATABASE_URL)
        rows = await conn.fetch(query, *params)
        
        bills = []
        for row in rows:
            bill = {
                "id": row["id"],
                "user_id": row["user_id"],
                "created_at": row["created_at"],
                "total": row["total"],
                "payment": {"type": row["payment_type"], "amount": row["payment_amount"]},
                "notes": row["notes"],
                "products": []
            }
            products = await conn.fetch("SELECT name, price, quantity FROM bill_products WHERE bill_id = $1", row["id"])
            for product in products:
                bill["products"].append({
                    "name": product["name"],
                    "price": product["price"],
                    "quantity": product["quantity"],
                })

            bills.append(BillResponse.from_receipt(bill))
        
        await conn.close()
        return bills

    @staticmethod
    async def get_bill_by_id(bill_id: int) -> Optional[BillResponse]:
        conn = await asyncpg.connect(DATABASE_URL)
        try:
            row = await conn.fetchrow("SELECT * FROM bills WHERE id = $1", bill_id)
            if not row:
                return None
            receipt = {
                "id": row["id"],
                "user_id": row["user_id"],
                "created_at": row["created_at"],
                "total": row["total"],
                "payment": {"type": row["payment_type"], "amount": row["payment_amount"]},
                "notes": row["notes"],
                "products": []
            }

            products = await conn.fetch("SELECT name, price, quantity FROM bill_products WHERE bill_id = $1", bill_id)
            for product in products:
                receipt["products"].append({
                    "name": product["name"],
                    "price": product["price"],
                    "quantity": product["quantity"],
                    "total": product["price"] * product["quantity"]
                })

            return BillResponse.from_receipt(receipt)
        finally:
            await conn.close()

    @staticmethod
    async def get_user_by_bill_id(bill_id: int) -> Dict[str, str]:
        conn = await asyncpg.connect(DATABASE_URL)
        try:
            bill_row = await conn.fetchrow("SELECT user_id FROM bills WHERE id = $1", bill_id)
            if not bill_row:
                raise HTTPException(status_code=404, detail="Bill not found")
            user_id = bill_row['user_id']
            user_info = await conn.fetchrow("SELECT username, full_name FROM users WHERE id = $1", user_id)
            if not user_info:
                raise HTTPException(status_code=404, detail="User not found")
            return {"username": user_info['username'], "full_name": user_info['full_name']}
        finally:
            await conn.close()


class Token:
    @staticmethod
    async def save_tokens(user_id: int, access_token: str, refresh_token: str):
        access_expires_at = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        refresh_expires_at = datetime.now(timezone.utc) + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)

        conn = await asyncpg.connect(DATABASE_URL)
        try:
            await conn.execute('''
                INSERT INTO tokens (user_id, access_token, refresh_token, access_expires_at, refresh_expires_at) 
                VALUES ($1, $2, $3, $4, $5)
            ''', user_id, access_token, refresh_token, access_expires_at, refresh_expires_at)
        finally:
            await conn.close()

    @staticmethod
    async def update_access_token(user_id: int, new_access_token: str):
        new_access_expires_at = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)

        conn = await asyncpg.connect(DATABASE_URL)
        try:
            await conn.execute('''
                UPDATE tokens 
                SET access_token = $1, access_expires_at = $2
                WHERE user_id = $3
            ''', new_access_token, new_access_expires_at, user_id)
        finally:
            await conn.close()

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
