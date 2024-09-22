from fastapi import FastAPI, HTTPException, Depends, Query
from fastapi.responses import PlainTextResponse
from models import User, UserCreate, UserAuthenticate, Token, RefreshToken
from models import BillCreate, Bill, BillResponse, init_db
from typing import Optional, List
from contextlib import asynccontextmanager
from datetime import datetime
from fastapi import status
import uuid
import pyqrcode
from qr2text import QR
from PIL import Image


@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_db()
    yield

app = FastAPI(
    title="Billing API",
    description="API для управління чеками",
    version="1.0.0",
    docs_url="/swagger",
    redoc_url="/redoc-docs",
    lifespan=lifespan
    )


@app.post("/register", status_code=status.HTTP_201_CREATED)
async def register(user: UserCreate):
    if await User.get_user_id(user.username):
        raise HTTPException(status_code=400, detail="Username already registered")
    await User.create(user)
    return {"message": "User registered successfully"}


@app.post("/login")
async def login(user: UserAuthenticate):
    if not await User.authenticate(user.username, user.password):
        raise HTTPException(status_code=400, detail="Invalid username or password")
    access_token = Token.create_access_token(username=user.username)
    new_refresh_token = Token.create_refresh_token(username=user.username)
    user_id = await User.get_user_id(user.username)
    await Token.save_tokens(
        user_id=user_id,
        access_token=access_token,
        refresh_token=new_refresh_token
    )
    return {
        "access_token": access_token,
        "refresh_token": new_refresh_token,
        "token_type": "bearer"
    }


@app.post("/refresh-token")
async def refresh_token(token: RefreshToken):
    username = await Token.verify_refresh_token(token.refresh_token)
    if not username:
        raise HTTPException(status_code=401, detail="Invalid refresh token")
    new_access_token = Token.create_access_token(username=username)
    user_id = await User.get_user_id(username)
    await Token.update_access_token(
        user_id=user_id,
        new_access_token=new_access_token
        )
    return {
        "access_token": new_access_token,
        "token_type": "bearer"
    }


@app.post("/bill", response_model=BillResponse, status_code=status.HTTP_201_CREATED)
async def create_bill(receipt_data: BillCreate, user_id: int = Depends(Token.get_current_user)):
    bill_id = (uuid.uuid4().int >> 64) % 100000
    bill_id_str = int(str(bill_id).ljust(5, '0'))
    receipt_entry = {
        "id": bill_id_str,
        "products": receipt_data.products,
        "payment": receipt_data.payment.model_dump(),
        "total": sum([product.quantity * product.price for product in receipt_data.products]),
        "created_at": datetime.now().timestamp(),
        "user_id": user_id,
        "notes": receipt_data.notes
    }
    await Bill.save_bill(receipt_entry)
    return BillResponse.from_receipt(receipt_entry)


@app.get("/bills", response_model=List[BillResponse])
async def get_bills(
    user_id: int = Depends(Token.get_current_user),
    date_from: Optional[str] = None,
    date_to: Optional[str] = None,
    min_total: Optional[float] = None,
    max_total: Optional[float] = None,
    payment_type: Optional[str] = None,
    limit: int = 10,
    offset: int = 0
):
    receipts = await Bill.get_filtered_bills(
        user_id=user_id,
        date_from=date_from,
        date_to=date_to,
        min_total=min_total,
        max_total=max_total,
        payment_type=payment_type,
        limit=limit,
        offset=offset
    )
    return receipts


@app.get("/bill/{bill_id}", response_class=PlainTextResponse)
async def get_bill_text(bill_id: int, line_length: int = 40):
    receipt = await Bill.get_bill_by_id(bill_id)
    nameinbill = await Bill.get_user_by_bill_id(bill_id)
    if not receipt:
        raise HTTPException(status_code=404, detail="Receipt not found")
    formatted_receipt = format_bill(receipt, line_length, nameinbill)
    return formatted_receipt


def format_bill(receipt: BillResponse, line_length: int, nameinbill: dict) -> str:
    if receipt.payment.type == 'nano':
        receipt_text = image_to_ascii('img/nano-logo.png', line_length)+ "\n"
        receipt_text += f"{nameinbill['full_name']}/{nameinbill['username']}".center(line_length) + "\n"
        qr_code = generate_qr_ascii('https://blocklattice.io/block/CCC4996E6CFFB4C0035A7DD49CE95ADBD56CB14AAE10AB71261F8630F1BD6F82', line_length)
    else:
        receipt_text = f"{nameinbill['full_name']}/{nameinbill['username']}".center(line_length) + "\n"
        qr_code = generate_qr_ascii(receipt.url, line_length)
    receipt_text += "=" * line_length + "\n"
    for product in receipt.products:
        product_line = f"{product.quantity:.2f} x {product.price:,.2f}"
        receipt_text += f"{product_line:<{line_length}}\n"
        name_length = line_length - len(f"{product.total:,.2f}") - 1
        receipt_text += f"{product.name[:name_length]:<{name_length}} {product.total:>{len(f'{product.total:,.2f}')},.2f}\n"
        receipt_text += "-" * line_length + "\n"
    receipt_text += f"{'СУМА':<15}{receipt.total:>{line_length - 15},.2f}\n"
    receipt_text += f"{'Оплата':<15}{receipt.payment.amount:>{line_length - 15},.2f}\n"
    receipt_text += f"{'Решта':<15}{receipt.change:>{line_length - 15},.2f}\n"
    receipt_text += "=" * line_length + "\n"
    receipt_text += f"{receipt.created_at:^{line_length}}\n"
    receipt_text += f"{'Дякуємо за покупку!':^{line_length}}\n"
    receipt_text += "\n" + qr_code
    return receipt_text


def generate_qr_ascii(qr_code_link: str, line_length: int) -> str:
    QR.from_text = classmethod(from_text_mock)
    qr = QR.from_text(qr_code_link)
    qr_ascii = qr.to_ascii_art(trim=True, pad=0)
    qr_lines = qr_ascii.splitlines()
    centered_qr_lines = [
        line.center(line_length) for line in qr_lines
    ]

    return '\n'.join(centered_qr_lines)


def image_to_ascii(image_path: str, output_width: int = 100) -> str:
    ASCII_CHARS = "@%#*+=-:. "
    image = Image.open(image_path)
    grayscale_image = image.convert("L")
    original_width, original_height = grayscale_image.size
    aspect_ratio = original_height / original_width
    output_height = int(aspect_ratio * output_width * 0.55)
    resized_image = grayscale_image.resize((output_width, output_height))
    pixels = list(resized_image.getdata())
    scale_factor = (255 // len(ASCII_CHARS)) + 1
    ascii_art = ""
    for y in range(output_height):
        line = "".join(ASCII_CHARS[pixel // scale_factor] for pixel in pixels[y * output_width:(y + 1) * output_width])
        ascii_art += line + "\n"
    return ascii_art


def from_text_mock(cls, text: str) -> 'QR':
    code = pyqrcode.create(text, encoding='UTF-8', error='L')
    data = code.text().splitlines()
    qr = cls(len(data))
    qr.canvas.pixels = [
        [int(px) for px in row] for row in data
    ]
    return qr
