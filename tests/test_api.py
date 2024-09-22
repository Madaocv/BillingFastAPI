import pytest
from unittest.mock import AsyncMock, patch
from fastapi.testclient import TestClient
from main import app
from models import Token, BillResponse
client = TestClient(app)


@pytest.mark.asyncio
@patch("models.User.get_user_id", new_callable=AsyncMock)
@patch("models.User.create", new_callable=AsyncMock)
async def test_registration(mock_create, mock_get_user_id):
    mock_get_user_id.return_value = None
    mock_create.return_value = None

    response = client.post("/register", json={
        "username": "testuser",
        "password": "testpassword",
        "full_name": "Test User"
    })

    assert response.status_code == 201
    assert response.json()["message"] == "User registered successfully"
    mock_get_user_id.assert_called_once_with("testuser")
    mock_create.assert_called_once()


@pytest.mark.asyncio
@patch("models.User.authenticate", new_callable=AsyncMock)
@patch("models.Token.save_tokens", new_callable=AsyncMock)
@patch("models.User.get_user_id", new_callable=AsyncMock)
async def test_login(mock_get_user_id, mock_save_tokens, mock_authenticate):
    mock_authenticate.return_value = True
    mock_get_user_id.return_value = 1
    mock_save_tokens.return_value = None

    response = client.post("/login", json={
        "username": "testuser",
        "password": "testpassword"
    })

    assert response.status_code == 200
    json_response = response.json()
    assert "access_token" in json_response
    assert "refresh_token" in json_response
    mock_authenticate.assert_called_once_with("testuser", "testpassword")


@pytest.mark.asyncio
@patch("models.asyncpg.connect", new_callable=AsyncMock)  # Замокати підключення до бази даних
@patch("models.Bill.save_bill", new_callable=AsyncMock)
@patch("models.Token.get_current_user", return_value=1)
async def test_create_bill(mock_get_current_user, mock_save_bill, mock_connect):
    mock_conn = AsyncMock()
    mock_connect.return_value = mock_conn
    mock_save_bill.return_value = None
    access_token = Token.create_access_token(username="testuser")
    headers = {"Authorization": f"Bearer {access_token}"}
    
    response = client.post("/bill", json={
        "products": [{"name": "Product1", "price": 10.0, "quantity": 2}],
        "payment": {"type": "cash", "amount": 25.0},
        "notes": "Test note"
    }, headers=headers)

    assert response.status_code == 201
    json_response = response.json()
    assert json_response["total"] == 20.0
    mock_save_bill.assert_called_once()


@pytest.mark.asyncio
@patch("models.asyncpg.connect", new_callable=AsyncMock)
@patch("models.Bill.get_filtered_bills", new_callable=AsyncMock)
@patch("models.Token.get_current_user", return_value=1)
async def test_get_bills(mock_get_current_user, mock_get_filtered_bills, mock_connect):
    mock_conn = AsyncMock()
    mock_connect.return_value = mock_conn
    mock_conn.fetchrow.return_value = {"id": 1}
    access_token = Token.create_access_token(username="testuser")
    headers = {"Authorization": f"Bearer {access_token}"}
    mock_get_filtered_bills.return_value = [
        {
            "id": 1,
            "products": [],
            "payment": {"type": "cash", "amount": 100.0},
            "total": 100.0,
            "change": 0.0,
            "created_at": "01.01.2024 12:00",
            "notes": None,
            "url": "http://127.0.0.1:8000/bill/1"
        }
    ]

    response = client.get("/bills", headers=headers)
    assert response.status_code == 200
    json_response = response.json()
    assert len(json_response) == 1
    assert json_response[0]["total"] == 100.0
    mock_get_filtered_bills.assert_called_once_with(
        user_id=1,
        date_from=None,
        date_to=None,
        min_total=None,
        max_total=None,
        payment_type=None,
        limit=10,
        offset=0
    )


@pytest.mark.asyncio
@patch("models.asyncpg.connect", new_callable=AsyncMock)
@patch("models.Bill.get_bill_by_id", new_callable=AsyncMock)
async def test_public_view_bill(mock_get_bill_by_id, mock_connect):
    mock_conn = AsyncMock()
    mock_connect.return_value = mock_conn
    mock_get_bill_by_id.return_value = BillResponse(
        id=1,
        products=[],
        payment={"type": "cash", "amount": 100.0},
        total=100.0,
        change=0.0,
        created_at="01.01.2024 12:00",
        notes=None,
        url="http://127.0.0.1:8000/bill/1"
    )

    response = client.get("/bill/1")
    assert response.status_code == 200
    assert "СУМА" in response.text
    mock_get_bill_by_id.assert_called_once_with(1)


@pytest.mark.asyncio
@patch("models.asyncpg.connect", new_callable=AsyncMock)
@patch("models.Bill.get_bill_by_id", new_callable=AsyncMock)
async def test_invalid_bill_request(mock_get_bill_by_id, mock_connect):
    mock_get_bill_by_id.return_value = None
    response = client.get("/bill/999")
    assert response.status_code == 404
    assert response.json()["detail"] == "Receipt not found"
    mock_get_bill_by_id.assert_called_once_with(999)
