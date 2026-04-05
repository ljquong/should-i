import base64
import hashlib
import hmac
import json
import os
import secrets
from dotenv import load_dotenv
from datetime import UTC, datetime, timedelta

from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from mysql.connector import Error, MySQLConnection
from pydantic import BaseModel, EmailStr, Field

from app.database import get_db

load_dotenv()

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:4173",
        "http://127.0.0.1:4173",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

JWT_SECRET = os.getenv("JWT_SECRET", "dev-secret-change-me")
JWT_ALGORITHM = "HS256"
JWT_EXPIRE_MINUTES = int(os.getenv("JWT_EXPIRE_MINUTES", "60"))


class RegisterRequest(BaseModel):
    first_name: str = Field(min_length=1, max_length=100)
    last_name: str = Field(min_length=1, max_length=100)
    username: str = Field(min_length=3, max_length=100)
    password: str = Field(min_length=8, max_length=128)
    email: EmailStr
    school: str = Field(min_length=1)
    address: str = Field(min_length=1)
    degree: str = Field(min_length=1)
    year: int = Field(ge=1, le=10)


class LoginRequest(BaseModel):
    username: str = Field(min_length=3, max_length=100)
    password: str = Field(min_length=8, max_length=128)


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user_id: int
    username: str


def hash_password(password: str) -> str:
    salt = secrets.token_hex(16)
    password_hash = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt.encode("utf-8"),
        100_000,
    )
    encoded_hash = base64.urlsafe_b64encode(password_hash).decode("utf-8")
    return f"{salt}${encoded_hash}"


def verify_password(password: str, stored_password: str) -> bool:
    try:
        salt, password_hash = stored_password.split("$", maxsplit=1)
    except ValueError:
        return False

    candidate_hash = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt.encode("utf-8"),
        100_000,
    )
    encoded_candidate = base64.urlsafe_b64encode(candidate_hash).decode("utf-8")
    return secrets.compare_digest(encoded_candidate, password_hash)


def _urlsafe_b64encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("utf-8")


def create_access_token(subject: str) -> str:
    header = {"alg": JWT_ALGORITHM, "typ": "JWT"}
    expiration = datetime.now(UTC) + timedelta(minutes=JWT_EXPIRE_MINUTES)
    payload = {"sub": subject, "exp": int(expiration.timestamp())}

    header_segment = _urlsafe_b64encode(
        json.dumps(header, separators=(",", ":")).encode("utf-8")
    )
    payload_segment = _urlsafe_b64encode(
        json.dumps(payload, separators=(",", ":")).encode("utf-8")
    )
    signing_input = f"{header_segment}.{payload_segment}".encode("utf-8")
    signature = hmac.new(
        JWT_SECRET.encode("utf-8"), signing_input, hashlib.sha256
    ).digest()
    signature_segment = _urlsafe_b64encode(signature)
    return f"{header_segment}.{payload_segment}.{signature_segment}"


@app.get("/")
def healthcheck() -> dict[str, str]:
    return {"status": "ok"}


@app.post(
    "/register",
    response_model=TokenResponse,
    status_code=status.HTTP_201_CREATED,
)
def register(
    payload: RegisterRequest, db: MySQLConnection = Depends(get_db)
) -> TokenResponse:
    cursor = db.cursor(dictionary=True)
    try:
        cursor.execute(
            "SELECT id FROM `User` WHERE username = %s OR email = %s",
            (payload.username, payload.email),
        )
        existing_user = cursor.fetchone()
        if existing_user is not None:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Username or email already registered",
            )

        hashed_password = hash_password(payload.password)
        cursor.execute(
            """
            INSERT INTO `User`
            (first_name, last_name, username, password, email, school, address, degree, year)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
            """,
            (
                payload.first_name,
                payload.last_name,
                payload.username,
                hashed_password,
                payload.email,
                payload.school,
                payload.address,
                payload.degree,
                payload.year,
            ),
        )
        db.commit()
        user_id = cursor.lastrowid
    except Error as exc:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to create user",
        ) from exc
    finally:
        cursor.close()

    access_token = create_access_token(str(user_id))
    return TokenResponse(
        access_token=access_token,
        user_id=user_id,
        username=payload.username,
    )


@app.post("/token", response_model=TokenResponse)
def login(payload: LoginRequest, db: MySQLConnection = Depends(get_db)) -> TokenResponse:
    cursor = db.cursor(dictionary=True)
    try:
        cursor.execute(
            "SELECT id, username, password FROM `User` WHERE username = %s",
            (payload.username,),
        )
        user = cursor.fetchone()
    except Error as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to load user",
        ) from exc
    finally:
        cursor.close()

    if user is None or not verify_password(payload.password, user["password"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password",
        )

    access_token = create_access_token(str(user["id"]))
    return TokenResponse(
        access_token=access_token,
        user_id=user["id"],
        username=user["username"],
    )

class GetMeRequest(BaseModel):
    username: str

class GetMeResponse(BaseModel):
    id: int
    first_name: str
    last_name: str
    username: str
    email: EmailStr
    school: str
    address: str
    degree: str
    year: int

@app.post("/getme", response_model=GetMeResponse)
def get_me(payload: GetMeRequest, db: MySQLConnection = Depends(get_db)):
    cursor = db.cursor(dictionary=True)
    try:
        cursor.execute(
            "SELECT id, first_name, last_name, username, email, school, address, degree, year FROM `User` WHERE username = %s",
            (payload.username,)
        )
        user = cursor.fetchone()
    except Error as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to fetch user",
        ) from exc
    finally:
        cursor.close()

    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )

    return GetMeResponse(**user)

class PredictRequest(BaseModel):
    course_name: str = Field(min_length=1, max_length=4)
    course_number: int = Field(ge=0)
    mandatory_attendance: bool = Field(False)
    exam_or_quiz: bool = Field(False)
    weather: str = Field(min_length=1, max_length=100)
    commute: int = Field(ge=0)
    core: bool = Field(False)

class PredictResponse(BaseModel):
    recommendation: str

def predict(attendance, exam, weather, commute, seriousness, core):
    if exam:
        return "GO TO CLASS"
    if attendance:
        return "GO TO CLASS"
    score = 0
    bad_weather = ("rainy", "snowy", "hail")
    good_weather = ("sunny", "clear", "chinook")
    if weather.lower() in bad_weather:
        score -= 1
    elif weather.lower() in good_weather:
        score += 1
    if commute > 60:
        score -= 1
    elif commute < 30:
        score += 0.5
    if seriousness == 3:
        score += 2
    elif seriousness == 2:
        score += 1
    elif seriousness == 1:
        score -= 1
    if core:
        score += 1
    else:
        score -= 1
    if score >= 2:
        return "GO TO CLASS"
    elif score >= 0:
        return "YOUR CALL"
    else:
        return "SKIP"

@app.post("/predict", response_model=PredictResponse)
def predict(payload: PredictRequest, db: MySQLConnection = Depends(get_db)):
    cursor = db.cursor(dictionary=True)
    try:
        cursor.execute(
            """
            SELECT seriousness
            FROM Course
            WHERE course_code = %s AND course_number = %s
            """,
            (payload.course_name.upper(), payload.course_number)
        )
        course = cursor.fetchone()
        if not course:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Course not found"
            )
        seriousness = course["seriousness"]
    except Error as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to fetch course seriousness"
        ) from exc
    finally:
        cursor.close()
    recommendation = predict(payload.mandatory_attendance, payload.exam_or_quiz, payload.weather, payload.commute, seriousness, payload.core)
    return PredictResponse(recommendation=recommendation)