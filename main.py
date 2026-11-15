import base64, csv, hashlib, hmac, json, os, secrets, sqlite3, time
from datetime import date as Date
from pathlib import Path
from typing import Optional

from fastapi import Depends, FastAPI, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

BASE = Path(__file__).parent
DATA = BASE / "data"
QUANTILES = [f"{i / 10:.1f}" for i in range(1, 10)]


def read_csv(path: Path) -> list:
    raw = path.read_bytes()
    try:
        text = raw.decode("utf-8-sig")
    except UnicodeDecodeError:
        text = raw.decode("cp1251")
    lines = [l.strip().strip('"') for l in text.splitlines() if l.strip()]
    return list(csv.DictReader(lines))


ROUTES = {}
for r in read_csv(DATA / "routes.csv"):
    origin, dest = [s.strip() for s in r["name"].split("—")]
    ROUTES[(origin.lower(), dest.lower())] = {
        "route": r["route"], "origin": origin, "destination": dest,
        "base_price": float(r["base_price"]),
        "sensitivity": float(r["price_sensitivity"]),
        "price_min": float(r["price_min"]), "price_max": float(r["price_max"]),
    }

FORECAST = {}
for r in read_csv(DATA / "my_forecast.csv"):
    FORECAST[(r["route"], r["date"])] = r
DATES = sorted({d for _, d in FORECAST})



def db():
    con = sqlite3.connect(DATA / "app.db")
    con.execute("CREATE TABLE IF NOT EXISTS users(username TEXT PRIMARY KEY, salt TEXT, hash TEXT)")
    return con


def _secret() -> bytes:
    if os.environ.get("SECRET_KEY"):
        return os.environ["SECRET_KEY"].encode()
    f = DATA / ".secret"
    if not f.exists():
        f.write_text(secrets.token_hex(32))
    return f.read_bytes().strip()


SECRET = _secret()


def hash_pw(password: str, salt: bytes) -> str:
    return hashlib.scrypt(password.encode(), salt=salt, n=2 ** 14, r=8, p=1).hex()


def sign(body: str) -> str:
    mac = hmac.new(SECRET, body.encode(), hashlib.sha256).digest()
    return base64.urlsafe_b64encode(mac).decode().rstrip("=")


def make_token(username: str) -> str:
    payload = {"u": username, "exp": time.time() + 12 * 3600}
    body = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
    return f"{body}.{sign(body)}"


bearer = HTTPBearer(auto_error=False)


def current_user(cred: Optional[HTTPAuthorizationCredentials] = Depends(bearer)) -> str:
    if not cred:
        raise HTTPException(401, "Войдите в систему, чтобы получить прогноз")
    try:
        body, sig = cred.credentials.split(".")
        data = json.loads(base64.urlsafe_b64decode(body + "=" * (-len(body) % 4)))
        ok = hmac.compare_digest(sign(body), sig)
    except Exception:
        raise HTTPException(401, "Неверный токен, войдите снова")
    if not ok or data["exp"] < time.time():
        raise HTTPException(401, "Сессия истекла, войдите снова")
    return data["u"]


app = FastAPI(title="Решись Авиа")


class Credentials(BaseModel):
    username: str = Field(min_length=3, max_length=32)
    password: str = Field(min_length=6, max_length=128)


class PredictIn(BaseModel):
    origin: str
    destination: str
    date: Date
    price: float = Field(ge=0, le=1_000_000)


@app.post("/api/register")
def register(c: Credentials):
    salt = secrets.token_bytes(16)
    try:
        with db() as con:
            con.execute("INSERT INTO users VALUES (?,?,?)",
                        (c.username, salt.hex(), hash_pw(c.password, salt)))
    except sqlite3.IntegrityError:
        raise HTTPException(409, "Такое имя уже занято")
    return {"token": make_token(c.username), "username": c.username}


@app.post("/api/login")
def login(c: Credentials):
    row = db().execute("SELECT salt, hash FROM users WHERE username=?", (c.username,)).fetchone()
    if not row or not hmac.compare_digest(row[1], hash_pw(c.password, bytes.fromhex(row[0]))):
        raise HTTPException(401, "Неверное имя или пароль")
    return {"token": make_token(c.username), "username": c.username}


@app.get("/api/meta")
def meta():
    return {"routes": list(ROUTES.values()), "date_min": DATES[0], "date_max": DATES[-1]}


def wish(base_demand: float, route: dict, price: float) -> float:
    return base_demand - route["sensitivity"] * (price - route["base_price"])


@app.post("/api/predict")
def predict(p: PredictIn, user: str = Depends(current_user)):
    route = ROUTES.get((p.origin.strip().lower(), p.destination.strip().lower()))
    if not route:
        raise HTTPException(404, "Такого маршрута нет. Доступны рейсы из Москвы в 5 городов")
    row = FORECAST.get((route["route"], p.date.isoformat()))
    if not row:
        raise HTTPException(404, f"Нет прогноза на {p.date}. Данные: {DATES[0]} – {DATES[-1]}")
    seats = int(float(row["seats"]))

    def sales(w: float) -> float:
        return min(seats, max(0.0, w))

    w_med = wish(float(row["0.5_base_demand"]), route, p.price)
    scenarios = []
    for q in QUANTILES:
        w = wish(float(row[f"{q}_base_demand"]), route, p.price)
        scenarios.append({"quantile": float(q), "wish": round(w, 1), "sales": round(sales(w), 1)})
    return {
        "route": route["route"], "origin": route["origin"], "destination": route["destination"],
        "date": p.date.isoformat(), "price": p.price, "base_price": route["base_price"],
        "price_min": route["price_min"], "price_max": route["price_max"],
        "seats": seats, "wish": round(w_med, 1), "sales": round(sales(w_med), 1),
        "scenarios": scenarios,
    }


app.mount("/", StaticFiles(directory=BASE / "static", html=True), name="static")
