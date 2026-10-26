import base64
import json
import threading
import time
import urllib.error
import urllib.request
from http.server import HTTPServer

import jwt
import pytest

import main


# ---------- fixtures and helpers ----------

@pytest.fixture
def db(tmp_path, monkeypatch):
    """Empty database in a temp folder (connect() uses a relative path)."""
    monkeypatch.chdir(tmp_path)
    conn = main.connect()
    yield conn
    conn.close()


@pytest.fixture
def server(db):
    """Run the real handler on a free port; yields its base URL."""
    httpd = HTTPServer(("127.0.0.1", 0), main.MyServer)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{httpd.server_port}"
    httpd.shutdown()
    httpd.server_close()


def request(method, url, data=None, headers=None):
    """Return (status, body) without raising on 4xx/5xx."""
    req = urllib.request.Request(url, data=data, method=method,
                                 headers=headers or {})
    try:
        with urllib.request.urlopen(req) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as err:
        return err.code, err.read()


def exp_of(conn, kid):
    return conn.execute("SELECT exp FROM keys WHERE kid = ?",
                        (kid,)).fetchone()[0]


# ---------- database tests ----------

def test_connect_creates_table(db):
    columns = [row[1] for row in db.execute("PRAGMA table_info(keys)")]
    assert columns == ["kid", "key", "exp"]


def test_save_key_stores_pkcs1_pem(db):
    main.save_key(db, main.pem, 12345)
    key, exp = db.execute("SELECT key, exp FROM keys").fetchone()
    assert key.startswith(b"-----BEGIN RSA PRIVATE KEY-----")
    assert exp == 12345


def test_seed_keys_adds_one_valid_and_one_expired(db):
    main.seed_keys(db)
    now = time.time()
    exps = [r[0] for r in db.execute("SELECT exp FROM keys")]
    assert len(exps) == 2
    assert sum(e > now for e in exps) == 1
    assert sum(e <= now for e in exps) == 1


def test_seed_keys_twice_adds_no_duplicates(db):
    main.seed_keys(db)
    main.seed_keys(db)
    assert db.execute("SELECT COUNT(*) FROM keys").fetchone()[0] == 2


def test_read_privatekey_valid(db):
    main.seed_keys(db)
    kid, pem = main.read_privatekey(db, expired=False)
    assert exp_of(db, kid) > time.time()
    assert pem.startswith(b"-----BEGIN RSA PRIVATE KEY-----")


def test_read_privatekey_expired(db):
    main.seed_keys(db)
    kid, _ = main.read_privatekey(db, expired=True)
    assert exp_of(db, kid) <= time.time()


def test_read_privatekey_returns_none_when_empty(db):
    assert main.read_privatekey(db, expired=False) is None
    assert main.read_privatekey(db, expired=True) is None


def test_read_all_valid_keys_skips_expired(db):
    main.seed_keys(db)
    main.save_key(db, main.pem, int(time.time()) + 600)
    rows = main.read_all_valid_keys(db)
    assert len(rows) == 2
    assert all(exp_of(db, kid) > time.time() for kid, _ in rows)


# ---------- POST /auth ----------

def test_auth_returns_valid_token(db, server):
    main.seed_keys(db)
    status, body = request("POST", server + "/auth")
    assert status == 200
    token = body.decode()
    kid = int(jwt.get_unverified_header(token)["kid"])
    assert exp_of(db, kid) > time.time()
    claims = jwt.decode(token, options={"verify_signature": False})
    assert claims["exp"] > time.time()


@pytest.mark.parametrize("query", ["?expired", "?expired=true"])
def test_auth_expired_uses_expired_key(db, server, query):
    main.seed_keys(db)
    status, body = request("POST", server + "/auth" + query)
    assert status == 200
    token = body.decode()
    kid = int(jwt.get_unverified_header(token)["kid"])
    assert exp_of(db, kid) <= time.time()
    claims = jwt.decode(token, options={"verify_signature": False})
    assert claims["exp"] < time.time()


def test_auth_returns_500_when_no_key(server):
    status, _ = request("POST", server + "/auth")
    assert status == 500


def test_auth_accepts_basic_auth_and_json_body(db, server):
    main.seed_keys(db)
    creds = base64.b64encode(b"userABC:password123").decode()
    status, _ = request("POST", server + "/auth",
                        headers={"Authorization": "Basic " + creds})
    assert status == 200
    payload = json.dumps({"username": "userABC",
                          "password": "password123"}).encode()
    status, _ = request("POST", server + "/auth", data=payload,
                        headers={"Content-Type": "application/json"})
    assert status == 200


# ---------- GET /.well-known/jwks.json ----------

def test_jwks_lists_only_valid_keys(db, server):
    main.seed_keys(db)
    status, body = request("GET", server + "/.well-known/jwks.json")
    assert status == 200
    keys = json.loads(body)["keys"]
    assert len(keys) == 1
    assert exp_of(db, int(keys[0]["kid"])) > time.time()
    assert keys[0]["alg"] == "RS256"
    assert keys[0]["kty"] == "RSA"


def test_jwks_empty_when_no_valid_keys(server):
    _, body = request("GET", server + "/.well-known/jwks.json")
    assert json.loads(body) == {"keys": []}


def test_token_verifies_with_jwks_key(db, server):
    main.seed_keys(db)
    _, body = request("POST", server + "/auth")
    token = body.decode()
    _, jwks_body = request("GET", server + "/.well-known/jwks.json")
    kid = jwt.get_unverified_header(token)["kid"]
    jwk = next(k for k in json.loads(jwks_body)["keys"] if k["kid"] == kid)
    public_key = jwt.algorithms.RSAAlgorithm.from_jwk(json.dumps(jwk))
    claims = jwt.decode(token, public_key, algorithms=["RS256"])
    assert claims["user"] == "username"


def test_expired_token_kid_not_in_jwks(db, server):
    main.seed_keys(db)
    _, body = request("POST", server + "/auth?expired")
    kid = jwt.get_unverified_header(body.decode())["kid"]
    _, jwks_body = request("GET", server + "/.well-known/jwks.json")
    assert kid not in [k["kid"] for k in json.loads(jwks_body)["keys"]]


# ---------- unsupported methods and paths ----------

@pytest.mark.parametrize("method,path", [
    ("PUT", "/auth"),
    ("PATCH", "/auth"),
    ("DELETE", "/auth"),
    ("HEAD", "/auth"),
    ("GET", "/auth"),
    ("POST", "/nope"),
    ("GET", "/nope"),
    ("POST", "/.well-known/jwks.json"),
])
def test_unsupported_requests_return_405(server, method, path):
    status, _ = request(method, server + path)
    assert status == 405


# ---------- helper ----------

def test_int_to_base64_encodes_65537_as_aqab():
    assert main.int_to_base64(65537) == "AQAB"
