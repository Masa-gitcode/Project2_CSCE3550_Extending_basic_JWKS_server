from http.server import BaseHTTPRequestHandler, HTTPServer
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from urllib.parse import urlparse, parse_qs
import base64
import json
import jwt
import datetime
import os       # schema file
import sqlite3  # database
import time     # time expiration 

SCHEMA_FILE = os.path.join(os.path.dirname(__file__), "schema.sql")

hostName = "localhost"
serverPort = 8080

# RSA private key
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)
expired_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)

# PKCS PEM format
pem = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.TraditionalOpenSSL, # makes it PKCS1 format
    encryption_algorithm=serialization.NoEncryption()
)
# PKCS PEM format
expired_pem = expired_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.TraditionalOpenSSL, # makes it PKCS1 format
    encryption_algorithm=serialization.NoEncryption()
)

numbers = private_key.private_numbers()


def int_to_base64(value):
    """Convert an integer to a Base64URL-encoded string"""
    value_hex = format(value, 'x')
    # Ensure even length
    if len(value_hex) % 2 == 1:
        value_hex = '0' + value_hex
    value_bytes = bytes.fromhex(value_hex)
    encoded = base64.urlsafe_b64encode(value_bytes).rstrip(b'=')
    return encoded.decode('utf-8')


class MyServer(BaseHTTPRequestHandler):
    def do_PUT(self):
        self.send_response(405)
        self.end_headers()
        return

    def do_PATCH(self):
        self.send_response(405)
        self.end_headers()
        return

    def do_DELETE(self):
        self.send_response(405)
        self.end_headers()
        return

    def do_HEAD(self):
        self.send_response(405)
        self.end_headers()
        return

    def do_POST(self):
        parsed_path = urlparse(self.path)
        params = parse_qs(parsed_path.query)
        if parsed_path.path == "/auth":
            headers = {
                "kid": "goodKID"
            }
            token_payload = {
                "user": "username",
                "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=1)
            }
            if 'expired' in params:
                headers["kid"] = "expiredKID"
                token_payload["exp"] = datetime.datetime.utcnow() - datetime.timedelta(hours=1)
            encoded_jwt = jwt.encode(token_payload, pem, algorithm="RS256", headers=headers)
            self.send_response(200)
            self.end_headers()
            self.wfile.write(bytes(encoded_jwt, "utf-8"))
            return

        self.send_response(405)
        self.end_headers()
        return

    def do_GET(self):
        if self.path == "/.well-known/jwks.json":
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            keys = {
                "keys": [
                    {
                        "alg": "RS256",
                        "kty": "RSA",
                        "use": "sig",
                        "kid": "goodKID",
                        "n": int_to_base64(numbers.public_numbers.n),
                        "e": int_to_base64(numbers.public_numbers.e),
                    }
                ]
            }
            self.wfile.write(bytes(json.dumps(keys), "utf-8"))
            return

        self.send_response(405)
        self.end_headers()
        return

    # save private ley to the database
    def save_key(conn, prm_bytes, expitrd_time):
        conn.execute("INSERT INTO keys (key, exp) VALUES (?, ?)", (pem_bytes, exp))
        conn.commit()
    
    def seed_keys(conn):
        now = int(time.time())
        # find if there're keys
        valid_count, expired_count = conn.execute(
            "SELECT COALESCE(SUM(exp > ?), 0), COALESCE(SUM(exp <= ?), 0) FROM keys",
            (now, now)).fetchone()
        # if no valid -> add one valid key
        if not has_valid:
            save_key(conn, pem, now + 3600)
        # if no expied -> add one expired key
        if not has_expired:
            save_key(conn, expired_pem, now - 3600)

# created the back storage file "totally_not_my_privateKeys.db" and connected to schema.sql file
def connect(db_file="totally_not_my_privateKeys.db"):
    conn = sqlite3.connect(db_file)
    with open(SCHEMA_FILE) as f:
        conn.executescript(f.read())
    return conn

if __name__ == "__main__":
    conn = connect()
    seed_keys(conn)
    conn.close()
    
    webServer = HTTPServer((hostName, serverPort), MyServer)
    try:
        webServer.serve_forever()
    except KeyboardInterrupt:
        pass

    webServer.server_close()
