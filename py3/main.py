from http.server import BaseHTTPRequestHandler, HTTPServer
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from urllib.parse import urlparse, parse_qs
import base64
import json
import jwt
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
        params = parse_qs(parsed_path.query, keep_blank_values=True)
        if parsed_path.path == "/auth":
            expired = 'expired' in params
            connection= connect()
            row= read_privatekey(connection, expired)
            connection.close()

            if row is None:
                self.send_response(500)
                self.end_headers()
                return
            
            kid, key_pem= row
            headers= {"kid": str(kid)}
            now= int(time.time())
            token_payload={
                "user": "username",
                "exp": now-3600 if expired else now+3600
            }
            encoded_jwt = jwt.encode(token_payload, key_pem, algorithm="RS256", headers=headers)
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
            
            connection = connect()
            rows= read_all_valid_keys(connection)
            connection.close()
            # JWKS response here
            keys= {"keys": []}
            for kid, key_pem in rows:
                public_num = serialization.load_pem_private_key(
                    key_pem, password=None).public_key().public_numbers()
                keys["keys"].append({
                    "alg": "RS256",
                    "kty": "RSA",
                    "use": "sig",
                    "kid": str(kid),
                    "n": int_to_base64(public_num.n),
                    "e": int_to_base64(public_num.e),
                })
            self.wfile.write(bytes(json.dumps(keys), "utf-8"))
            return

        self.send_response(405)
        self.end_headers()
        return

# save private ley to the database
def save_key(conn, pem_bytes, expitrd_time):
    conn.execute("INSERT INTO keys (key, exp) VALUES (?, ?)", (pem_bytes, expitrd_time))
    conn.commit()
    
def seed_keys(conn):
    now = int(time.time())
    # find if there're keys
    valid_count, expired_count = conn.execute(
        "SELECT COALESCE(SUM(exp > ?), 0), COALESCE(SUM(exp <= ?), 0) FROM keys",
        (now, now)).fetchone()
    # if no valid -> add one valid key
    if valid_count == 0:
        save_key(conn, pem, now + 3600)
    # if no expied -> add one expired key
    if not expired_count:
        save_key(conn, expired_pem, now - 3600)

# created the back storage file "totally_not_my_privateKeys.db" and connected to schema.sql file
def connect(db_file="totally_not_my_privateKeys.db"):
    conn = sqlite3.connect(db_file)
    with open(SCHEMA_FILE) as f:
        conn.executescript(f.read())
    return conn

# read private key from database
def read_privatekey(connection, expired):
    now = int(time.time())
    # if the parameter is prsent
    if expired:
        sql="SELECT kid, key FROM keys WHERE exp <= ? ORDER BY kid DESC LIMIT 1"
    # if empty parameter
    else:
        sql="SELECT kid, key FROM keys WHERE exp > ? ORDER BY kid DESC LIMIT 1"
    # return (kid, pem) or None 
    return connection.execute(sql, (now,)).fetchone()

# read all of valid keys from database
def read_all_valid_keys(connection):
    now= int(time.time())
    # return a list of valid(kid, pem) here
    return connection.execute("SELECT kid, key FROM keys WHERE exp > ? ORDER BY kid", (now,)).fetchall()

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
