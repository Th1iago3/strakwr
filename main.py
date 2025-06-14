from flask import Flask, request, jsonify
import asyncio
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from google.protobuf.json_format import MessageToJson
import binascii
import aiohttp
import requests
import json
import time
import concurrent.futures
import urllib3
from google.protobuf.message import DecodeError
import os

# Protobuf imports (make sure these files are available)
import like_pb2
import like_count_pb2
import uid_generator_pb2
import my_pb2
import output_pb2

# Disable SSL warnings for requests
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

app = Flask(__name__)

# Constants and configuration
ACCOUNTS_FILE = 'accs.txt'
TOKENS_FILE = 'tokens.json'
AES_KEY = b'Yg&tc%DEuh6%Zc^8'
AES_IV = b'6oyZDr22E3ychjM%'
MAX_WORKERS = 50
REQUEST_TIMEOUT = 15
SESSION = requests.Session()

# ========================
# TOKEN GENERATION SECTION
# ========================

def encrypt_message(plaintext):
    """Encrypts a message using AES CBC and returns a hex string."""
    try:
        cipher = AES.new(AES_KEY, AES.MODE_CBC, AES_IV)
        padded_message = pad(plaintext, AES.block_size)
        encrypted_message = cipher.encrypt(padded_message)
        return binascii.hexlify(encrypted_message).decode('utf-8')
    except Exception as e:
        app.logger.error(f"Error encrypting message: {e}")
        return None

def load_accounts(file_path, limit=None):
    """Loads accounts from a file (each line should be in the format uid:password)."""
    accounts = []
    try:
        with open(file_path, 'r') as f:
            for i, line in enumerate(f):
                if limit is not None and i >= limit:
                    break
                line = line.strip()
                if line and ':' in line:
                    uid_val, password = line.split(':', 1)
                    accounts.append((uid_val.strip(), password.strip()))
    except Exception as e:
        app.logger.error(f"Error reading {file_path}: {e}")
    return accounts

def fetch_jwt_token(account):
    """Fetches a JWT token for a single account using OAuth and then logs in via the game API."""
    uid_val, password = account
    start_time = time.time()
    oauth_url = "https://100067.connect.garena.com/oauth/guest/token/grant"
    payload = {
        'uid': uid_val,
        'password': password,
        'response_type': "token",
        'client_type': "2",
        'client_secret': "2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3",
        'client_id': "100067"
    }
    headers = {
        'User-Agent': "GarenaMSDK/4.0.19P9(SM-M526B; Android 13; en; US;)",
        'Connection': "Keep-Alive",
        'Accept-Encoding': "gzip"
    }
    try:
        response = SESSION.post(oauth_url, data=payload, headers=headers, timeout=REQUEST_TIMEOUT)
        if response.status_code != 200:
            app.logger.error(f"OAuth error for {uid_val}: {response.status_code}")
            return None
        oauth_data = response.json()
        access_token = oauth_data.get('access_token')
        open_id = oauth_data.get('open_id')
        platform_type = oauth_data.get('platform', 4)
        if not access_token or not open_id:
            app.logger.error(f"Invalid credentials for {uid_val}")
            return None
    except Exception as e:
        app.logger.error(f"OAuth error for {uid_val}: {str(e)}")
        return None

    # Create game data protobuf message
    game_data = my_pb2.GameData()
    game_data.timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    game_data.game_name = "free fire"
    game_data.game_version = 1
    game_data.version_code = "1.108.3"
    game_data.os_info = "Android OS 9 / API-28"
    game_data.device_type = "Handheld"
    game_data.network_provider = "Verizon Wireless"
    game_data.connection_type = "WIFI"
    game_data.screen_width = 1280
    game_data.screen_height = 960
    game_data.dpi = "240"
    game_data.cpu_info = "ARMv7 VFPv3 NEON"
    game_data.total_ram = 5951
    game_data.gpu_name = "Adreno(TM) 640"
    game_data.gpu_version = "OpenGL ES 3.0"
    game_data.user_id = "Google|74b585a9-0268-4ad3-8f36-ef41d2e53610"
    game_data.ip_address = "172.190.111.97"
    game_data.language = "en"
    game_data.open_id = open_id
    game_data.access_token = access_token
    game_data.platform_type = platform_type
    game_data.field_99 = str(platform_type)
    game_data.field_100 = str(platform_type)

    try:
        serialized_data = game_data.SerializeToString()
        encrypted_data = encrypt_message(serialized_data)
        if encrypted_data is None:
            return None
        # The encrypted data is passed as a hex string
        url = "https://loginbp.ggblueshark.com/MajorLogin"
        headers = {
            "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)",
            "Connection": "Keep-Alive",
            "Accept-Encoding": "gzip",
            "Content-Type": "application/octet-stream",
            "Expect": "100-continue",
            "X-Unity-Version": "2018.4.11f1",
            "X-GA": "v1 1",
            "ReleaseVersion": "OB48"
        }
        response = SESSION.post(url, data=bytes.fromhex(encrypted_data), headers=headers, verify=False, timeout=REQUEST_TIMEOUT)
        if response.status_code == 200:
            response_msg = output_pb2.Garena_420()
            response_msg.ParseFromString(response.content)
            elapsed_time = time.time() - start_time
            app.logger.info(f"Token fetched for {uid_val} in {elapsed_time:.2f}s")
            return {"uid": uid_val, "jwt_token": response_msg.token}
        app.logger.error(f"Token fetch warning for {uid_val}: {response.status_code}")
        return None
    except Exception as e:
        app.logger.error(f"Token fetch error for {uid_val}: {str(e)}")
        return None

def save_tokens(tokens):
    """Saves tokens to TOKENS_FILE."""
    try:
        with open(TOKENS_FILE, 'w') as f:
            json.dump({"tokens": tokens}, f, indent=4)
        app.logger.info(f"Tokens saved to {TOKENS_FILE}")
    except Exception as e:
        app.logger.error(f"Error saving tokens: {e}")

def generate_tokens(limit=100):
    """Generates tokens from accounts and saves them. Returns the list of tokens."""
    accounts = load_accounts(ACCOUNTS_FILE, limit)
    tokens = []
    total_accounts = len(accounts)
    success_count = 0
    start_time = time.time()
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        future_to_account = {executor.submit(fetch_jwt_token, account): account for account in accounts}
        for future in concurrent.futures.as_completed(future_to_account):
            account = future_to_account[future]
            try:
                result = future.result()
                if result:
                    tokens.append(result)
                    success_count += 1
            except Exception as e:
                app.logger.error(f"Error for account {account[0]}: {str(e)}")
    save_tokens(tokens)
    elapsed_time = time.time() - start_time
    app.logger.info(f"Total accounts: {total_accounts}")
    app.logger.info(f"Generated tokens: {success_count}")
    app.logger.info(f"Success rate: {(success_count/total_accounts)*100:.2f}%")
    app.logger.info(f"Total time: {elapsed_time:.2f} seconds")
    app.logger.info(f"Tokens per second: {success_count/elapsed_time:.2f}")
    return tokens

def load_tokens_from_file():
    """Loads tokens from the saved file."""
    try:
        with open(TOKENS_FILE, 'r') as f:
            data = json.load(f)
        return data.get("tokens", [])
    except Exception as e:
        app.logger.error(f"Error loading tokens: {e}")
        return None

# ========================
# LIKE API SECTION
# ========================

def encrypt_message_for_like(plaintext):
    """Encrypts the protobuf message for like API and returns a hex string."""
    try:
        key = b'Yg&tc%DEuh6%Zc^8'
        iv = b'6oyZDr22E3ychjM%'
        cipher = AES.new(key, AES.MODE_CBC, iv)
        padded_message = pad(plaintext, AES.block_size)
        encrypted_message = cipher.encrypt(padded_message)
        return binascii.hexlify(encrypted_message).decode('utf-8')
    except Exception as e:
        app.logger.error(f"Error encrypting message: {e}")
        return None

def create_protobuf_message(user_id):
    """Creates a protobuf message (like_pb2) using the provided user ID."""
    try:
        message = like_pb2.like()
        message.uid = int(user_id)
        return message.SerializeToString()
    except Exception as e:
        app.logger.error(f"Error creating protobuf message: {e}")
        return None

async def send_request(encrypted_uid, token, url):
    """Sends a single asynchronous POST request."""
    try:
        edata = bytes.fromhex(encrypted_uid)
        headers = {
            'User-Agent': "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)",
            'Connection': "Keep-Alive",
            'Accept-Encoding': "gzip",
            'Authorization': f"Bearer {token}",
            'Content-Type': "application/x-www-form-urlencoded",
            'Expect': "100-continue",
            'X-Unity-Version': "2018.4.11f1",
            'X-GA': "v1 1",
            'ReleaseVersion': "OB48"
        }
        async with aiohttp.ClientSession() as session:
            async with session.post(url, data=edata, headers=headers) as response:
                if response.status != 200:
                    app.logger.error(f"Request failed with status code: {response.status}")
                    return response.status
                return await response.text()
    except Exception as e:
        app.logger.error(f"Exception in send_request: {e}")
        return None

async def send_multiple_requests(uid, url):
    """
    Creates a protobuf message for the provided uid, encrypts it, and then sends 100 asynchronous like requests using the saved tokens.
    """
    try:
        protobuf_message = create_protobuf_message(uid)
        if protobuf_message is None:
            app.logger.error("Failed to create protobuf message.")
            return None
        encrypted_uid = encrypt_message_for_like(protobuf_message)
        if encrypted_uid is None:
            app.logger.error("Encryption failed.")
            return None

        tokens = load_tokens_from_file()
        if tokens is None or len(tokens) == 0:
            app.logger.error("Failed to load tokens.")
            return None

        tasks = []
        # Rotate tokens for the 100 like requests
        for i in range(100):
            token = tokens[i % len(tokens)]["jwt_token"]
            tasks.append(send_request(encrypted_uid, token, url))
        results = await asyncio.gather(*tasks, return_exceptions=True)
        return results
    except Exception as e:
        app.logger.error(f"Exception in send_multiple_requests: {e}")
        return None

def create_uid_protobuf(uid):
    """Creates a protobuf message (uid_generator) using the provided uid."""
    try:
        message = uid_generator_pb2.uid_generator()
        message.saturn_ = int(uid)
        message.garena = 1
        return message.SerializeToString()
    except Exception as e:
        app.logger.error(f"Error creating uid protobuf: {e}")
        return None

def enc(uid):
    """Encrypts the uid protobuf message and returns the encrypted hex string."""
    protobuf_data = create_uid_protobuf(uid)
    if protobuf_data is None:
        return None
    encrypted_uid = encrypt_message_for_like(protobuf_data)
    return encrypted_uid

def make_request(encrypted_data, token):
    """
    Sends a POST request to retrieve player personal info using the encrypted data.
    The response is assumed to be a protobuf which is then decoded.
    """
    try:
        url = "https://client.us.freefiremobile.com/GetPlayerPersonalShow"
        edata = bytes.fromhex(encrypted_data)
        headers = {
            'User-Agent': "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)",
            'Connection': "Keep-Alive",
            'Accept-Encoding': "gzip",
            'Authorization': f"Bearer {token}",
            'Content-Type': "application/x-www-form-urlencoded",
            'Expect': "100-continue",
            'X-Unity-Version': "2018.4.11f1",
            'X-GA': "v1 1",
            'ReleaseVersion': "OB48"
        }
        response = requests.post(url, data=edata, headers=headers, verify=False)
        hex_data = response.content.hex()
        binary = bytes.fromhex(hex_data)
        decoded = decode_protobuf(binary)
        if decoded is None:
            app.logger.error("Protobuf decoding returned None.")
        return decoded
    except Exception as e:
        app.logger.error(f"Error in make_request: {e}")
        return None

def decode_protobuf(binary):
    """Decodes the binary data using the like_count protobuf."""
    try:
        info = like_count_pb2.Info()
        info.ParseFromString(binary)
        return info
    except DecodeError as e:
        app.logger.error(f"Error decoding Protobuf data: {e}")
        return None
    except Exception as e:
        app.logger.error(f"Unexpected error during protobuf decoding: {e}")
        return None

# ========================
# FLASK API ENDPOINT
# ========================

@app.route('/like', methods=['GET'])
def handle_like_request():
    uid = request.args.get("uid")
    if not uid:
        return jsonify({"error": "UID is required"}), 400
    try:
        # Before sending likes, generate tokens and save them.
        generate_tokens()
        tokens = load_tokens_from_file()
        if tokens is None or len(tokens) == 0:
            raise Exception("Failed to generate tokens.")
        # Use the first token for preliminary requests
        token = tokens[0]["jwt_token"]
        encrypted_uid = enc(uid)
        if encrypted_uid is None:
            raise Exception("Encryption of UID failed.")
        # Get player info before sending like requests
        before = make_request(encrypted_uid, token)
        if before is None:
            raise Exception("Failed to retrieve initial player info.")
        try:
            jsone = MessageToJson(before)
        except Exception as e:
            raise Exception(f"Error converting 'before' protobuf to JSON: {e}")
        data_before = json.loads(jsone)
        before_like = data_before.get('AccountInfo', {}).get('Likes', 0)
        try:
            before_like = int(before_like)
        except Exception:
            before_like = 0
        app.logger.info(f"Likes before command: {before_like}")
            
        # Send 100 asynchronous like requests
        like_url = "https://client.us.freefiremobile.com/LikeProfile"
        asyncio.run(send_multiple_requests(uid, like_url))

        # Get player info after sending like requests
        after = make_request(encrypted_uid, token)
        if after is None:
            raise Exception("Failed to retrieve player info after like requests.")
        try:
            jsone_after = MessageToJson(after)
        except Exception as e:
            raise Exception(f"Error converting 'after' protobuf to JSON: {e}")
        data_after = json.loads(jsone_after)
        after_like = int(data_after.get('AccountInfo', {}).get('Likes', 0))
        player_uid = int(data_after.get('AccountInfo', {}).get('UID', 0))
        player_name = str(data_after.get('AccountInfo', {}).get('PlayerNickname', ''))
        like_given = after_like - before_like
        status = 1 if like_given != 0 else 2

        result = {
    "status": status,
  #  "uid": player_uid,
    "nickname": player_name,
    "after": after_like,
    "before": before_like,
    "sent": like_given
}

        return jsonify(result)
    except Exception as e:
        app.logger.error(f"Error processing request: {e}")
        return jsonify({"error": str(e)}), 500

# ========================
# MAIN
# ========================

if __name__ == '__main__':
    # Run the Flask app on all network interfaces (0.0.0.0) with debug enabled.
    app.run(debug=True, host="0.0.0.0")
