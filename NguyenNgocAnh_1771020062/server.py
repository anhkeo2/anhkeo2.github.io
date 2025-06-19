# server.py
from flask import Flask, send_from_directory # type: ignore
from flask_socketio import SocketIO # type: ignore
from Crypto.Signature import pkcs1_15 # type: ignore
from Crypto.Hash import SHA256 # type: ignore
from Crypto.PublicKey import RSA # type: ignore

app = Flask(__name__, static_folder='static')
socketio = SocketIO(app)

@app.route('/')
def index():
    return send_from_directory('static', 'index.html')

@socketio.on('file_upload')
def handle_file_upload(data):
    file_bytes = bytes(data['file'])
    signature = bytes(data['signature'])

    pub_key = RSA.import_key(open('keys/public.pem').read())
    h = SHA256.new(file_bytes)
    
    try:
        pkcs1_15.new(pub_key).verify(h, signature)
        print("✔️ File hợp lệ. Không bị chỉnh sửa.")
    except (ValueError, TypeError):
        print("❌ Chữ ký không hợp lệ. File đã bị thay đổi.")

if __name__ == '__main__':
    socketio.run(app, debug=True)

from flask_socketio import SocketIO, emit # type: ignore

@socketio.on('file_upload')
def handle_file_upload(data):
    file_bytes = bytes(data['file'])
    signature = bytes(data['signature'])

    h = SHA256.new(file_bytes)
    local_digest = h.digest()

    if local_digest == signature:
        print("✔️ File hợp lệ (hash trùng khớp).")
        emit("verify_result", {"success": True, "message": "File hợp lệ, chữ ký trùng khớp."})
    else:
        print("❌ File không hợp lệ (hash khác nhau).")
        emit("verify_result", {"success": False, "message": "File KHÔNG hợp lệ, chữ ký sai."})

