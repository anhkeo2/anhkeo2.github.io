const net = require('net');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const PORT = 3001;
const NODE_NAME = 'Node1';

// Load RSA keys
const nodePrivateKey = fs.readFileSync(path.join(__dirname, 'keys', 'node1_private.pem'), 'utf8');
const nodePublicKey = fs.readFileSync(path.join(__dirname, 'keys', 'node1_public.pem'), 'utf8');
const senderPublicKey = fs.readFileSync(path.join(__dirname, 'keys', 'sender_public.pem'), 'utf8');
const receiverPublicKey = fs.readFileSync(path.join(__dirname, 'keys', 'receiver_public.pem'), 'utf8');

// Tạo thư mục storage nếu chưa tồn tại
const storageDir = path.join(__dirname, 'storage', 'node1');
if (!fs.existsSync(storageDir)) {
    fs.mkdirSync(storageDir, { recursive: true });
}

let sessionKey = null;
let storedFiles = new Map(); // Lưu trữ file data tạm thời

function log(message) {
    console.log(`[${NODE_NAME}] ${new Date().toISOString()}: ${message}`);
}

function verifySignature(data, signature, publicKey) {
    try {
        const verify = crypto.createVerify('RSA-SHA512');
        const normalizedData = JSON.stringify(data, Object.keys(data).sort());
        log(`📋 Dữ liệu xác thực: ${normalizedData}`);
        log(`🔏 Chữ ký nhận được: ${signature.substring(0, 20)}...`);
        verify.update(normalizedData);
        const isValid = verify.verify(publicKey, signature, 'base64');
        log(`✅ Kết quả xác thực: ${isValid}`);
        return isValid;
    } catch (error) {
        log(`❌ Lỗi xác thực chữ ký: ${error.message}`);
        return false;
    }
}

function decryptSessionKey(encryptedKey) {
    try {
        log(`🔑 Nhận encrypted session key: ${encryptedKey.substring(0, 20)}...`);
        const decrypted = crypto.privateDecrypt({
            key: nodePrivateKey,
            padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
            oaepHash: 'sha256'
        }, Buffer.from(encryptedKey, 'base64'));
        log(`✅ Session key giải mã thành công, kích thước: ${decrypted.length} bytes`);
        return decrypted;
    } catch (error) {
        log(`❌ Lỗi giải mã session key: ${error.message}`);
        return null;
    }
}

function decryptFile(iv, ciphertext, sessionKey) {
    try {
        const decipher = crypto.createDecipheriv('aes-256-cbc', sessionKey, Buffer.from(iv, 'base64'));
        let decrypted = decipher.update(Buffer.from(ciphertext, 'base64'), null, 'utf8');
        decrypted += decipher.final('utf8');
        return decrypted;
    } catch (error) {
        log(`❌ Lỗi giải mã file: ${error.message}`);
        return null;
    }
}

function verifyHash(iv, ciphertext, hash) {
    const combined = Buffer.concat([Buffer.from(iv, 'base64'), Buffer.from(ciphertext, 'base64')]);
    const calculatedHash = crypto.createHash('sha512').update(combined).digest('hex');
    return calculatedHash === hash;
}

const server = net.createServer((socket) => {
    log(`🔗 Client kết nối từ ${socket.remoteAddress}:${socket.remotePort}`);
    
    socket.on('data', (data) => {
        try {
            const message = data.toString().trim();
            log(`📨 Nhận: ${message.substring(0, 100)}${message.length > 100 ? '...' : ''}`);
            
            if (message === 'Hello!') {
                // Handshake
                log('🤝 Bắt đầu handshake');
                socket.write('Ready!');
                return;
            }
            
            try {
                const jsonData = JSON.parse(message);
                
                if (jsonData.type === 'upload') {
                    handleUpload(socket, jsonData);
                } else if (jsonData.type === 'download_request') {
                    handleDownloadRequest(socket, jsonData);
                }
            } catch (parseError) {
                log(`❌ Lỗi parse JSON: ${parseError.message}`);
                socket.write(JSON.stringify({ status: 'NACK', error: 'Invalid JSON format' }));
            }
        } catch (error) {
            log(`❌ Lỗi xử lý dữ liệu: ${error.message}`);
            socket.write(JSON.stringify({ status: 'NACK', error: 'Processing error' }));
        }
    });
    
    function handleUpload(socket, data) {
        log('📤 Xử lý upload request');
        
        // Giải mã session key
        sessionKey = decryptSessionKey(data.sessionKey);
        if (!sessionKey) {
            socket.write(JSON.stringify({ status: 'NACK', error: 'Failed to decrypt session key' }));
            return;
        }
        
        // Xác thực chữ ký metadata
        log(`📋 Metadata nhận được: ${JSON.stringify(data.metadata, null, 2)}`);
        const metadataToVerify = { ...data.metadata };
        delete metadataToVerify.signature; // Loại bỏ trường signature trước khi xác thực
        if (!verifySignature(metadataToVerify, data.metadata.signature, senderPublicKey)) {
            log('❌ Chữ ký metadata không hợp lệ');
            socket.write(JSON.stringify({ status: 'NACK', error: 'Invalid metadata signature' }));
            return;
        }
        log('✅ Chữ ký metadata hợp lệ');
        
        // Kiểm tra hash
        if (!verifyHash(data.iv, data.cipher, data.hash)) {
            log('❌ Hash không khớp');
            socket.write(JSON.stringify({ status: 'NACK', error: 'Hash verification failed' }));
            return;
        }
        log('✅ Hash verification thành công');
        
        // Giải mã file
        const decryptedContent = decryptFile(data.iv, data.cipher, sessionKey);
        if (!decryptedContent) {
            socket.write(JSON.stringify({ status: 'NACK', error: 'Decryption failed' }));
            return;
        }
        log('✅ File được giải mã thành công');
        
        // Lưu file
        const filename = data.metadata.filename;
        const filepath = path.join(storageDir, filename);
        fs.writeFileSync(filepath, decryptedContent);
        
        // Lưu thông tin file để download sau
        storedFiles.set(filename, {
            iv: data.iv,
            cipher: data.cipher,
            hash: data.hash,
            metadata: data.metadata,
            sessionKey: sessionKey
        });
        
        log(`✅ File '${filename}' được lưu thành công tại ${filepath}`);
        socket.write(JSON.stringify({ status: 'ACK', message: 'File uploaded successfully', node: NODE_NAME }));
    }
    
    function handleDownloadRequest(socket, data) {
        log('📥 Xử lý download request');
        
        // Xác thực chữ ký của receiver
        log(`📋 Dữ liệu yêu cầu download: ${JSON.stringify({ filename: data.filename, timestamp: data.timestamp }, null, 2)}`);
        log(`🔏 Chữ ký nhận được: ${data.signature.substring(0, 20)}...`);
        const requestData = { filename: data.filename, timestamp: data.timestamp };
        if (!verifySignature(requestData, data.signature, receiverPublicKey)) {
            log('❌ Chữ ký receiver không hợp lệ');
            socket.write(JSON.stringify({ status: 'NACK', error: 'Invalid receiver signature' }));
            return;
        }
        log('✅ Chữ ký receiver hợp lệ');
        
        // Kiểm tra file có tồn tại không
        const filename = data.filename;
        if (!storedFiles.has(filename)) {
            log(`❌ File '${filename}' không tồn tại`);
            socket.write(JSON.stringify({ status: 'NACK', error: 'File not found' }));
            return;
        }
        
        const fileData = storedFiles.get(filename);
        log(`✅ File '${filename}' được tìm thấy, bắt đầu gửi`);
        
        // Gửi file data
        const response = {
            status: 'ACK',
            iv: fileData.iv,
            cipher: fileData.cipher,
            hash: fileData.hash,
            metadata: fileData.metadata,
            node: NODE_NAME
        };
        
        socket.write(JSON.stringify(response));
        log('✅ File data đã được gửi thành công');
    }
    
    socket.on('close', () => {
        log('🔌 Client ngắt kết nối');
    });
    
    socket.on('error', (error) => {
        log(`❌ Socket error: ${error.message}`);
    });
});

server.listen(PORT, () => {
    log(`🚀 ${NODE_NAME} Azure Blob Storage đang chạy trên port ${PORT}`);
});

server.on('error', (error) => {
    log(`❌ Server error: ${error.message}`);
});