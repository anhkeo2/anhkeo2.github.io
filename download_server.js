const express = require('express');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const net = require('net');
const cors = require('cors');

const app = express();
const PORT = 4000;

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static('public'));

// Load RSA keys
const receiverPrivateKey = fs.readFileSync(path.join(__dirname, 'keys', 'receiver_private.pem'), 'utf8');
const receiverPublicKey = fs.readFileSync(path.join(__dirname, 'keys', 'receiver_public.pem'), 'utf8');
const senderPublicKey = fs.readFileSync(path.join(__dirname, 'keys', 'sender_public.pem'), 'utf8');

// Tạo thư mục downloads nếu chưa tồn tại
const downloadsDir = path.join(__dirname, 'downloads');
if (!fs.existsSync(downloadsDir)) {
    fs.mkdirSync(downloadsDir);
}

function log(message) {
    console.log(`[Download-Server] ${new Date().toISOString()}: ${message}`);
}

function createSignature(data) {
    const sign = crypto.createSign('RSA-SHA512');
    const normalizedData = JSON.stringify(data, Object.keys(data).sort());
    sign.update(normalizedData);
    return sign.sign(receiverPrivateKey, 'base64');
}

function verifySignature(data, signature, publicKey) {
    try {
        const verify = crypto.createVerify('RSA-SHA512');
        const normalizedData = JSON.stringify(data, Object.keys(data).sort());
        verify.update(normalizedData);
        return verify.verify(publicKey, signature, 'base64');
    } catch (error) {
        log(`❌ Lỗi xác thực chữ ký: ${error.message}`);
        return false;
    }
}

function verifyHash(iv, ciphertext, hash) {
    const combined = Buffer.concat([Buffer.from(iv, 'base64'), Buffer.from(ciphertext, 'base64')]);
    const calculatedHash = crypto.createHash('sha512').update(combined).digest('hex');
    return calculatedHash === hash;
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

async function connectToNode(host, port) {
    return new Promise((resolve, reject) => {
        const socket = net.createConnection(port, host);
        
        socket.on('connect', () => {
            log(`🔗 Kết nối thành công đến Node trên port ${port}`);
            resolve(socket);
        });
        
        socket.on('error', (error) => {
            log(`❌ Lỗi kết nối đến Node trên port ${port}: ${error.message}`);
            reject(error);
        });
        
        setTimeout(() => {
            socket.destroy();
            reject(new Error(`Connection timeout to port ${port}`));
        }, 5000);
    });
}

async function requestDownload(socket, filename, transactionId) {
    return new Promise((resolve, reject) => {
        const timestamp = new Date().toISOString();
        const requestData = { filename, timestamp };
        const signature = createSignature(requestData);
        
        log(`📋 Dữ liệu yêu cầu download: ${JSON.stringify(requestData, null, 2)}`);
        log(`🔏 Chữ ký yêu cầu: ${signature.substring(0, 20)}...`);
        
        const downloadRequest = {
            type: 'download_request',
            filename: filename,
            timestamp: timestamp,
            signature: signature
        };
        
        socket.write(JSON.stringify(downloadRequest));
        
        socket.once('data', (response) => {
            try {
                const result = JSON.parse(response.toString());
                log(`📨 Nhận response từ Node: ${JSON.stringify(result)}`);
                resolve(result);
            } catch (error) {
                log(`❌ Lỗi parse response: ${error.message}`);
                reject(new Error('Invalid response format'));
            }
        });
        
        setTimeout(() => {
            reject(new Error('Download timeout'));
        }, 10000);
    });
}

// Download endpoint
app.post('/download', async (req, res) => {
    const startTime = Date.now();
    
    try {
        const { filename, nodeChoice, transactionId } = req.body;
        
        if (!filename || !transactionId) {
            log('❌ Tên file hoặc transactionId không được cung cấp');
            return res.status(400).json({ error: 'Filename and transactionId are required' });
        }
        
        log(`📥 Bắt đầu download file: ${filename} từ ${nodeChoice || 'Node1'}`);
        
        // Chọn node để download (mặc định Node1)
        const nodePort = nodeChoice === 'Node2' ? 3002 : 3001;
        const nodeName = nodeChoice === 'Node2' ? 'Node2' : 'Node1';
        
        // Kết nối đến node
        const socket = await connectToNode('localhost', nodePort);
        
        // Gửi yêu cầu download
        const result = await requestDownload(socket, filename, transactionId);
        
        if (result.status === 'NACK') {
            socket.destroy();
            throw new Error(result.error);
        }
        
        log(`✅ Nhận response từ ${nodeName}`);
        
        // Xác thực chữ ký metadata
        const metadataToVerify = { ...result.metadata };
        delete metadataToVerify.signature; // Loại bỏ trường signature trước khi xác thực
        if (!verifySignature(metadataToVerify, result.metadata.signature, senderPublicKey)) {
            socket.destroy();
            throw new Error('Invalid metadata signature');
        }
        log('✅ Chữ ký metadata hợp lệ');
        
        // Kiểm tra hash
        if (!verifyHash(result.iv, result.cipher, result.hash)) {
            socket.destroy();
            throw new Error('Hash verification failed');
        }
        log('✅ Hash verification thành công');
        
        // Đọc session key
        const sessionKeyPath = path.join(__dirname, 'session_keys', `${transactionId}.key`);
        if (!fs.existsSync(sessionKeyPath)) {
            socket.destroy();
            throw new Error('Session key not found');
        }
        const sessionKey = Buffer.from(fs.readFileSync(sessionKeyPath, 'utf8'), 'base64');
        log(`🔑 Đọc session key từ ${sessionKeyPath}`);
        
        // Giải mã file
        const decryptedContent = decryptFile(result.iv, result.cipher, sessionKey);
        if (!decryptedContent) {
            socket.destroy();
            throw new Error('Decryption failed');
        }
        log('✅ File được giải mã thành công');
        
        // Lưu file giải mã
        const filePath = path.join(downloadsDir, filename);
        fs.writeFileSync(filePath, decryptedContent);
        
        // Gửi ACK
        socket.write(JSON.stringify({ status: 'ACK' }));
        socket.destroy();
        log('📤 Gửi ACK thành công');
        
        const processingTime = Date.now() - startTime;
        log(`✅ Download thành công trong ${processingTime}ms`);
        
        res.json({
            success: true,
            message: `File downloaded and decrypted successfully from ${nodeName}`,
            metadata: result.metadata,
            node: result.node,
            filePath: filePath,
            processingTime: processingTime
        });
        
    } catch (error) {
        log(`❌ Download failed: ${error.message}`);
        
        res.status(500).json({
            success: false,
            error: error.message,
            processingTime: Date.now() - startTime
        });
    }
});

// List available files endpoint
app.get('/files', async (req, res) => {
    try {
        const files = [];
        
        // Kết nối đến cả 2 nodes để lấy danh sách files
        const promises = [
            connectToNode('localhost', 3001).then(socket => {
                socket.destroy();
                return { node: 'Node1', available: true };
            }).catch(() => ({ node: 'Node1', available: false })),
            
            connectToNode('localhost', 3002).then(socket => {
                socket.destroy();
                return { node: 'Node2', available: true };
            }).catch(() => ({ node: 'Node2', available: false }))
        ];
        
        const nodeStatus = await Promise.all(promises);
        
        res.json({
            success: true,
            nodes: nodeStatus,
            message: 'Để download file, cần biết tên file và transactionId chính xác'
        });
        
    } catch (error) {
        res.status(500).json({
            success: false,
            error: error.message
        });
    }
});

// Get download status
app.get('/status', (req, res) => {
    res.json({
        server: 'Download Server',
        status: 'Running',
        timestamp: new Date().toISOString(),
        nodes: [
            { name: 'Node1', port: 3001 },
            { name: 'Node2', port: 3002 }
        ]
    });
});

app.listen(PORT, () => {
    log(`🚀 Download Server đang chạy trên port ${PORT}`);
    log('📁 Serving static files from ./public/');
});

app.on('error', (error) => {
    log(`❌ Server error: ${error.message}`);
});