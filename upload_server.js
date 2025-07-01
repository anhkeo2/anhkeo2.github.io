const express = require('express');
const multer = require('multer');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const net = require('net');
const cors = require('cors');

const app = express();
const PORT = 3000;

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static('public'));

// Multer configuration for file upload
const upload = multer({ 
    dest: 'uploads/',
    limits: { fileSize: 10 * 1024 * 1024 } // 10MB limit
});

// Tạo thư mục session_keys nếu chưa tồn tại
const sessionKeysDir = path.join(__dirname, 'session_keys');
if (!fs.existsSync(sessionKeysDir)) {
    fs.mkdirSync(sessionKeysDir);
}

// Load RSA keys
const senderPrivateKey = fs.readFileSync(path.join(__dirname, 'keys', 'sender_private.pem'), 'utf8');
const senderPublicKey = fs.readFileSync(path.join(__dirname, 'keys', 'sender_public.pem'), 'utf8');
const node1PublicKey = fs.readFileSync(path.join(__dirname, 'keys', 'node1_public.pem'), 'utf8');
const node2PublicKey = fs.readFileSync(path.join(__dirname, 'keys', 'node2_public.pem'), 'utf8');

function log(message) {
    console.log(`[Upload-Server] ${new Date().toISOString()}: ${message}`);
}

function createSignature(data) {
    const sign = crypto.createSign('RSA-SHA512');
    const normalizedData = JSON.stringify(data, Object.keys(data).sort());
    sign.update(normalizedData);
    return sign.sign(senderPrivateKey, 'base64');
}

function encryptSessionKey(sessionKey, publicKey) {
    return crypto.publicEncrypt({
        key: publicKey,
        padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
        oaepHash: 'sha256'
    }, sessionKey).toString('base64');
}

function encryptFile(content, sessionKey) {
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv('aes-256-cbc', sessionKey, iv);
    
    let encrypted = cipher.update(content, 'utf8', 'base64');
    encrypted += cipher.final('base64');
    
    return {
        iv: iv.toString('base64'),
        cipher: encrypted
    };
}

function calculateHash(iv, ciphertext) {
    const combined = Buffer.concat([Buffer.from(iv, 'base64'), Buffer.from(ciphertext, 'base64')]);
    return crypto.createHash('sha512').update(combined).digest('hex');
}

async function connectToNode(host, port) {
    return new Promise((resolve, reject) => {
        const socket = net.createConnection(port, host);
        
        socket.on('connect', () => {
            log(`🔗 Kết nối thành công tới node trên port ${port}`);
            resolve(socket);
        });
        
        socket.on('error', (error) => {
            log(`❌ Lỗi kết nối tới node trên port ${port}: ${error.message}`);
            reject(error);
        });
        
        setTimeout(() => {
            socket.destroy();
            reject(new Error(`Connection timeout to port ${port}`));
        }, 5000);
    });
}

async function handshakeWithNode(socket) {
    return new Promise((resolve, reject) => {
        socket.write('Hello!');
        log('🤝 Gửi handshake: Hello!');
        
        socket.once('data', (data) => {
            const response = data.toString().trim();
            if (response === 'Ready!') {
                log('✅ Nhận handshake: Ready!');
                resolve(true);
            } else {
                log(`❌ Handshake thất bại: Nhận được ${response}`);
                reject(new Error('Handshake failed'));
            }
        });
        
        setTimeout(() => {
            reject(new Error('Handshake timeout'));
        }, 3000);
    });
}

async function sendToNode(socket, data) {
    return new Promise((resolve, reject) => {
        socket.write(JSON.stringify(data));
        log('📤 Gửi dữ liệu tới node');
        
        socket.once('data', (response) => {
            try {
                const result = JSON.parse(response.toString());
                log(`📨 Nhận response từ node: ${JSON.stringify(result)}`);
                resolve(result);
            } catch (error) {
                log(`❌ Lỗi parse response từ node: ${error.message}`);
                reject(new Error('Invalid response format'));
            }
        });
        
        setTimeout(() => {
            reject(new Error('Upload timeout'));
        }, 10000);
    });
}

// Upload endpoint
app.post('/upload', upload.single('file'), async (req, res) => {
    const startTime = Date.now();
    
    try {
        if (!req.file) {
            log('❌ Không có file được upload');
            return res.status(400).json({ error: 'No file uploaded' });
        }
        
        log(`📤 Bắt đầu upload file: ${req.file.originalname}`);
        
        // Đọc file content
        const fileContent = fs.readFileSync(req.file.path, 'utf8');
        
        // Tạo session key
        const sessionKey = crypto.randomBytes(32);
        log(`🔑 Session key được tạo, kích thước: ${sessionKey.length} bytes`);
        
        // Tạo metadata
        const metadata = {
            filename: req.file.originalname,
            timestamp: new Date().toISOString(),
            transactionId: crypto.randomUUID(),
            size: req.file.size
        };
        
        // Lưu session key
        const sessionKeyStorage = path.join(sessionKeysDir, `${metadata.transactionId}.key`);
        fs.writeFileSync(sessionKeyStorage, sessionKey.toString('base64'));
        log(`🔑 Session key được lưu tại ${sessionKeyStorage}`);
        
        // Ký metadata
        log(`📋 Metadata trước khi ký: ${JSON.stringify(metadata, null, 2)}`);
        const metadataToSign = { ...metadata };
        metadata.signature = createSignature(metadataToSign);
        log('✅ Metadata được ký');
        
        // Mã hóa file
        const { iv, cipher } = encryptFile(fileContent, sessionKey);
        log('🔒 File được mã hóa bằng AES-CBC');
        
        // Tính hash
        const hash = calculateHash(iv, cipher);
        log('🔍 Hash được tính toán');
        
        // Mã hóa session key cho từng node
        const sessionKeyNode1 = encryptSessionKey(sessionKey, node1PublicKey);
        const sessionKeyNode2 = encryptSessionKey(sessionKey, node2PublicKey);
        log(`🔐 Session key mã hóa cho Node1: ${sessionKeyNode1.substring(0, 20)}...`);
        log(`🔐 Session key mã hóa cho Node2: ${sessionKeyNode2.substring(0, 20)}...`);
        
        // Kết nối đến cả 2 nodes
        const node1SocketPromise = connectToNode('localhost', 3001);
        const node2SocketPromise = connectToNode('localhost', 3002);
        
        let node1Socket, node2Socket;
        try {
            [node1Socket, node2Socket] = await Promise.all([node1SocketPromise, node2SocketPromise]);
        } catch (error) {
            throw new Error(`Kết nối tới node thất bại: ${error.message}`);
        }
        
        // Handshake với cả 2 nodes
        await Promise.all([
            handshakeWithNode(node1Socket),
            handshakeWithNode(node2Socket)
        ]);
        log('🤝 Handshake thành công với cả 2 nodes');
        
        // Chuẩn bị data để gửi
        const uploadData1 = {
            type: 'upload',
            sessionKey: sessionKeyNode1,
            iv: iv,
            cipher: cipher,
            hash: hash,
            metadata: metadata
        };
        
        const uploadData2 = {
            type: 'upload',
            sessionKey: sessionKeyNode2,
            iv: iv,
            cipher: cipher,
            hash: hash,
            metadata: metadata
        };
        
        // Upload đồng thời đến cả 2 nodes
        const uploadPromises = [
            sendToNode(node1Socket, uploadData1),
            sendToNode(node2Socket, uploadData2)
        ];
        
        const results = await Promise.allSettled(uploadPromises);
        const successfulNodes = results.filter(r => r.status === 'fulfilled' && r.value.status === 'ACK');
        
        if (successfulNodes.length === 0) {
            log('❌ Upload thất bại trên cả 2 nodes');
            throw new Error('Upload failed on all nodes');
        }
        
        log(`🎯 Upload hoàn thành trên ${successfulNodes.length} node(s)`);
        results.forEach((result, index) => {
            const nodeName = index === 0 ? 'Node1' : 'Node2';
            if (result.status === 'fulfilled') {
                log(`🎯 ${nodeName}: ${result.value.status} - ${result.value.message || 'OK'}`);
            } else {
                log(`❌ ${nodeName}: Lỗi - ${result.reason.message}`);
            }
        });
        
        // Đóng kết nối
        node1Socket.destroy();
        node2Socket.destroy();
        
        // Xóa file tạm
        fs.unlinkSync(req.file.path);
        
        const processingTime = Date.now() - startTime;
        log(`✅ Upload thành công trong ${processingTime}ms`);
        
        res.json({
            success: true,
            message: `File uploaded successfully to ${successfulNodes.length} node(s)`,
            metadata: {
                filename: metadata.filename,
                timestamp: metadata.timestamp,
                transactionId: metadata.transactionId,
                size: metadata.size
            },
            transactionId: metadata.transactionId, // Thêm transactionId để client sử dụng
            results: results.map(r => r.status === 'fulfilled' ? r.value : { status: 'NACK', error: r.reason.message }),
            processingTime: processingTime
        });
        
    } catch (error) {
        log(`❌ Upload failed: ${error.message}`);
        
        // Cleanup
        if (req.file && fs.existsSync(req.file.path)) {
            fs.unlinkSync(req.file.path);
        }
        
        res.status(500).json({
            success: false,
            error: error.message,
            processingTime: Date.now() - startTime
        });
    }
});

// Get upload status
app.get('/status', (req, res) => {
    res.json({
        server: 'Upload Server',
        status: 'Running',
        timestamp: new Date().toISOString(),
        nodes: [
            { name: 'Node1', port: 3001 },
            { name: 'Node2', port: 3002 }
        ]
    });
});

app.listen(PORT, () => {
    log(`🚀 Upload Server đang chạy trên port ${PORT}`);
    log('📁 Serving static files from ./public/');
});

app.on('error', (error) => {
    log(`❌ Server error: ${error.message}`);
});