const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

// Tạo thư mục keys nếu chưa tồn tại
const keysDir = path.join(__dirname, 'keys');
if (!fs.existsSync(keysDir)) {
    fs.mkdirSync(keysDir);
}

// Tạo RSA key pair 2048-bit
const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding: {
        type: 'spki',
        format: 'pem'
    },
    privateKeyEncoding: {
        type: 'pkcs8',
        format: 'pem'
    }
});

// Tạo key pair cho sender
fs.writeFileSync(path.join(keysDir, 'sender_public.pem'), publicKey);
fs.writeFileSync(path.join(keysDir, 'sender_private.pem'), privateKey);

// Tạo key pair cho receiver
const { publicKey: receiverPublicKey, privateKey: receiverPrivateKey } = crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding: {
        type: 'spki',
        format: 'pem'
    },
    privateKeyEncoding: {
        type: 'pkcs8',
        format: 'pem'
    }
});

fs.writeFileSync(path.join(keysDir, 'receiver_public.pem'), receiverPublicKey);
fs.writeFileSync(path.join(keysDir, 'receiver_private.pem'), receiverPrivateKey);

// Tạo key pair cho node1
const { publicKey: node1PublicKey, privateKey: node1PrivateKey } = crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding: {
        type: 'spki',
        format: 'pem'
    },
    privateKeyEncoding: {
        type: 'pkcs8',
        format: 'pem'
    }
});

fs.writeFileSync(path.join(keysDir, 'node1_public.pem'), node1PublicKey);
fs.writeFileSync(path.join(keysDir, 'node1_private.pem'), node1PrivateKey);

// Tạo key pair cho node2
const { publicKey: node2PublicKey, privateKey: node2PrivateKey } = crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding: {
        type: 'spki',
        format: 'pem'
    },
    privateKeyEncoding: {
        type: 'pkcs8',
        format: 'pem'
    }
});

fs.writeFileSync(path.join(keysDir, 'node2_public.pem'), node2PublicKey);
fs.writeFileSync(path.join(keysDir, 'node2_private.pem'), node2PrivateKey);

console.log('✅ Đã tạo thành công các RSA key pairs:');
console.log('- Sender: sender_public.pem, sender_private.pem');
console.log('- Receiver: receiver_public.pem, receiver_private.pem');
console.log('- Node1: node1_public.pem, node1_private.pem');
console.log('- Node2: node2_public.pem, node2_private.pem');
console.log('\n📁 Tất cả keys được lưu trong thư mục: ./keys/');
