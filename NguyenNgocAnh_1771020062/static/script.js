const socket = io();

async function sendFile() {
    const fileInput = document.getElementById("fileInput");
    const file = fileInput.files[0];
    if (!file) return alert("Vui lòng chọn file!");

    const arrayBuffer = await file.arrayBuffer();
    const fileBytes = new Uint8Array(arrayBuffer);

    // Hash SHA-256 tạm thời thay chữ ký số
    const hashBuffer = await crypto.subtle.digest("SHA-256", fileBytes);
    const hashBytes = new Uint8Array(hashBuffer);

    socket.emit("file_upload", {
        file: Array.from(fileBytes),
        signature: Array.from(hashBytes)  // demo chữ ký giả
    });

    alert("✅ Đã gửi file (demo).");
}
// Lắng nghe phản hồi từ server
socket.on("verify_result", (data) => {
    alert(data.message);
});

