// renderer.js - Electron IPC
const { ipcRenderer } = require('electron');

// تهيئة الخانات
const emulators = [
    { icon: "🔥", name: "PS1", full: "PlayStation 1", id: "ps1", example: "Final Fantasy VII" },
    { icon: "🎮", name: "PS2", full: "PlayStation 2", id: "ps2", example: "God of War II" },
    { icon: "🎮", name: "PS3", full: "PlayStation 3", id: "ps3", example: "The Last of Us" },
    { icon: "🎮", name: "N64", full: "Nintendo 64", id: "n64", example: "Super Mario 64" },
    { icon: "🎮", name: "NES", full: "Nintendo Entertainment System", id: "nes", example: "Super Mario Bros" }
];

const grid = document.getElementById('emulator-grid');

emulators.forEach(emu => {
    const card = document.createElement('div');
    card.className = 'card';
    card.innerHTML = `
        <div class="card-icon">${emu.icon}</div>
        <div class="card-title">${emu.name}</div>
        <div class="card-fullname">${emu.full}</div>
        <div class="card-example">${emu.example}</div>
        <button class="play-btn" data-id="${emu.id}">تشغيل</button>
    `;
    grid.appendChild(card);
});

// ربط أزرار التشغيل مع Python
document.addEventListener('click', async (e) => {
    if (e.target.classList.contains('play-btn')) {
        const emuId = e.target.dataset.id;
        console.log(`Launching ${emuId}`);
        
        // استدعاء main process عبر IPC
        const result = await ipcRenderer.invoke('launch-emulator', emuId, "");
        console.log('Result:', result);
    }
});

// زر السيزون
document.getElementById('season-btn').addEventListener('click', () => {
    alert('نافذة السيزون - قريباً');
});

// إضافة صديق
document.getElementById('add-friend').addEventListener('click', () => {
    const name = prompt('أدخل اسم المستخدم:');
    if (name) {
        const friendDiv = document.createElement('div');
        friendDiv.textContent = `👤 ${name}`;
        document.getElementById('friends-list').appendChild(friendDiv);
    }
});

// إرسال رسالة
document.getElementById('chat-input').addEventListener('keypress', (e) => {
    if (e.key === 'Enter' && e.target.value) {
        const msgDiv = document.createElement('div');
        msgDiv.textContent = `أنت: ${e.target.value}`;
        document.getElementById('chat-messages').appendChild(msgDiv);
        e.target.value = '';
    }
});
