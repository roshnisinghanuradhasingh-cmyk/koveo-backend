// server.js
require('dotenv').config();
const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const cors = require('cors');
const { Pool } = require('pg');

const app = express();
app.use(cors());
const server = http.createServer(app);

const io = new Server(server, { cors: { origin: "*" } });

// 🐘 NEON DB CONNECTION
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: { rejectUnauthorized: false }
});

// Auto-create Tables
async function initDB() {
    try {
        // 1. Messages Queue Table
        await pool.query(`
            CREATE TABLE IF NOT EXISTS messages_queue (
                id VARCHAR(255) PRIMARY KEY,
                sender_id VARCHAR(255) NOT NULL,
                receiver_id VARCHAR(255) NOT NULL,
                text TEXT NOT NULL,
                timestamp VARCHAR(100),
                status VARCHAR(50) DEFAULT 'sent',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        `);
        // 2. Users Table (NEW)
        await pool.query(`
            CREATE TABLE IF NOT EXISTS users (
                phone VARCHAR(50) PRIMARY KEY,
                name VARCHAR(100),
                bio TEXT,
                dp_url TEXT,
                last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        `);
        console.log("🐘 Neon DB Connected & Tables Ready!");
    } catch (err) { console.error("❌ DB Connection Error:", err); }
}
initDB();

const connectedUsers = new Map();

io.on('connection', (socket) => {
    console.log(`🟢 Device Connected: ${socket.id}`);

    // 🔐 SECURE LOGIN & REGISTRATION
    socket.on('auth_login', async (data) => {
        connectedUsers.set(data.phone, socket.id);
        console.log(`📱 User Authenticated: ${data.phone} (${data.name})`);

        try {
            // Save or Update User in Database
            await pool.query(`
                INSERT INTO users (phone, name, bio) 
                VALUES ($1, $2, $3) 
                ON CONFLICT (phone) DO UPDATE 
                SET name = EXCLUDED.name, bio = EXCLUDED.bio, last_seen = CURRENT_TIMESTAMP
            `, [data.phone, data.name, data.bio]);
            
            socket.emit('auth_success', { phone: data.phone });

            // 📥 CHECK PENDING OFFLINE MESSAGES
            const result = await pool.query(
                `SELECT * FROM messages_queue WHERE receiver_id = $1 AND status != 'read'`,
                [data.phone]
            );
            if (result.rows.length > 0) {
                console.log(`📦 Delivering ${result.rows.length} offline messages to ${data.phone}`);
                result.rows.forEach(msg => {
                    socket.emit('receive_message', {
                        id: msg.id, senderId: msg.sender_id, text: msg.text, timestamp: msg.timestamp
                    });
                });
            }
        } catch (err) { console.error("Auth DB Error", err); }
    });

    // 🔍 SECURE CONTACT LOOKUP
    socket.on('search_contact', async (phoneQuery) => {
        try {
            const result = await pool.query(`SELECT phone, name, bio, last_seen FROM users WHERE phone = $1`, [phoneQuery]);
            if (result.rows.length > 0) {
                // User mil gaya
                socket.emit('contact_result', { success: true, user: result.rows[0] });
            } else {
                // User nahi mila
                socket.emit('contact_result', { success: false, message: "User not found on Koveo Network" });
            }
        } catch (err) {
            console.error("Lookup Error:", err);
            socket.emit('contact_result', { success: false, message: "Server error during lookup" });
        }
    });

    socket.on('send_message', async (data) => {
        const receiverSocket = connectedUsers.get(data.receiverId);
        let deliveryStatus = receiverSocket ? 'delivered' : 'sent';

        try {
            await pool.query(
                `INSERT INTO messages_queue (id, sender_id, receiver_id, text, timestamp, status) VALUES ($1, $2, $3, $4, $5, $6)`,
                [data.id, data.senderId, data.receiverId, data.text, data.timestamp, deliveryStatus]
            );
        } catch (err) { console.error("DB Insert Error", err); }

        if (receiverSocket) {
            io.to(receiverSocket).emit('receive_message', data);
            socket.emit('message_delivered', { messageId: data.id });
        }
    });

    socket.on('message_seen', async (data) => {
        try {
            await pool.query(`UPDATE messages_queue SET status = 'read' WHERE id = $1`, [data.messageId]);
            const senderSocket = connectedUsers.get(data.senderId);
            if (senderSocket) {
                io.to(senderSocket).emit('message_read_update', { messageId: data.messageId });
            }
        } catch (err) { console.error("Read Update Error", err); }
    });

    socket.on('disconnect', () => {
        for (let [userId, sockId] of connectedUsers.entries()) {
            if (sockId === socket.id) {
                connectedUsers.delete(userId);
                // Update Last Seen in DB
                pool.query(`UPDATE users SET last_seen = CURRENT_TIMESTAMP WHERE phone = $1`, [userId]).catch(console.error);
                console.log(`🔴 Offline: ${userId}`);
                break;
            }
        }
    });
});

setInterval(async () => {
    try {
        const result = await pool.query(`DELETE FROM messages_queue WHERE status = 'read' AND created_at < NOW() - INTERVAL '12 hours'`);
        if(result.rowCount > 0) console.log(`🗑️ Auto-Cleaned ${result.rowCount} messages.`);
    } catch (err) { console.error("Cleanup Job Error", err); }
}, 60 * 60 * 1000);

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => { console.log(`🚀 Koveo Routing Engine is running on port ${PORT}`); });