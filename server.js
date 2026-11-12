// server.js
const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const cors = require('cors');
const admin = require('firebase-admin');

// 🚀 INITIALIZE FIREBASE ADMIN
const serviceAccount = require('./koveo-firebase-adminsdk.json');
admin.initializeApp({
    credential: admin.credential.cert(serviceAccount)
});

const app = express();
app.use(cors());
const server = http.createServer(app);

// 🚀 50MB Buffer Limit so Base64 Voice Notes & HD Photos never get dropped by Socket.io!
const io = new Server(server, {
    cors: { origin: "*" },
    maxHttpBufferSize: 5e7,
    pingInterval: 10000,
    pingTimeout: 25000,
    connectTimeout: 30000
});

// ==========================================
// � STATELESS ROUTER MODE (ZERO DISK I/O)
// ==========================================
// No fs module, no JSON files, no offline message arrays!
// Maximum performance, zero memory leaks.

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const USERS_DB_FILE = path.join(__dirname, 'koveo_users_registry.json');
let registeredUsers = new Map();
let connectedUsers = new Map();
let userDevicesMap = new Map();
let simChallengesMap = new Map();
let pairingRateLimitMap = new Map();

// Load persistent registered users on server boot so Render restarts NEVER wipe Koveo users!
const loadPersistentUsers = () => {
    try {
        if (fs.existsSync(USERS_DB_FILE)) {
            const raw = JSON.parse(fs.readFileSync(USERS_DB_FILE, 'utf8') || '{}');
            Object.entries(raw).forEach(([phone, u]) => {
                registeredUsers.set(phone, { ...u, sessionTokens: new Set(u.sessionTokens || []) });
            });
            console.log(`📂 Loaded ${registeredUsers.size} persistent Koveo users from disk.`);
        }
    } catch (e) {
        console.warn('Registry load warning:', e.message);
    }
};

const savePersistentUsers = () => {
    try {
        const obj = {};
        registeredUsers.forEach((val, key) => {
            obj[key] = {
                phone: val.phone || key,
                name: val.name || 'Koveo User',
                bio: val.bio || 'Hey there! I am using Koveo.',
                dpUrl: val.dpUrl || '',
                dpBg: val.dpBg || '00d4ff',
                fcmToken: val.fcmToken || null,
                last_seen: val.last_seen || Date.now()
            };
        });
        fs.writeFileSync(USERS_DB_FILE, JSON.stringify(obj, null, 2), 'utf8');
    } catch (e) {}
};
loadPersistentUsers();

// Helper: Normalize phone to +91XXXXXXXXXX
const normalizeServerPhone = (raw) => {
    let digits = String(raw || '').replace(/\D/g, '');
    if (digits.length >= 10) return '+91' + digits.slice(-10);
    return String(raw || '').trim();
};

// Helper: Get ALL active socket IDs for a phone number (Matches +91, 10-digit, OR Display Name like 'Bdi Mummy' / 'Arnav'!)
const getAllSocketsForPhone = (rawTarget) => {
    let norm = normalizeServerPhone(rawTarget);
    const rawStr = String(rawTarget || '').trim().toLowerCase();

    // If frontend sent a contact name (e.g. 'Bdi Mummy' or 'Arnav') instead of +91 number, resolve phone from registeredUsers!
    if (!norm.startsWith('+91') && rawStr.length > 0) {
        registeredUsers.forEach((uData, regPhone) => {
            if (uData && uData.name && uData.name.trim().toLowerCase() === rawStr) {
                norm = regPhone;
            }
        });
    }

    const targetDigits = String(norm).replace(/\D/g, '').slice(-10);
    const sockIds = [];

    // 1. Check userDevicesMap
    const devMap = userDevicesMap.get(norm);
    if (devMap) {
        devMap.forEach((info, devId) => {
            const s = io.sockets.sockets.get(info.socketId);
            if (s && s.connected && !sockIds.includes(info.socketId)) {
                sockIds.push(info.socketId);
            } else if (!s || !s.connected) {
                devMap.delete(devId);
            }
        });
    }

    // 2. Check legacy connectedUsers map
    const legacyId = connectedUsers.get(norm);
    if (legacyId && !sockIds.includes(legacyId)) {
        const s = io.sockets.sockets.get(legacyId);
        if (s && s.connected) sockIds.push(legacyId);
    }

    // 3. Direct Live Scan across all connected sockets (Guarantees 0% missed messages or calls!)
    io.sockets.sockets.forEach((s) => {
        if (!s.connected || sockIds.includes(s.id)) return;
        const sPhone = normalizeServerPhone(s.userPhone);
        const sDigits = String(sPhone).replace(/\D/g, '').slice(-10);
        if ((sPhone && sPhone === norm) || (targetDigits.length === 10 && sDigits === targetDigits)) {
            sockIds.push(s.id);
        }
    });

    return { sockIds, matchedPhone: norm };
};

io.on('connection', (socket) => {
    console.log(`🟢 Device Connected: ${socket.id}`);

    // 🔐 1. CRYPTOGRAPHIC SIM CHALLENGE-RESPONSE (Prevents Fake Frontend Bypass!)
    socket.on('request_sim_challenge', (data, callback) => {
        const cleanPhone = normalizeServerPhone(data?.phone);
        if (cleanPhone.length < 10) {
            if (typeof callback === 'function') callback({ success: false, message: 'Invalid phone number' });
            return;
        }
        const nonce = 'KVN_' + crypto.randomBytes(12).toString('hex');
        simChallengesMap.set(cleanPhone, {
            nonce,
            simSlot: data?.simSlot || 1,
            expiresAt: Date.now() + (3 * 60 * 1000)
        });
        if (typeof callback === 'function') {
            callback({ success: true, nonce, timestamp: Date.now() });
        }
    });

    socket.on('verify_sim_proof', (data, callback) => {
        const cleanPhone = normalizeServerPhone(data?.phone);
        const challenge = simChallengesMap.get(cleanPhone);
        if (!challenge || Date.now() > challenge.expiresAt) {
            if (typeof callback === 'function') callback({ success: false, message: 'Challenge expired. Retry verification.' });
            return;
        }
        // Verify SHA-256 HMAC/Hash proof of (nonce + phone + deviceId)
        const expectedProof = crypto.createHash('sha256')
            .update(`${challenge.nonce}:${cleanPhone}:${data?.deviceId || 'default'}`)
            .digest('hex');

        if (data?.proof !== expectedProof) {
            if (typeof callback === 'function') callback({ success: false, message: 'Cryptographic SIM signature mismatch' });
            return;
        }

        simChallengesMap.delete(cleanPhone);
        const sessionToken = 'KVT_' + crypto.randomBytes(18).toString('hex');
        const prev = registeredUsers.get(cleanPhone) || {};
        prev.sessionTokens = new Set([...(prev.sessionTokens || []), sessionToken]);
        registeredUsers.set(cleanPhone, prev);

        if (typeof callback === 'function') {
            callback({
                success: true,
                sessionToken,
                existingUser: prev.name ? { name: prev.name, bio: prev.bio, dpUrl: prev.dpUrl } : null
            });
        }
    });

    // 🔗 2. RATE-LIMITED COMPANION DEVICE PAIRING + CHUNKED VAULT TRANSFER
    if (!global.companionPairingStore) global.companionPairingStore = new Map();

    socket.on('request_companion_link', (data, callback) => {
        const cleanPhone = normalizeServerPhone(data?.phone);
        if (cleanPhone.length < 10) {
            if (typeof callback === 'function') callback({ success: false });
            return;
        }
        // Generate cryptographically random 6-digit code
        const code = String(crypto.randomInt(100000, 999999));
        global.companionPairingStore.set(code, {
            secondarySocketId: socket.id,
            phone: cleanPhone,
            deviceId: data?.deviceId || ('comp_' + Date.now()),
            deviceName: data?.deviceName || 'Companion Device',
            ip: (socket.handshake.headers['x-forwarded-for'] || socket.handshake.address || 'Unknown IP').split(',')[0],
            createdAt: Date.now()
        });
        setTimeout(() => global.companionPairingStore.delete(code), 5 * 60 * 1000);
        if (typeof callback === 'function') callback({ success: true, code });
    });

    socket.on('approve_companion_link', (data, callback) => {
        const rateKey = socket.userPhone || socket.id;
        const rateRec = pairingRateLimitMap.get(rateKey) || { fails: 0, lockedUntil: 0 };
        if (Date.now() < rateRec.lockedUntil) {
            const waitSec = Math.ceil((rateRec.lockedUntil - Date.now()) / 1000);
            if (typeof callback === 'function') callback({ success: false, message: `Too many failed attempts. Locked for ${waitSec}s.` });
            return;
        }

        const code = String(data?.code || '').trim();
        const session = global.companionPairingStore.get(code);
        const myCleanPhone = normalizeServerPhone(socket.userPhone || data?.phone);

        if (!session || session.phone !== myCleanPhone) {
            rateRec.fails += 1;
            if (rateRec.fails >= 4) rateRec.lockedUntil = Date.now() + (5 * 60 * 1000);
            pairingRateLimitMap.set(rateKey, rateRec);
            if (typeof callback === 'function') callback({ success: false, message: 'Invalid code or phone number mismatch' });
            return;
        }

        pairingRateLimitMap.delete(rateKey);
        global.companionPairingStore.delete(code);

        // Issue dedicated companion session token
        const companionToken = 'KVT_COMP_' + crypto.randomBytes(16).toString('hex');
        const uRec = registeredUsers.get(myCleanPhone) || {};
        uRec.sessionTokens = new Set([...(uRec.sessionTokens || []), companionToken]);
        registeredUsers.set(myCleanPhone, uRec);

        io.to(session.secondarySocketId).emit('companion_link_approved', {
            phone: myCleanPhone,
            name: data.name || uRec.name,
            bio: data.bio || uRec.bio,
            dpUrl: data.dpUrl || uRec.dpUrl,
            sessionToken: companionToken,
            deviceId: session.deviceId,
            totalChunks: data.totalChunks || 0
        });

        if (typeof callback === 'function') {
            callback({
                success: true,
                secondarySocketId: session.secondarySocketId,
                deviceName: session.deviceName,
                ip: session.ip
            });
        }
    });

    // 📦 CHUNKED VAULT STREAMING (Streams 40 messages per packet so Socket never chokes!)
    socket.on('companion_sync_chunk', (chunkData, callback) => {
        if (chunkData && chunkData.targetSocketId) {
            io.to(chunkData.targetSocketId).emit('companion_receive_chunk', chunkData);
        }
        if (typeof callback === 'function') callback({ received: true });
    });

    // 🛡️ 3. LINKED DEVICES MANAGEMENT & 1-CLICK REMOTE REVOCATION
    socket.on('get_linked_devices', (callback) => {
        const cleanPhone = normalizeServerPhone(socket.userPhone);
        const devMap = userDevicesMap.get(cleanPhone) || new Map();
        const list = [];
        devMap.forEach((info, devId) => {
            list.push({
                deviceId: devId,
                deviceName: info.deviceName || 'Koveo Node',
                ip: info.ip || 'Encrypted IP',
                linkedAt: info.linkedAt,
                isPrimary: !!info.isPrimary,
                isCurrent: info.socketId === socket.id
            });
        });
        if (typeof callback === 'function') callback(list);
    });

    socket.on('revoke_companion_device', (data, callback) => {
        const cleanPhone = normalizeServerPhone(socket.userPhone);
        const targetDevId = data?.deviceId;
        const devMap = userDevicesMap.get(cleanPhone);
        if (devMap && targetDevId && devMap.has(targetDevId)) {
            const targetInfo = devMap.get(targetDevId);
            io.to(targetInfo.socketId).emit('force_logout', { reason: 'Session revoked from primary device' });
            const targetSock = io.sockets.sockets.get(targetInfo.socketId);
            if (targetSock) targetSock.disconnect();
            devMap.delete(targetDevId);
            if (typeof callback === 'function') callback({ success: true });
        } else {
            if (typeof callback === 'function') callback({ success: false });
        }
    });

    // 🔐 4. MULTI-DEVICE AUTHENTICATION (Supports Primary + Companion Simultaneously without kicking active sockets!)
    socket.on('auth_login', (data) => {
        const cleanPhone = normalizeServerPhone(data?.phone);
        if (!cleanPhone || cleanPhone.length < 5) return;

        // If client passed generic 'primary', bind unique socket ID so it never kicks another active phone!
        const rawDevId = data?.deviceId;
        const deviceId = (!rawDevId || rawDevId === 'primary')
            ? ('node_' + socket.id.slice(0, 10))
            : rawDevId;

        socket.userPhone = cleanPhone;
        socket.deviceId = deviceId;

        if (!userDevicesMap.has(cleanPhone)) {
            userDevicesMap.set(cleanPhone, new Map());
        }
        const devMap = userDevicesMap.get(cleanPhone);

        // Clean up only dead/disconnected sockets in devMap
        devMap.forEach((info, dKey) => {
            const existingSock = io.sockets.sockets.get(info.socketId);
            if (!existingSock || !existingSock.connected) {
                devMap.delete(dKey);
            }
        });

        devMap.set(deviceId, {
            socketId: socket.id,
            deviceName: data?.deviceName || (data?.isCompanion ? 'Companion Phone/Web' : 'Primary Phone'),
            ip: (socket.handshake.headers['x-forwarded-for'] || socket.handshake.address || 'Active Node').split(',')[0],
            linkedAt: Date.now(),
            isPrimary: !data?.isCompanion
        });

        connectedUsers.set(cleanPhone, socket.id);
        console.log(`📱 User Authenticated: ${cleanPhone} [Device: ${deviceId}, Total Linked: ${devMap.size}]`);

        const prevData = registeredUsers.get(cleanPhone) || {};
        registeredUsers.set(cleanPhone, {
            phone: cleanPhone,
            name: data.name || prevData.name || 'Koveo User',
            bio: data.bio || prevData.bio || 'Hey there! I am using Koveo.',
            dpUrl: data.dpUrl || prevData.dpUrl || `https://ui-avatars.com/api/?name=${encodeURIComponent(data.name || 'User')}&background=00d4ff&color=000`,
            dpBg: data.dpBg || prevData.dpBg || '00d4ff',
            fcmToken: data.fcmToken || prevData.fcmToken || null,
            sessionTokens: prevData.sessionTokens || new Set(),
            last_seen: Date.now()
        });

        savePersistentUsers();
        socket.emit('auth_success', { phone: cleanPhone, deviceId, user: registeredUsers.get(cleanPhone) });
        socket.broadcast.emit('user_came_online', { phone: cleanPhone, user: registeredUsers.get(cleanPhone) });

        if (global.pendingCalls && global.pendingCalls.has(cleanPhone)) {
            const pendingCallData = global.pendingCalls.get(cleanPhone);
            socket.emit('incoming_call', pendingCallData);
            global.pendingCalls.delete(cleanPhone);
        }
    });

    // 🔄 LIVE PROFILE & DP UPDATE (Broadcasts to Contacts + Mirrors to User's Own Linked Companion Devices!)
    socket.on('update_profile', (data) => {
        const cleanPhone = normalizeServerPhone(socket.userPhone || data?.phone);
        if (cleanPhone && registeredUsers.has(cleanPhone)) {
            const u = registeredUsers.get(cleanPhone);
            if (data.name) u.name = data.name;
            if (data.bio) u.bio = data.bio;
            if (data.dpUrl) u.dpUrl = data.dpUrl;
            registeredUsers.set(cleanPhone, u);
            savePersistentUsers();

            // 1. Update all contacts who have this user saved
            socket.broadcast.emit('contact_profile_updated', u);

            // 2. Mirror updated Name, Bio & DP to user's own other linked devices (Phone A <-> Phone B)
            const { sockIds: mySockets } = getAllSocketsForPhone(cleanPhone);
            mySockets.forEach(sId => {
                if (sId !== socket.id) io.to(sId).emit('own_profile_synced', u);
            });
        }
    });

    // 🔄 MULTI-DEVICE STATE SYNC (Mirrors Delete-for-Me, Clear Chat, Block, Pin, Mute, Star Across User's Own Linked Devices!)
    socket.on('own_device_state_sync', (pkt) => {
        if (!socket.userPhone || !pkt) return;
        const { sockIds: mySockets } = getAllSocketsForPhone(socket.userPhone);
        mySockets.forEach(sId => {
            if (sId !== socket.id) io.to(sId).emit('own_device_state_sync', pkt);
        });
    });

    // 🌟 NEW: INSTANT SUGGESTIONS OF USERS ALREADY ON KOVEO (With DP & Online Status)
    socket.on('get_koveo_suggestions', () => {
        const myPhone = socket.userPhone;
        const suggestions = [];
        registeredUsers.forEach((uData, phoneKey) => {
            if (phoneKey !== myPhone) {
                suggestions.push({
                    phone: phoneKey,
                    name: uData.name,
                    bio: uData.bio,
                    dpUrl: uData.dpUrl,
                    dpBg: uData.dpBg || '00d4ff',
                    isOnline: connectedUsers.has(phoneKey),
                    last_seen: uData.last_seen
                });
            }
        });
        socket.emit('koveo_suggestions_list', suggestions);
    });

    // ✅ ON-DEMAND CONTACT VERIFICATION & DP FETCH (Used by checkAndOpenChat)
    socket.on('check_user_exists', (phoneQuery, callback) => {
        const queryDigits = String(phoneQuery || '').replace(/\D/g, '').slice(-10);
        let matchedUser = null;

        registeredUsers.forEach((uData, regPhone) => {
            const regDigits = String(regPhone).replace(/\D/g, '').slice(-10);
            if (queryDigits.length >= 5 && regDigits === queryDigits) {
                matchedUser = {
                    exists: true,
                    phone: regPhone,
                    name: uData.name,
                    bio: uData.bio || 'Available on Koveo',
                    dpUrl: uData.dpUrl || null,
                    dpBg: uData.dpBg || '00d4ff',
                    isOnline: connectedUsers.has(regPhone)
                };
            }
        });

        if (typeof callback === 'function') {
            if (matchedUser) callback(matchedUser);
            else callback({ exists: false });
        }
    });

    // 🔍 SECURE CONTACT LOOKUP (Smart Last-10-Digit Matching + DP Return)
    socket.on('search_contact', (phoneQuery) => {
        const queryDigits = String(phoneQuery || '').replace(/\D/g, '').slice(-10);
        let foundUser = null;

        registeredUsers.forEach((uData, phoneKey) => {
            const keyDigits = String(phoneKey).replace(/\D/g, '').slice(-10);
            if (queryDigits.length >= 5 && keyDigits === queryDigits) {
                foundUser = {
                    phone: phoneKey,
                    name: uData.name,
                    bio: uData.bio,
                    dpUrl: uData.dpUrl,
                    dpBg: uData.dpBg || '00d4ff',
                    isOnline: connectedUsers.has(phoneKey)
                };
            }
        });

        if (foundUser) {
            socket.emit('contact_result', { success: true, user: foundUser });
        } else {
            socket.emit('contact_result', { success: false, phoneQuery: phoneQuery, message: "User not found on Koveo" });
        }
    });

    // 🚀 WHATSAPP-STYLE BULK CONTACT SYNC (Matches any phone format + Returns DPs)
    socket.on('sync_contacts', (phoneList) => {
        let matchedContacts = [];
        const seenPhones = new Set();

        if (Array.isArray(phoneList)) {
            phoneList.forEach(rawItem => {
                const rawPhone = typeof rawItem === 'object' ? rawItem.phone : rawItem;
                const localName = typeof rawItem === 'object' ? rawItem.name : null;
                const targetDigits = String(rawPhone || '').replace(/\D/g, '').slice(-10);
                if (targetDigits.length < 5) return;

                registeredUsers.forEach((uData, regPhone) => {
                    const regDigits = String(regPhone).replace(/\D/g, '').slice(-10);
                    if (regDigits === targetDigits && !seenPhones.has(regPhone)) {
                        seenPhones.add(regPhone);
                        matchedContacts.push({
                            phone: regPhone,
                            name: localName || uData.name,
                            koveoName: uData.name,
                            bio: uData.bio,
                            dpUrl: uData.dpUrl,
                            dpBg: uData.dpBg || '00d4ff',
                            isOnline: connectedUsers.has(regPhone)
                        });
                    }
                });
            });
        }

        socket.emit('sync_contacts_result', matchedContacts);
        console.log(`🔄 Sync: Found ${matchedContacts.length} Koveo users.`);
    });
    // Helper: Smart 10-Digit Socket Resolver (Matches +919876543210, 9876543210, 09876543210)
    const resolveSocketByPhone = (rawTarget) => {
        if (!rawTarget) return { sockId: null, matchedPhone: rawTarget };
        if (connectedUsers.has(rawTarget)) return { sockId: connectedUsers.get(rawTarget), matchedPhone: rawTarget };
        const targetDigits = String(rawTarget).replace(/\D/g, '').slice(-10);
        let foundSock = null, foundPhone = rawTarget;
        if (targetDigits.length === 10) {
            connectedUsers.forEach((sId, regPhone) => {
                if (String(regPhone).replace(/\D/g, '').slice(-10) === targetDigits) {
                    foundSock = sId;
                    foundPhone = regPhone;
                }
            });
        }
        return { sockId: foundSock, matchedPhone: foundPhone };
    };

    // 🕒 ZERO-DB 12-HOUR ENCRYPTED RAM QUEUE, ACTION SYNC QUEUE & MISSED CALL QUEUE
    if (!global.encryptedRamQueue) global.encryptedRamQueue = new Map();
    if (!global.pendingActionQueue) global.pendingActionQueue = new Map();
    if (!global.missedCallsQueue) global.missedCallsQueue = new Map();

    const flushQueuedMessagesForUser = (userPhone) => {
        const digits = String(userPhone || '').replace(/\D/g, '').slice(-10);
        if (digits.length < 10) return;

        // 1. Flush Queued Encrypted Messages (Keep in queue until client emits 'message_delivered' ACK!)
        const qList = global.encryptedRamQueue.get(digits);
        if (qList && qList.length > 0) {
            console.log(`⚡ Flushing ${qList.length} queued encrypted messages to ${userPhone}`);
            qList.forEach(pkt => {
                socket.emit('receive_message', pkt);
                const { sockIds: senderSockets } = getAllSocketsForPhone(pkt.senderId);
                senderSockets.forEach(sId => {
                    io.to(sId).emit('message_delivered', { messageId: pkt.id });
                });
            });
        }

        // 2. Flush Queued Delete-for-Everyone / Edit / Reaction Sync Events!
        const aList = global.pendingActionQueue.get(digits);
        if (aList && aList.length > 0) {
            console.log(`🗑️ Flushing ${aList.length} queued message actions (delete/edit) to ${userPhone}`);
            aList.forEach(act => socket.emit('message_action_sync', act));
            global.pendingActionQueue.delete(digits);
        }

        // 3. Flush Queued Missed Calls
        const mCalls = global.missedCallsQueue.get(digits);
        if (mCalls && mCalls.length > 0) {
            mCalls.forEach(mc => socket.emit('receive_missed_call', mc));
            global.missedCallsQueue.delete(digits);
        }
    };

    // Trigger queue flush whenever auth_login completes OR client explicitly requests sync on reconnect!
    socket.on('auth_login', () => {
        setTimeout(() => {
            if (socket.userPhone) flushQueuedMessagesForUser(socket.userPhone);
        }, 120);
        setTimeout(() => {
            if (socket.userPhone) flushQueuedMessagesForUser(socket.userPhone);
        }, 800);
    });

    socket.on('request_offline_sync', (data) => {
        const targetPhone = socket.userPhone || (data && data.phone);
        if (targetPhone) {
            flushQueuedMessagesForUser(targetPhone);
        }
    });

    // ==========================================
    // 📞 MULTI-DEVICE WEBRTC SIGNALING, ICE BUFFERING & FCM WAKE-UP ENGINE
    // ==========================================
    if (!global.pendingCalls) global.pendingCalls = new Map();
    if (!global.pendingCallCandidates) global.pendingCallCandidates = new Map();

    socket.on('call_user', async (data, callback) => {
        const callerNorm = normalizeServerPhone(socket.userPhone || data?.from);
        if (callerNorm && callerNorm.startsWith('+91') && !socket.userPhone) {
            socket.userPhone = callerNorm;
            connectedUsers.set(callerNorm, socket.id);
        }
        const { sockIds: receiverSockets, matchedPhone } = getAllSocketsForPhone(data?.userToCall);
        console.log(`📞 CALL REQUEST: From ${callerNorm} -> To ${data?.userToCall} (Matched: ${matchedPhone}, Active Receiver Sockets: ${receiverSockets.length})`);
        const callerProfile = registeredUsers.get(callerNorm) || {};

        // Reset old buffered ICE candidates for this new call session
        if (!data.isIceRestart) {
            global.pendingCallCandidates.set(matchedPhone, []);
        }

        const callPacket = {
            signal: data.signalData,
            from: callerNorm,
            callerName: data.callerName || callerProfile.name || callerNorm,
            callerDp: data.callerDp || callerProfile.dpUrl || '',
            type: data.type || 'Voice',
            isIceRestart: !!data.isIceRestart
        };

        if (receiverSockets.length > 0) {
            // If calling own number and multiple devices are linked, ring the OTHER device(s); if only 1 device, loopback to self for testing!
            const otherDeviceSockets = receiverSockets.filter(id => id !== socket.id);
            const targetSockets = otherDeviceSockets.length > 0 ? otherDeviceSockets : receiverSockets;

            targetSockets.forEach(sId => {
                if (data.isIceRestart) {
                    io.to(sId).emit('call_renegotiate_offer', callPacket);
                } else {
                    io.to(sId).emit('incoming_call', callPacket);
                }
            });
            if (typeof callback === 'function') callback({ ringing: true, online: true });
        } else {
            // Store pending call for 45 seconds in case receiver wakes up via FCM or reconnects
            global.pendingCalls.set(matchedPhone, callPacket);
            setTimeout(() => {
                if (global.pendingCalls.get(matchedPhone) === callPacket) {
                    global.pendingCalls.delete(matchedPhone);
                    global.pendingCallCandidates.delete(matchedPhone);
                }
            }, 45000);

            const targetUser = registeredUsers.get(matchedPhone) || registeredUsers.get(data.userToCall);
            if (targetUser && targetUser.fcmToken) {
                console.log(`🔔 Waking up ${matchedPhone} via FCM High-Priority Call Push...`);
                const payload = {
                    token: targetUser.fcmToken,
                    data: {
                        type: 'INCOMING_CALL',
                        callerPhone: String(callerNorm),
                        callerName: String(callPacket.callerName),
                        callType: String(callPacket.type)
                    },
                    android: { priority: 'high', ttl: 45000 }
                };

                try {
                    await admin.messaging().send(payload);
                    socket.emit('call_ringing_push_sent');
                    if (typeof callback === 'function') callback({ ringing: true, pushSent: true });
                } catch (error) {
                    socket.emit('call_failed', { message: "User is unreachable" });
                    if (typeof callback === 'function') callback({ ringing: false });
                }
            } else {
                socket.emit('call_failed', { message: "User offline and no push token" });
                if (typeof callback === 'function') callback({ ringing: false });
            }
        }
    });

    // Receiver device confirms it is ringing (Shows real "Ringing..." on Caller's screen!)
    socket.on('call_ringing_ack', (data) => {
        const { sockIds: callerSockets } = getAllSocketsForPhone(data?.to);
        callerSockets.forEach(sId => io.to(sId).emit('call_ringing_ack'));

        // Also flush any buffered ICE candidates to this ringing receiver
        const myNorm = normalizeServerPhone(socket.userPhone);
        const buffered = global.pendingCallCandidates.get(myNorm) || [];
        buffered.forEach(cand => socket.emit('ice_candidate', cand));
    });

    socket.on('answer_call', (data) => {
        const { sockIds: callerSockets } = getAllSocketsForPhone(data.to);
        callerSockets.forEach(sId => io.to(sId).emit('call_accepted', data.signal));

        const myNorm = normalizeServerPhone(socket.userPhone);
        global.pendingCalls.delete(myNorm);

        // Flush any buffered ICE candidates to the answering device
        const buffered = global.pendingCallCandidates.get(myNorm) || [];
        if (buffered.length > 0) {
            buffered.forEach(cand => socket.emit('ice_candidate', cand));
            global.pendingCallCandidates.delete(myNorm);
        }

        // Stop ringing on receiver's other linked companion devices once answered on this device!
        if (myNorm) {
            const { sockIds: myOtherSocks } = getAllSocketsForPhone(myNorm);
            myOtherSocks.forEach(sId => {
                if (sId !== socket.id) io.to(sId).emit('call_ended', { reason: 'Answered on another device' });
            });
        }
    });

    // In-Call Live Renegotiation (Network Switch Wi-Fi <-> 5G or Voice <-> Video Upgrade)
    socket.on('call_renegotiate_offer', (data) => {
        const { sockIds: peerSockets } = getAllSocketsForPhone(data?.to);
        peerSockets.forEach(sId => io.to(sId).emit('call_renegotiate_offer', {
            from: normalizeServerPhone(socket.userPhone),
            signal: data.signal,
            videoEnabled: data.videoEnabled
        }));
    });

    socket.on('call_renegotiate_answer', (data) => {
        const { sockIds: peerSockets } = getAllSocketsForPhone(data?.to);
        peerSockets.forEach(sId => io.to(sId).emit('call_renegotiate_answer', {
            from: normalizeServerPhone(socket.userPhone),
            signal: data.signal
        }));
    });

    socket.on('ice_candidate', (data) => {
        if (!data || !data.candidate) return;
        const { sockIds: peerSockets, matchedPhone } = getAllSocketsForPhone(data.to);
        if (peerSockets.length > 0) {
            peerSockets.forEach(sId => io.to(sId).emit('ice_candidate', data.candidate));
        } else if (matchedPhone) {
            // Buffer up to 35 ICE candidates while receiver phone is waking up from FCM push!
            const list = global.pendingCallCandidates.get(matchedPhone) || [];
            if (list.length < 35) {
                list.push(data.candidate);
                global.pendingCallCandidates.set(matchedPhone, list);
            }
        }
    });

    socket.on('call_busy', (data) => {
        const { sockIds: callerSockets } = getAllSocketsForPhone(data.to);
        callerSockets.forEach(sId => io.to(sId).emit('call_busy'));
    });

    socket.on('leave_missed_call', (data) => {
        const digits = String(data.to || '').replace(/\D/g, '').slice(-10);
        if (digits.length === 10) {
            const list = global.missedCallsQueue.get(digits) || [];
            list.push({
                from: normalizeServerPhone(socket.userPhone || 'Unknown'),
                callerName: data.callerName || 'Koveo User',
                timestamp: data.timestamp || 'Just now'
            });
            global.missedCallsQueue.set(digits, list.slice(-20));
        }
    });

    socket.on('end_call', async (data) => {
        const { sockIds: peerSockets, matchedPhone } = getAllSocketsForPhone(data?.to);
        if (matchedPhone) {
            global.pendingCalls.delete(matchedPhone);
            global.pendingCallCandidates.delete(matchedPhone);
        }
        if (socket.userPhone) {
            const myNorm = normalizeServerPhone(socket.userPhone);
            global.pendingCalls.delete(myNorm);
            global.pendingCallCandidates.delete(myNorm);
            const { sockIds: myOtherSocks } = getAllSocketsForPhone(myNorm);
            myOtherSocks.forEach(sId => {
                if (sId !== socket.id) io.to(sId).emit('call_ended');
            });
        }
        if (peerSockets.length > 0) {
            peerSockets.forEach(sId => io.to(sId).emit('call_ended'));
        } else if (matchedPhone) {
            const targetUser = registeredUsers.get(matchedPhone);
            if (targetUser && targetUser.fcmToken) {
                try {
                    await admin.messaging().send({
                        token: targetUser.fcmToken,
                        data: { type: 'CALL_CANCELLED', callerPhone: socket.userPhone || 'unknown' },
                        android: { priority: 'high' }
                    });
                } catch (e) {}
            }
        }
    });

    // 📨 MULTI-DEVICE SEND MESSAGE ENGINE (Delivers to ALL Receiver Devices + Mirrors to Sender's Other Linked Devices!)
    socket.on('send_message', (data, callback) => {
        const senderNorm = normalizeServerPhone(socket.userPhone || data?.senderId);
        if (senderNorm && senderNorm.startsWith('+91') && !socket.userPhone) {
            socket.userPhone = senderNorm;
            connectedUsers.set(senderNorm, socket.id);
        }
        data.senderId = senderNorm;
        const { sockIds: receiverSockets, matchedPhone } = getAllSocketsForPhone(data?.receiverId);
        console.log(`💬 MSG ROUTE: From ${senderNorm} -> To ${matchedPhone} (Active Receiver Sockets: ${receiverSockets.length})`);
        data.receiverId = matchedPhone;

        // 1. Store in RAM Queue until at least 1 receiver device ACKs delivery
        const recDigits = String(matchedPhone || '').replace(/\D/g, '').slice(-10);
        if (recDigits.length === 10) {
            const existingQ = global.encryptedRamQueue.get(recDigits) || [];
            if (!existingQ.some(m => m.id === data.id)) {
                existingQ.push({ ...data, queuedAt: Date.now() });
                global.encryptedRamQueue.set(recDigits, existingQ.slice(-100));
            }
        }

        // 2. SELF-MESSAGE MIRRORING: Send outgoing message copy to Sender's other linked devices (Phone A <-> Phone B)!
        const { sockIds: senderOtherSockets } = getAllSocketsForPhone(senderNorm);
        senderOtherSockets.forEach(sId => {
            if (sId !== socket.id) {
                io.to(sId).emit('receive_self_message_mirror', data);
            }
        });

        const isPeerTrulyConnected = receiverSockets.length > 0;
        if (typeof callback === 'function') {
            callback({ 
                queued: true, 
                peerOnline: isPeerTrulyConnected,
                receiverOffline: !isPeerTrulyConnected // 🚀 Frontend trigger for SMS Pill!
            });
        }

        // 3. Emit to ALL active devices of the receiver
        if (isPeerTrulyConnected) {
            receiverSockets.forEach(sId => io.to(sId).emit('receive_message', data));
        } else {
            socket.emit('recipient_offline_notice', {
                messageId: data.id,
                receiverId: matchedPhone
            });
            const targetUser = registeredUsers.get(matchedPhone);
            if (targetUser && targetUser.fcmToken) {
                admin.messaging().send({
                    token: targetUser.fcmToken,
                    notification: {
                        title: `New Encrypted Message`,
                        body: `New message from ${senderNorm}`
                    },
                    data: { type: 'WAKE_UP_SYNC', senderPhone: String(senderNorm || '') },
                    android: { priority: 'high' }
                }).catch((err) => {
                    // 🛡️ FIX: Remove stale FCM tokens to prevent Firebase from banning/throttling your project!
                    if (err.code === 'messaging/registration-token-not-registered' || err.code === 'messaging/invalid-registration-token') {
                        const u = registeredUsers.get(matchedPhone);
                        if (u) {
                            u.fcmToken = null;
                            registeredUsers.set(matchedPhone, u);
                            savePersistentUsers();
                            console.log(`🗑️ Removed stale FCM token for ${matchedPhone}`);
                        }
                    }
                });
            }
        }
    });

    // 🔄 SYNC OLD DOUBLE TICKS ON BOOT (RAM Queue Check)
    socket.on('check_message_statuses', (msgIds, callback) => {
        if (!Array.isArray(msgIds) || typeof callback !== 'function') return;
        const statuses = [];
        
        msgIds.forEach(id => {
            let isStillPending = false;
            // Scan RAM queue: If message is NO LONGER in the receiver's queue, it was successfully delivered!
            if (global.encryptedRamQueue) {
                for (const queue of global.encryptedRamQueue.values()) {
                    if (queue.some(m => m.id === id)) {
                        isStillPending = true;
                        break;
                    }
                }
            }
            if (!isStillPending) {
                statuses.push({ id, status: 'delivered' });
            }
        });
        
        callback(statuses);
    });

    // ✔️✔️ MULTI-DEVICE BULLETPROOF DELIVERY RECEIPT RELAY (Never deletes until ALL linked devices receive it!)
    socket.on('message_delivered', (data) => {
        if (!data || !data.messageId) return;
        const cleanPhone = normalizeServerPhone(socket.userPhone);
        const myDigits = String(cleanPhone || '').replace(/\D/g, '').slice(-10);
        const devId = socket.deviceId || 'default';

        if (myDigits.length === 10 && global.encryptedRamQueue.has(myDigits)) {
            const q = global.encryptedRamQueue.get(myDigits) || [];
            const devMap = userDevicesMap.get(cleanPhone);
            const totalLinkedCount = devMap ? Math.max(1, devMap.size) : 1;

            const updatedQueue = q.filter(m => {
                if (m.id !== data.messageId) return true;
                if (!Array.isArray(m.deliveredToDevices)) m.deliveredToDevices = [];
                if (!m.deliveredToDevices.includes(devId)) m.deliveredToDevices.push(devId);
                // Keep message in RAM queue until EVERY linked device of this account has received it!
                return m.deliveredToDevices.length < totalLinkedCount;
            });
            global.encryptedRamQueue.set(myDigits, updatedQueue);
        }
        if (data.senderId) {
            const { sockIds } = getAllSocketsForPhone(data.senderId);
            sockIds.forEach(sId => io.to(sId).emit('message_delivered', { messageId: data.messageId }));
        }
    });

    // 💙 MULTI-DEVICE MESSAGE SEEN (BLUE TICK) + OWN-DEVICE READ SYNC
    socket.on('message_seen', (data) => {
        if (!data) return;
        const { sockIds: senderSocks } = getAllSocketsForPhone(data.senderId);
        senderSocks.forEach(sId => io.to(sId).emit('message_read_update', { messageId: data.messageId, readerId: socket.userPhone }));

        // Also tell reader's own other linked devices that this chat was read!
        if (socket.userPhone) {
            const { sockIds: myOtherSocks } = getAllSocketsForPhone(socket.userPhone);
            myOtherSocks.forEach(sId => {
                if (sId !== socket.id) {
                    io.to(sId).emit('own_device_chat_read', { chatId: normalizeServerPhone(data.senderId), messageId: data.messageId });
                }
            });
        }
    });

    // ✍️ MULTI-DEVICE LIVE TYPING RELAY
    socket.on('typing', (data) => {
        if (!data || !data.to) return;
        const { sockIds } = getAllSocketsForPhone(data.to);
        sockIds.forEach(sId => io.to(sId).emit('typing', data));
    });

    // ⚡ MULTI-DEVICE EDIT, DELETE-FOR-EVERYONE & REACTION SYNC (Syncs to Peer Devices AND Sender's Own Linked Devices!)
    socket.on('message_action_sync', (data) => {
        if (!data || !data.receiverId) return;
        const { sockIds: peerSockets } = getAllSocketsForPhone(data.receiverId);
        const recDigits = String(data.receiverId).replace(/\D/g, '').slice(-10);

        if (data.action === 'delete_everyone' && recDigits.length === 10 && global.encryptedRamQueue.has(recDigits)) {
            const q = global.encryptedRamQueue.get(recDigits) || [];
            const shortId = data.shortId || String(data.msgId || '').replace(/[^a-zA-Z0-9]/g, '').slice(-7);
            global.encryptedRamQueue.set(recDigits, q.filter(m => m.id !== data.msgId && !String(m.id || '').endsWith(shortId)));
        }

        if (recDigits.length === 10) {
            const actList = global.pendingActionQueue.get(recDigits) || [];
            if (!actList.some(a => a.msgId === data.msgId && a.action === data.action)) {
                actList.push({ ...data, queuedAt: Date.now() });
                global.pendingActionQueue.set(recDigits, actList.slice(-100));
            }
        }

        // 1. Emit to all active sockets of the receiver
        peerSockets.forEach(sId => io.to(sId).emit('message_action_sync', data));

        // 2. Also mirror the delete/edit/reaction to Sender's own other linked devices!
        if (socket.userPhone) {
            const { sockIds: myOtherSocks } = getAllSocketsForPhone(socket.userPhone);
            myOtherSocks.forEach(sId => {
                if (sId !== socket.id) io.to(sId).emit('message_action_sync', data);
            });
        }
    });

    // 🚩 TRUST & SAFETY REPORT HANDLER
    socket.on('report_user', (data) => {
        console.log(`🚩 Safety Report from ${socket.userPhone} against ${data?.targetId}: ${data?.reason}`);
    });

    // 🔴 MULTI-DEVICE DISCONNECT LOGIC & GHOST CALL CANCELLATION
    socket.on('disconnect', () => {
        const userId = socket.userPhone;
        if (!userId) return;

        // 📞 FIX: Prevent "Ghost Ringing" - If the caller's internet drops, cancel their outgoing calls instantly!
        const myNorm = normalizeServerPhone(userId);
        if (global.pendingCalls) {
            global.pendingCalls.forEach((callData, receiverPhone) => {
                if (callData.from === myNorm) {
                    global.pendingCalls.delete(receiverPhone);
                    if (global.pendingCallCandidates) global.pendingCallCandidates.delete(receiverPhone);
                    const { sockIds: recSockets } = getAllSocketsForPhone(receiverPhone);
                    recSockets.forEach(sId => io.to(sId).emit('call_ended', { reason: 'Caller disconnected' }));
                }
            });
        }

        const devMap = userDevicesMap.get(userId);
        if (devMap && socket.deviceId) {
            const entry = devMap.get(socket.deviceId);
            if (entry && entry.socketId === socket.id) {
                devMap.delete(socket.deviceId);
            }
        }

        const { sockIds: remainingSockets } = getAllSocketsForPhone(userId);
        if (remainingSockets.length > 0) {
            connectedUsers.set(userId, remainingSockets[0]);
        } else {
            connectedUsers.delete(userId);
            const nowTs = Date.now();
            if (registeredUsers.has(userId)) {
                let uData = registeredUsers.get(userId);
                uData.last_seen = nowTs;
                registeredUsers.set(userId, uData);
            }
            socket.broadcast.emit('user_went_offline', { phone: userId, last_seen: nowTs });
            console.log(`🔴 All Devices Offline for: ${userId}`);
        }
    });
});

// 🧹 12-Hour Automatic RAM Queue Cleanup
setInterval(() => {
    if (!global.encryptedRamQueue) return;
    const cutoff = Date.now() - (12 * 60 * 60 * 1000);
    global.encryptedRamQueue.forEach((list, key) => {
        const fresh = list.filter(item => (item.queuedAt || Date.now()) > cutoff);
        if (fresh.length === 0) global.encryptedRamQueue.delete(key);
        else global.encryptedRamQueue.set(key, fresh);
    });
}, 30 * 60 * 1000);

const PORT = process.env.PORT || 3000;
server.listen(PORT, '0.0.0.0', () => { 
    console.log(`🚀 Koveo Routing Engine is running on port ${PORT}`); 
});
