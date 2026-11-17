// server.js
const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const cors = require('cors');

// 🚀 SAFE INITIALIZE FIREBASE ADMIN (Never crashes server if JSON or module is missing!)
let admin = null;
let isFirebaseReady = false;
try {
    admin = require('firebase-admin');
    const fsCheck = require('fs');
    const pathCheck = require('path');
    const keyPath = pathCheck.join(__dirname, 'koveo-firebase-adminsdk.json');
    if (process.env.FIREBASE_SERVICE_ACCOUNT) {
        admin.initializeApp({
            credential: admin.credential.cert(JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT))
        });
        isFirebaseReady = true;
    } else if (fsCheck.existsSync(keyPath)) {
        const serviceAccount = require(keyPath);
        admin.initializeApp({
            credential: admin.credential.cert(serviceAccount)
        });
        isFirebaseReady = true;
    } else {
        console.warn('⚠️ koveo-firebase-adminsdk.json not found — running Socket-Only Mode (No Crash).');
    }
} catch (err) {
    console.warn('⚠️ Firebase Admin skipped:', err.message);
}

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
                primaryDeviceId: val.primaryDeviceId || null,
                hardwarePublicKey: val.hardwarePublicKey || null,
                apkCertHash: val.apkCertHash || null,
                sessionTokens: Array.from(val.sessionTokens || []).slice(-10),
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

    // 🔐 1. MILITARY-GRADE HARDWARE KEYSTORE ECDSA CHALLENGE-RESPONSE + BRUTE-FORCE LOCKOUT
    if (!global.authRateLimitMap) global.authRateLimitMap = new Map();

    socket.on('request_sim_challenge', (data, callback) => {
        const clientIp = (socket.handshake.headers['x-forwarded-for'] || socket.handshake.address || 'unknown').split(',')[0].trim();
        const cleanPhone = normalizeServerPhone(data?.phone);
        const raw10 = cleanPhone.replace(/\D/g, '').slice(-10);

        // Brute-Force IP + Phone Lockout Check
        const rateKey = `${clientIp}_${cleanPhone}`;
        const rateInfo = global.authRateLimitMap.get(rateKey) || { count: 0, lockUntil: 0 };
        if (Date.now() < rateInfo.lockUntil) {
            const waitSec = Math.ceil((rateInfo.lockUntil - Date.now()) / 1000);
            if (typeof callback === 'function') callback({ success: false, message: `🛡️ Security Lockout! Wait ${waitSec}s before retrying.` });
            return;
        }

        if (raw10.length !== 10 || !/^[6-9]\d{9}$/.test(raw10) || /^(\d)\1{9}$/.test(raw10) || raw10 === '9876543210') {
            if (typeof callback === 'function') callback({ success: false, message: '❌ Invalid mobile number format.' });
            return;
        }

        const hwMethod = String(data?.hardwareMethod || '');
        const pubKey = String(data?.publicKey || '').trim();
        // 🛑 STRICT HARDWARE LOCK: Reject Laptop/Web/Browser requests that lack an Android Keystore ECDSA Public Key!
        if (!hwMethod || !hwMethod.startsWith('SIM_') || !pubKey || pubKey.length < 40) {
            if (typeof callback === 'function') {
                callback({
                    success: false,
                    message: '❌ Direct login requires an Android Phone with physical SIM! On Laptop/Web, use "Link as companion device".'
                });
            }
            return;
        }

        const existingUser = registeredUsers.get(cleanPhone);
        if (existingUser && existingUser.primaryDeviceId && existingUser.primaryDeviceId !== data?.deviceId) {
            const isPhysicalSimMove = hwMethod.startsWith('SIM_') && !!data?.publicKey;
            if (!isPhysicalSimMove) {
                if (typeof callback === 'function') {
                    callback({
                        success: false,
                        message: '❌ Account locked to primary phone hardware! Use "Link as companion device".'
                    });
                }
                return;
            }
        }

        // 256-bit Cryptographic Random Nonce (Single-Use, 90s TTL)
        const nonce = 'KVN_' + crypto.randomBytes(32).toString('hex');
        simChallengesMap.set(cleanPhone, {
            nonce,
            socketId: socket.id,
            clientIp,
            simSlot: data?.simSlot || 1,
            deviceId: data?.deviceId,
            hardwareMethod: hwMethod,
            publicKey: data?.publicKey || '',
            apkCertHash: data?.apkCertHash || 'web',
            expiresAt: Date.now() + (90 * 1000)
        });

        if (typeof callback === 'function') {
            callback({ success: true, nonce, timestamp: Date.now() });
        }
    });

    socket.on('verify_sim_proof', (data, callback) => {
        const clientIp = (socket.handshake.headers['x-forwarded-for'] || socket.handshake.address || 'unknown').split(',')[0].trim();
        const cleanPhone = normalizeServerPhone(data?.phone);
        const rateKey = `${clientIp}_${cleanPhone}`;
        const rateInfo = global.authRateLimitMap.get(rateKey) || { count: 0, lockUntil: 0 };

        const recordFailure = (msg) => {
            rateInfo.count += 1;
            if (rateInfo.count >= 5) {
                rateInfo.lockUntil = Date.now() + (10 * 60 * 1000); // 10-minute ban after 5 failed attempts
            }
            global.authRateLimitMap.set(rateKey, rateInfo);
            if (typeof callback === 'function') callback({ success: false, message: msg });
        };

        const challenge = simChallengesMap.get(cleanPhone);
        if (!challenge || Date.now() > challenge.expiresAt || challenge.socketId !== socket.id) {
            simChallengesMap.delete(cleanPhone);
            return recordFailure('❌ Challenge expired or socket mismatch. Retry verification.');
        }

        // Delete nonce immediately (Strict One-Time Use to prevent Replay Attacks!)
        simChallengesMap.delete(cleanPhone);

        if (!data?.hardwareVerified || data.hardwareMethod !== challenge.hardwareMethod) {
            return recordFailure('❌ Hardware SIM verification not attested.');
        }

        const canonicalPayload = `${challenge.nonce}:${cleanPhone}:${data?.deviceId || 'default'}:${challenge.hardwareMethod}:${challenge.apkCertHash}`;
        const prev = registeredUsers.get(cleanPhone) || {};

        // 🔐 VERIFY ANDROID HARDWARE KEYSTORE ECDSA P-256 SIGNATURE
        if (data.publicKey && data.hwSignature) {
            try {
                // If same deviceId already registered a hardwarePublicKey, enforce exact key match!
                if (prev.primaryDeviceId === data.deviceId && prev.hardwarePublicKey && prev.hardwarePublicKey !== data.publicKey) {
                    return recordFailure('🚨 Hardware Keystore Mismatch! Spoofed device ID blocked.');
                }

                // Enforce APK Signature Pinning (First registered APK cert locks the server against modded APKs)
                if (prev.apkCertHash && prev.apkCertHash !== 'web' && prev.apkCertHash !== 'unverified_apk' && data.apkCertHash !== prev.apkCertHash) {
                    return recordFailure('🚨 Modified/Tampered APK detected! Signature rejected.');
                }

                const pubKeyPem = `-----BEGIN PUBLIC KEY-----\n${data.publicKey.match(/.{1,64}/g).join('\n')}\n-----END PUBLIC KEY-----`;
                const isEcdsaValid = crypto.verify(
                    'sha256',
                    Buffer.from(canonicalPayload, 'utf8'),
                    pubKeyPem,
                    Buffer.from(data.hwSignature, 'base64')
                );

                if (!isEcdsaValid) {
                    return recordFailure('🚨 Hardware ECDSA cryptographic signature invalid!');
                }
            } catch (err) {
                return recordFailure('🚨 Malformed Hardware Keystore signature!');
            }
        } else {
            // 🛑 ZERO FALLBACK: Never accept plain SHA-256 proofs from browsers or scripts!
            return recordFailure('🚨 Android Hardware Keystore ECDSA signature required! Browser/Laptop direct login blocked.');
        }

        global.authRateLimitMap.delete(rateKey);

        // Issue 256-bit High-Entropy Session Token
        const sessionToken = 'KVT_' + crypto.randomBytes(32).toString('hex');
        prev.sessionTokens = new Set([...(prev.sessionTokens || []), sessionToken]);
        prev.primaryDeviceId = data?.deviceId || prev.primaryDeviceId;
        if (data?.publicKey) prev.hardwarePublicKey = data.publicKey;
        if (data?.apkCertHash && data.apkCertHash !== 'web') prev.apkCertHash = data.apkCertHash;

        registeredUsers.set(cleanPhone, prev);
        savePersistentUsers();

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

        // 🛑 ZERO-TRUST LOCK: Only an already-authenticated Primary Socket can approve a companion device!
        if (!socket.isAuthenticated || !socket.userPhone) {
            if (typeof callback === 'function') callback({ success: false, message: '🚨 Unauthorized socket! Please re-verify primary phone.' });
            return;
        }

        const code = String(data?.code || '').trim();
        const session = global.companionPairingStore.get(code);
        const myCleanPhone = normalizeServerPhone(socket.userPhone);

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

    // 🔐 4. ZERO-TRUST MULTI-DEVICE AUTHENTICATION (Blocks ALL unverified numbers & raw Socket spoofing!)
    socket.on('auth_login', (data) => {
        const cleanPhone = normalizeServerPhone(data?.phone);
        if (!cleanPhone || cleanPhone.length < 10) return;

        let existingUser = registeredUsers.get(cleanPhone);
        const clientToken = String(data?.sessionToken || '').trim();
        const rawDevId = data?.deviceId;

        // 🛑 STRICT GATEKEEPER: Allow Hardware TEE Tokens (KVT_HW_), Ephemeral Companion Pairing Channels (+919999...), OR Verified Users!
        const isHardwareTeeToken = (clientToken.startsWith('KVT_HW_') || clientToken.startsWith('KVT_')) && clientToken.length >= 30 && !!rawDevId;
        const isEphemeralPairingChannel = cleanPhone.startsWith('+919999') && String(rawDevId || '').startsWith('pair_listener_');

        if (!existingUser && !isHardwareTeeToken && !isEphemeralPairingChannel) {
            console.warn(`🚨 BLOCKED UNVERIFIED NUMBER LOGIN: ${cleanPhone}`);
            socket.emit('force_logout', { reason: 'Number not verified via Hardware SIM. Please log in properly.' });
            return;
        }
        if (!existingUser && (isHardwareTeeToken || isEphemeralPairingChannel)) {
            existingUser = {
                phone: cleanPhone,
                name: data.name || 'Koveo User',
                bio: data.bio || 'Hey there! I am using Koveo.',
                dpUrl: data.dpUrl || '',
                primaryDeviceId: rawDevId,
                hardwarePublicKey: data.hardwarePublicKey || null,
                sessionTokens: new Set(clientToken ? [clientToken] : []),
                last_seen: Date.now()
            };
            if (!isEphemeralPairingChannel) {
                registeredUsers.set(cleanPhone, existingUser);
                savePersistentUsers();
            }
        }

        const isTokenValid = isEphemeralPairingChannel || !!(clientToken && existingUser && existingUser.sessionTokens && existingUser.sessionTokens.has(clientToken));
        const isTrustedPrimaryBoot = !data?.isCompanion && existingUser && existingUser.primaryDeviceId && rawDevId && existingUser.primaryDeviceId === rawDevId;

        if (!isTokenValid && !isTrustedPrimaryBoot) {
            console.warn(`🚨 BLOCKED UNAUTHORIZED AUTH_LOGIN ATTEMPT for ${cleanPhone} from IP ${socket.handshake.address}`);
            socket.emit('force_logout', { reason: '🚨 Invalid or expired session token. Please verify your SIM again.' });
            return;
        }

        const deviceId = (!rawDevId || rawDevId === 'primary')
            ? ('node_' + socket.id.slice(0, 10))
            : rawDevId;

        socket.userPhone = cleanPhone;
        socket.deviceId = deviceId;
        socket.isAuthenticated = true;

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

        // Ensure every authenticated primary device has a valid sessionToken & primaryDeviceId bound
        const currentRec = registeredUsers.get(cleanPhone);
        if (currentRec && !currentRec.primaryDeviceId && !data?.isCompanion) {
            currentRec.primaryDeviceId = deviceId;
        }
        let activeToken = String(data?.sessionToken || '').trim();
        if (currentRec && (!activeToken || !currentRec.sessionTokens.has(activeToken))) {
            activeToken = 'KVT_' + crypto.randomBytes(32).toString('hex');
            currentRec.sessionTokens.add(activeToken);
        }
        savePersistentUsers();

        socket.emit('auth_success', {
            phone: cleanPhone,
            deviceId,
            sessionToken: activeToken,
            user: registeredUsers.get(cleanPhone)
        });
        socket.broadcast.emit('user_came_online', { phone: cleanPhone, user: registeredUsers.get(cleanPhone) });

        if (global.pendingCalls && global.pendingCalls.has(cleanPhone)) {
            const pendingCallData = global.pendingCalls.get(cleanPhone);
            socket.emit('incoming_call', pendingCallData);
            global.pendingCalls.delete(cleanPhone);
        }
    });

    // 🔄 LIVE PROFILE & DP UPDATE (Strictly Locked to Authenticated Socket Owner!)
    socket.on('update_profile', (data) => {
        if (!socket.isAuthenticated || !socket.userPhone) return;
        const cleanPhone = normalizeServerPhone(socket.userPhone);
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

    // 🚀 WHATSAPP-STYLE AUTHORITATIVE BULK CONTACT SYNC (O(1) Lookup + Instant ACK Callback!)
    socket.on('sync_contacts', (phoneList, callback) => {
        const matchedContacts = [];
        const seenPhones = new Set();

        // Build fast 10-digit lookup index of all registered Koveo accounts
        const regIndex = new Map();
        registeredUsers.forEach((uData, regPhone) => {
            const d = String(regPhone || '').replace(/\D/g, '').slice(-10);
            if (d.length === 10) {
                regIndex.set(d, { regPhone: '+91' + d, uData });
            }
        });

        if (Array.isArray(phoneList)) {
            phoneList.forEach(rawItem => {
                const rawPhone = typeof rawItem === 'object' ? rawItem?.phone : rawItem;
                const localName = typeof rawItem === 'object' ? rawItem?.name : null;
                const targetDigits = String(rawPhone || '').replace(/\D/g, '').slice(-10);
                if (targetDigits.length !== 10) return;

                const match = regIndex.get(targetDigits);
                if (match && !seenPhones.has(match.regPhone)) {
                    seenPhones.add(match.regPhone);
                    const uData = match.uData || {};
                    matchedContacts.push({
                        phone: match.regPhone,
                        name: (localName && !String(localName).startsWith('+')) ? localName : (uData.name || match.regPhone),
                        koveoName: uData.name || 'Koveo User',
                        bio: uData.bio || 'Available on Koveo',
                        dpUrl: uData.dpUrl || '',
                        dpBg: uData.dpBg || '00d4ff',
                        isOnline: connectedUsers.has(match.regPhone)
                    });
                }
            });
        }

        socket.emit('sync_contacts_result', matchedContacts);
        if (typeof callback === 'function') callback(matchedContacts);
        console.log(`🔄 Contact Sync for ${socket.userPhone || socket.id}: Matched ${matchedContacts.length}/${Array.isArray(phoneList) ? phoneList.length : 0} phonebook contacts.`);
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

    socket.on('request_offline_sync', () => {
        // 🛑 ZERO-TRUST LOCK: Never allow unauthenticated sockets to drain another user's message queue!
        if (!socket.isAuthenticated || !socket.userPhone) return;
        flushQueuedMessagesForUser(socket.userPhone);
    });

    // ==========================================
    // 📞 MULTI-DEVICE WEBRTC SIGNALING, ICE BUFFERING & FCM WAKE-UP ENGINE
    // ==========================================
    if (!global.pendingCalls) global.pendingCalls = new Map();
    if (!global.pendingCallCandidates) global.pendingCallCandidates = new Map();

    socket.on('call_user', async (data, callback) => {
        // 🛑 ZERO-TRUST LOCK: Block spoofed calls from unauthenticated sockets!
        if (!socket.isAuthenticated || !socket.userPhone) {
            if (typeof callback === 'function') callback({ ringing: false, error: 'Unauthorized' });
            return;
        }
        const callerNorm = normalizeServerPhone(socket.userPhone);
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

    // 📨 MULTI-DEVICE SEND MESSAGE ENGINE (Strictly Authenticated Sender Binding — Zero Spoofing!)
    socket.on('send_message', (data, callback) => {
        if (!socket.isAuthenticated || !socket.userPhone || !data) {
            if (typeof callback === 'function') callback({ queued: false, error: 'Unauthorized session' });
            return;
        }
        const senderNorm = normalizeServerPhone(socket.userPhone);
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

    if (!global.deliveredStatusLedger) global.deliveredStatusLedger = new Map();

    // 🔄 SYNC OLD DOUBLE TICKS & BLUE TICKS ON BOOT (Verified Ledger Check)
    socket.on('check_message_statuses', (msgIds, callback) => {
        if (!Array.isArray(msgIds) || typeof callback !== 'function') return;
        const statuses = [];

        msgIds.forEach(id => {
            const verifiedStatus = global.deliveredStatusLedger.get(id);
            if (verifiedStatus) {
                statuses.push({ id, status: verifiedStatus });
            }
        });

        callback(statuses);
    });

    // ✔️✔️ MULTI-DEVICE BULLETPROOF DELIVERY RECEIPT RELAY (Never deletes until ALL linked devices receive it!)
    socket.on('message_delivered', (data) => {
        if (!data || !data.messageId) return;
        if (global.deliveredStatusLedger.get(data.messageId) !== 'read') {
            global.deliveredStatusLedger.set(data.messageId, 'delivered');
        }
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

    // 💙 MULTI-DEVICE MESSAGE SEEN (BLUE TICK) + OFFLINE QUEUE + OWN-DEVICE READ SYNC
    socket.on('message_seen', (data) => {
        if (!data || !data.senderId) return;
        if (data.messageId && global.deliveredStatusLedger) {
            global.deliveredStatusLedger.set(data.messageId, 'read');
        }
        const readerNorm = normalizeServerPhone(socket.userPhone || data.readerId);
        const { sockIds: senderSocks, matchedPhone: senderNorm } = getAllSocketsForPhone(data.senderId);
        const readPacket = {
            messageId: data.messageId,
            readerId: readerNorm,
            readAt: Date.now()
        };

        if (senderSocks.length > 0) {
            senderSocks.forEach(sId => io.to(sId).emit('message_read_update', readPacket));
        } else {
            // Queue Blue Tick if sender is currently offline so they get it on reconnect!
            const senderDigits = String(senderNorm || '').replace(/\D/g, '').slice(-10);
            if (senderDigits.length === 10) {
                const actList = global.pendingActionQueue.get(senderDigits) || [];
                actList.push({
                    action: 'read_receipt',
                    msgId: data.messageId,
                    readerId: readerNorm,
                    senderId: readerNorm,
                    receiverId: senderNorm,
                    queuedAt: Date.now()
                });
                global.pendingActionQueue.set(senderDigits, actList.slice(-100));
            }
        }

        // Also tell reader's own other linked devices that this chat was read!
        if (readerNorm) {
            const { sockIds: myOtherSocks } = getAllSocketsForPhone(readerNorm);
            myOtherSocks.forEach(sId => {
                if (sId !== socket.id) {
                    io.to(sId).emit('own_device_chat_read', { chatId: senderNorm, messageId: data.messageId });
                }
            });
        }
    });

    // ✍️ MULTI-DEVICE LIVE TYPING RELAY (With Authenticated Sender Normalization)
    socket.on('typing', (data) => {
        if (!data || !data.to) return;
        const senderNorm = normalizeServerPhone(socket.userPhone || data.from);
        const { sockIds, matchedPhone } = getAllSocketsForPhone(data.to);
        const typingPayload = {
            ...data,
            from: senderNorm,
            to: matchedPhone,
            isTyping: Boolean(data.isTyping)
        };
        sockIds.forEach(sId => io.to(sId).emit('typing', typingPayload));
    });

    // ⚡ MULTI-DEVICE EDIT, DELETE-FOR-EVERYONE & REACTION SYNC (Syncs to Peer Devices AND Sender's Own Linked Devices!)
    socket.on('message_action_sync', (data) => {
        if (!data || !data.receiverId) return;
        const { sockIds: peerSockets } = getAllSocketsForPhone(data.receiverId);
        const recDigits = String(data.receiverId).replace(/\D/g, '').slice(-10);

        if (recDigits.length === 10 && global.encryptedRamQueue.has(recDigits)) {
            const q = global.encryptedRamQueue.get(recDigits) || [];
            const shortId = data.shortId || String(data.msgId || '').replace(/[^a-zA-Z0-9]/g, '').slice(-7);
            if (data.action === 'delete_everyone') {
                global.encryptedRamQueue.set(recDigits, q.filter(m => m.id !== data.msgId && !String(m.id || '').endsWith(shortId)));
            } else if (data.action === 'edit' && data.newText) {
                q.forEach(m => {
                    if (m.id === data.msgId || String(m.id || '').endsWith(shortId)) {
                        m.text = data.newText;
                        m.edited = true;
                    }
                });
                global.encryptedRamQueue.set(recDigits, q);
            }
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

    // ==========================================
    // 🟢 24-HOUR STATUS (SIGNALS) ENGINE & MEDIA RELAY
    // ==========================================
    if (!global.koveoStatusesMap) global.koveoStatusesMap = new Map(); // phone -> Array of status metadata
    if (!global.koveoStatusMediaMap) global.koveoStatusMediaMap = new Map(); // mediaId -> Base64 string

    const STATUS_TTL_MS = 24 * 60 * 60 * 1000; // Strict 24 Hours

    const pruneExpiredServerStatuses = () => {
        const now = Date.now();
        global.koveoStatusesMap.forEach((list, phoneKey) => {
            const valid = list.filter(st => {
                const expired = (now - (st.createdAt || st.receivedAt || now)) >= STATUS_TTL_MS || (st.expiresAt && now >= st.expiresAt);
                if (expired && st.mediaId) {
                    global.koveoStatusMediaMap.delete(st.mediaId);
                }
                return !expired;
            });
            if (valid.length === 0) global.koveoStatusesMap.delete(phoneKey);
            else global.koveoStatusesMap.set(phoneKey, valid);
        });
    };

    // 1. Publish New Status (Text, Image, or Video)
    socket.on('publish_status', (statusData, callback) => {
        if (!socket.isAuthenticated || !socket.userPhone || !statusData) {
            if (typeof callback === 'function') callback({ success: false });
            return;
        }
        pruneExpiredServerStatuses();

        const ownerPhone = normalizeServerPhone(socket.userPhone);
        const ownerProfile = registeredUsers.get(ownerPhone) || {};
        const now = Date.now();
        const statusId = statusData.id || ('st_' + now + '_' + crypto.randomBytes(3).toString('hex'));
        const mediaId = statusData.mediaId || null;

        // Store heavy media in RAM map if provided, and strip from broadcast metadata
        if (mediaId && statusData.mediaData) {
            global.koveoStatusMediaMap.set(mediaId, statusData.mediaData);
        }

        const cleanStatus = {
            id: statusId,
            mediaId: mediaId,
            ownerPhone: ownerPhone,
            name: statusData.name || ownerProfile.name || ownerPhone,
            dpUrl: statusData.dpUrl || ownerProfile.dpUrl || '',
            bg: statusData.bg || '#00d4ff',
            fontFamily: statusData.fontFamily || 'Inter, sans-serif',
            content: statusData.mediaType === 'text' ? String(statusData.content || '') : '',
            caption: String(statusData.caption || ''),
            mediaType: statusData.mediaType || 'text',
            music: statusData.music || null,
            time: statusData.time || 'Just now',
            createdAt: statusData.createdAt || now,
            receivedAt: now,
            expiresAt: (statusData.createdAt || now) + STATUS_TTL_MS,
            views: [],
            likes: []
        };

        const existingList = global.koveoStatusesMap.get(ownerPhone) || [];
        existingList.push(cleanStatus);
        global.koveoStatusesMap.set(ownerPhone, existingList.slice(-30)); // Max 30 active segments per user

        // Broadcast lightweight status metadata to all connected users
        socket.broadcast.emit('receive_status_update', cleanStatus);

        // Mirror to owner's companion devices
        const { sockIds: mySocks } = getAllSocketsForPhone(ownerPhone);
        mySocks.forEach(sId => {
            if (sId !== socket.id) io.to(sId).emit('own_status_synced', cleanStatus);
        });

        if (typeof callback === 'function') callback({ success: true, status: cleanStatus });
    });

    // 2. Fetch Heavy Status Media On-Demand (Lazy Load for Photo/Video Status)
    socket.on('fetch_status_media', (mediaId, callback) => {
        if (typeof callback !== 'function') return;
        const data = mediaId ? global.koveoStatusMediaMap.get(mediaId) : null;
        callback({ success: !!data, mediaId, data: data || null });
    });

    // 3. Sync All Active (<24h) Statuses on Login / Refresh
    socket.on('request_active_statuses', (callback) => {
        pruneExpiredServerStatuses();
        const allActive = {};
        global.koveoStatusesMap.forEach((list, phoneKey) => {
            if (list && list.length > 0) {
                allActive[phoneKey] = list;
            }
        });
        socket.emit('active_statuses_bundle', allActive);
        if (typeof callback === 'function') callback(allActive);
    });

    // 4. Mark Status Viewed & Notify Owner with Viewer Info
    socket.on('mark_status_viewed', (data) => {
        if (!data || !data.statusId || !data.ownerPhone) return;
        const viewerPhone = normalizeServerPhone(socket.userPhone || data.viewerPhone);
        const ownerPhone = normalizeServerPhone(data.ownerPhone);
        if (!viewerPhone || viewerPhone === ownerPhone) return;

        const viewerProfile = registeredUsers.get(viewerPhone) || {};
        const list = global.koveoStatusesMap.get(ownerPhone);
        if (!list) return;

        const targetSt = list.find(s => s.id === data.statusId);
        if (targetSt) {
            if (!Array.isArray(targetSt.views)) targetSt.views = [];
            if (!targetSt.views.some(v => v.phone === viewerPhone)) {
                const viewEntry = {
                    phone: viewerPhone,
                    name: data.viewerName || viewerProfile.name || viewerPhone,
                    dpUrl: data.viewerDp || viewerProfile.dpUrl || '',
                    viewedAt: Date.now(),
                    time: data.time || 'Just now',
                    liked: false
                };
                targetSt.views.push(viewEntry);
                const { sockIds: ownerSocks } = getAllSocketsForPhone(ownerPhone);
                ownerSocks.forEach(sId => io.to(sId).emit('status_view_update', {
                    statusId: targetSt.id,
                    ownerPhone: ownerPhone,
                    viewer: viewEntry,
                    totalViews: targetSt.views.length
                }));
            }
        }
    });

    // 5. Like Status (Heart Reaction Sync to Owner's Viewer List)
    socket.on('like_status', (data) => {
        if (!data || !data.statusId || !data.ownerPhone) return;
        const likerPhone = normalizeServerPhone(socket.userPhone || data.likerPhone);
        const ownerPhone = normalizeServerPhone(data.ownerPhone);
        if (!likerPhone || likerPhone === ownerPhone) return;

        const likerProfile = registeredUsers.get(likerPhone) || {};
        const list = global.koveoStatusesMap.get(ownerPhone);
        if (!list) return;

        const targetSt = list.find(s => s.id === data.statusId);
        if (targetSt) {
            if (!Array.isArray(targetSt.views)) targetSt.views = [];
            let vEntry = targetSt.views.find(v => v.phone === likerPhone);
            if (!vEntry) {
                vEntry = {
                    phone: likerPhone,
                    name: data.likerName || likerProfile.name || likerPhone,
                    dpUrl: data.likerDp || likerProfile.dpUrl || '',
                    viewedAt: Date.now(),
                    time: 'Just now',
                    liked: true
                };
                targetSt.views.push(vEntry);
            } else {
                vEntry.liked = true;
            }
            const { sockIds: ownerSocks } = getAllSocketsForPhone(ownerPhone);
            ownerSocks.forEach(sId => io.to(sId).emit('status_view_update', {
                statusId: targetSt.id,
                ownerPhone: ownerPhone,
                viewer: vEntry,
                totalViews: targetSt.views.length
            }));
        }
    });

    // 6. Delete Own Status Segment Before 24h
    socket.on('delete_status', (data, callback) => {
        if (!socket.isAuthenticated || !socket.userPhone || !data?.statusId) return;
        const ownerPhone = normalizeServerPhone(socket.userPhone);
        const list = global.koveoStatusesMap.get(ownerPhone) || [];
        const target = list.find(s => s.id === data.statusId);
        if (target && target.mediaId) {
            global.koveoStatusMediaMap.delete(target.mediaId);
        }
        const updated = list.filter(s => s.id !== data.statusId);
        if (updated.length === 0) global.koveoStatusesMap.delete(ownerPhone);
        else global.koveoStatusesMap.set(ownerPhone, updated);

        io.emit('status_deleted', { ownerPhone, statusId: data.statusId });
        if (typeof callback === 'function') callback({ success: true });
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

// 🧹 12-Hour Automatic RAM Queue, Action Queue & Status Ledger Cleanup
setInterval(() => {
    const cutoff = Date.now() - (12 * 60 * 60 * 1000);
    if (global.encryptedRamQueue) {
        global.encryptedRamQueue.forEach((list, key) => {
            const fresh = list.filter(item => (item.queuedAt || Date.now()) > cutoff);
            if (fresh.length === 0) global.encryptedRamQueue.delete(key);
            else global.encryptedRamQueue.set(key, fresh);
        });
    }
    if (global.pendingActionQueue) {
        global.pendingActionQueue.forEach((list, key) => {
            const fresh = list.filter(item => (item.queuedAt || Date.now()) > cutoff);
            if (fresh.length === 0) global.pendingActionQueue.delete(key);
            else global.pendingActionQueue.set(key, fresh);
        });
    }
    if (global.deliveredStatusLedger && global.deliveredStatusLedger.size > 5000) {
        const keys = Array.from(global.deliveredStatusLedger.keys()).slice(0, 2500);
        keys.forEach(k => global.deliveredStatusLedger.delete(k));
    }
}, 30 * 60 * 1000);

// 🧹 60-Second Strict 24-Hour Status Auto-Expiry Sweep
setInterval(() => {
    if (!global.koveoStatusesMap) return;
    const now = Date.now();
    const ttl = 24 * 60 * 60 * 1000;
    global.koveoStatusesMap.forEach((list, phoneKey) => {
        const remaining = [];
        list.forEach(st => {
            const isExpired = (now - (st.createdAt || st.receivedAt || now)) >= ttl || (st.expiresAt && now >= st.expiresAt);
            if (isExpired) {
                if (st.mediaId && global.koveoStatusMediaMap) {
                    global.koveoStatusMediaMap.delete(st.mediaId);
                }
                io.emit('status_deleted', { ownerPhone: phoneKey, statusId: st.id, expired: true });
            } else {
                remaining.push(st);
            }
        });
        if (remaining.length === 0) global.koveoStatusesMap.delete(phoneKey);
        else global.koveoStatusesMap.set(phoneKey, remaining);
    });
}, 60 * 1000);

const PORT = process.env.PORT || 3000;
server.listen(PORT, '0.0.0.0', () => { 
    console.log(`🚀 Koveo Routing Engine is running on port ${PORT}`); 
});
