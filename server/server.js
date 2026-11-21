#!/usr/bin/env node
/**
 * Relay server
 *
 * The server is only a relay: it stores PUBLIC keys (ECDH + Ed25519), routes
 * the key exchange and forwards already-encrypted envelopes. It never sees
 * private keys or plaintext (all cryptography happens on the client).
 */

const path = require('path');

// Load environment variables (path relative to this file, not to the cwd)
require('dotenv').config({ path: path.join(__dirname, '..', 'config.env'), quiet: true });

const express = require('express');
const http = require('http');
const socketIo = require('socket.io');
const cors = require('cors');

const WebSocketHandler = require('./src/websocket/WebSocketHandler');

class SecureMessageServer {
    constructor() {
        this.app = express();
        this.server = http.createServer(this.app);
        this.io = socketIo(this.server, {
            cors: {
                origin: '*',
                methods: ['GET', 'POST']
            }
        });

        this.port = process.env.NODE_PORT || 6666;

        this.setupMiddleware();
        this.setupRoutes();
        this.setupWebSocket();
    }

    setupMiddleware() {
        this.app.use(cors());
        this.app.use(express.json());
    }

    /**
     * REST routes (informational only)
     */
    setupRoutes() {
        this.app.get('/status', (req, res) => {
            res.json({
                status: 'online',
                service: 'e2e-encryption-study-server',
                version: '1.0.0',
                timestamp: new Date().toISOString(),
                features: ['E2E Encryption (AES-128-GCM)', 'ECDH Key Exchange', 'Ed25519 + TOFU', 'Group Chat', 'Real-time Messaging']
            });
        });

        this.app.get('/info', (req, res) => {
            res.json({
                system: 'E2E Encryption Study - terminal chat',
                architecture: 'Node.js (Express + Socket.IO)',
                algorithms: {
                    encryption: 'AES-128-GCM (AEAD), performed on the client',
                    keyExchange: 'ECDH (Elliptic Curve Diffie-Hellman)',
                    curve: 'secp256k1',
                    keyDerivation: 'HKDF-SHA256',
                    authentication: 'Ed25519 + TOFU'
                },
                features: [
                    'End-to-end encryption with AES-128-GCM',
                    'ECDH key exchange authenticated with Ed25519',
                    'Encrypted 1:1 chat',
                    'Group chat with a shared key and automatic re-keying',
                    'Full CLI',
                    'Detailed logs for study'
                ],
                endpoints: {
                    websocket: '/socket.io/',
                    status: '/status',
                    info: '/info'
                }
            });
        });

        this.app.get('/', (req, res) => {
            res.json({
                message: 'E2E Encryption Study - server running',
                documentation: '/info',
                websocket: 'ws://localhost:' + this.port,
                client: 'Use the CLI client to connect'
            });
        });
    }

    setupWebSocket() {
        this.wsHandler = new WebSocketHandler(this.io);
        console.log('WebSocket ready');
    }

    async start() {
        try {
            this.server.listen(this.port, () => {
                console.log('Server started!');
                console.log('Listening on: http://localhost:' + this.port);
                console.log('WebSocket at: ws://localhost:' + this.port);
                console.log('Endpoints:');
                console.log('   - GET  /status     - Server status');
                console.log('   - GET  /info       - System information');
                console.log('   - WS   /socket.io/ - WebSocket for clients');
                console.log('');
                console.log('To connect clients:');
                console.log('   node client/cli/main.js --username Alice');
                console.log('   node client/cli/main.js --username Bob');
                console.log('');
                console.log('Press Ctrl+C to stop');
            });

        } catch (error) {
            console.error('Error starting server:', error);
            process.exit(1);
        }
    }

    stop() {
        console.log('Stopping server...');
        this.server.close(() => {
            console.log('Server stopped.');
            process.exit(0);
        });
    }
}

const server = new SecureMessageServer();

process.on('SIGINT', () => {
    console.log('\nReceived SIGINT, stopping server...');
    server.stop();
});

process.on('SIGTERM', () => {
    console.log('\nReceived SIGTERM, stopping server...');
    server.stop();
});

server.start();
