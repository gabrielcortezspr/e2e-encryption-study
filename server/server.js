#!/usr/bin/env node
/**
 * Servidor Principal do Sistema de Mensagens Seguras
 *
 * O servidor é apenas um relay: guarda chaves PÚBLICAS (ECDH + Ed25519),
 * roteia a troca de chaves e encaminha envelopes já cifrados. Ele nunca vê
 * chaves privadas nem texto claro (toda a criptografia acontece no cliente).
 */

const path = require('path');

// Carregar variáveis de ambiente (caminho relativo a este arquivo, não ao cwd)
require('dotenv').config({ path: path.join(__dirname, '..', 'config.env') });

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
                origin: "*",
                methods: ["GET", "POST"]
            }
        });
        
        this.port = process.env.NODE_PORT || 6666;
        
        this.setupMiddleware();
        this.setupRoutes();
        this.setupWebSocket();
    }

    /**
     * Configura middleware
     */
    setupMiddleware() {
        this.app.use(cors());
        this.app.use(express.json());
    }

    /**
     * Configura rotas REST
     */
    setupRoutes() {
        // Rota de status
        this.app.get('/status', (req, res) => {
            res.json({
                status: 'online',
                service: 'Secure Message Server',
                version: '1.0.0',
                timestamp: new Date().toISOString(),
                features: ['E2E Encryption (AES-128-GCM)', 'ECDH Key Exchange', 'Ed25519 + TOFU', 'Group Chat', 'Real-time Messaging']
            });
        });

        // Rota de informações do sistema
        this.app.get('/info', (req, res) => {
            res.json({
                system: 'Sistema de Mensagens Seguras',
                architecture: 'JavaScript Nativo (Node.js)',
                algorithms: {
                    encryption: 'AES-128-GCM (AEAD), feita no cliente',
                    keyExchange: 'ECDH (Elliptic Curve Diffie-Hellman)',
                    curve: 'secp256k1',
                    keyDerivation: 'HKDF-SHA256',
                    authentication: 'Ed25519 + TOFU'
                },
                features: [
                    'Criptografia ponta a ponta com AES-128-GCM',
                    'Troca de chaves ECDH autenticada com Ed25519',
                    'Chat 1:1 criptografado',
                    'Chat em grupo com chave compartilhada',
                    'Interface CLI completa',
                    'Logs detalhados para análise'
                ],
                endpoints: {
                    websocket: '/socket.io/',
                    status: '/status',
                    info: '/info'
                }
            });
        });

        // Rota raiz
        this.app.get('/', (req, res) => {
            res.json({
                message: 'Sistema de Mensagens Seguras - Servidor Ativo',
                documentation: '/info',
                websocket: 'ws://localhost:' + this.port,
                client: 'Use o cliente CLI para conectar'
            });
        });
    }

    /**
     * Configura WebSocket
     */
    setupWebSocket() {
        this.wsHandler = new WebSocketHandler(this.io);
        console.log('WebSocket configurado');
    }

    /**
     * Inicia o servidor
     */
    async start() {
        try {
            // Iniciar servidor Node.js
            this.server.listen(this.port, () => {
                console.log('Servidor iniciado com sucesso!');
                console.log('Servidor rodando em: http://localhost:' + this.port);
                console.log('WebSocket disponivel em: ws://localhost:' + this.port);
                console.log('Endpoints disponiveis:');
                console.log('   - GET  /status    - Status do servidor');
                console.log('   - GET  /info      - Informacoes do sistema');
                console.log('   - WS   /socket.io/ - WebSocket para clientes');
                console.log('');
                console.log('Para conectar clientes:');
                console.log('   node client/cli/main.js --username Alice');
                console.log('   node client/cli/main.js --username Bob');
                console.log('');
                console.log('Para parar o servidor: Ctrl+C');
            });

        } catch (error) {
            console.error('Erro ao iniciar servidor:', error);
            process.exit(1);
        }
    }

    /**
     * Para o servidor
     */
    stop() {
        console.log('Parando servidor...');
        this.server.close(() => {
            console.log('Servidor parado com sucesso!');
            process.exit(0);
        });
    }
}

// Inicializar servidor
const server = new SecureMessageServer();

// Tratamento de sinais para parada limpa
process.on('SIGINT', () => {
    console.log('\nRecebido SIGINT, parando servidor...');
    server.stop();
});

process.on('SIGTERM', () => {
    console.log('\nRecebido SIGTERM, parando servidor...');
    server.stop();
});

// Iniciar servidor
server.start();

