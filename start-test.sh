#!/bin/bash

# Script de automação para iniciar servidor e clientes em terminais separados
# Sistema de Mensagens Seguras - JavaScript Nativo

# Verificar se flag --debug foi passada
DEBUG_FLAG=""
if [ "$1" = "--debug" ]; then
    DEBUG_FLAG="--debug"
    echo "🔍 Modo DEBUG ativado - logs detalhados de criptografia"
fi

echo "🔐 Sistema de Mensagens Seguras - Iniciando Teste Completo"
echo "=========================================================="
echo "   Iniciando: Servidor + 3 Clientes (Alice, Bob, Charlie)"
if [ -n "$DEBUG_FLAG" ]; then
    echo "   Modo: DEBUG (mostrando Ed25519, TOFU, HKDF, Envelope)"
fi
echo ""

# Verificar se o arquivo de configuração existe
if [ ! -f "config.env" ]; then
    echo "❌ Arquivo config.env não encontrado!"
    echo "💡 Crie o arquivo config.env baseado no exemplo fornecido"
    exit 1
fi

# Carregar variáveis de ambiente
export $(cat config.env | grep -v '^#' | xargs)

# Verificar se as dependências estão instaladas
if [ ! -d "server/node_modules" ] || [ ! -d "client/node_modules" ]; then
    echo "📦 Instalando dependências..."
    cd server && npm install > /dev/null 2>&1
    cd ../client && npm install > /dev/null 2>&1
    cd ..
    echo "✅ Dependências instaladas"
    echo ""
fi

# Verificar se o servidor já está rodando
if lsof -i :${NODE_PORT:-6666} > /dev/null 2>&1; then
    echo "⚠️  Servidor já está rodando na porta ${NODE_PORT:-6666}"
    echo "💡 Parando servidor existente..."
    pkill -f "node.*server.js" 2>/dev/null
    sleep 2
fi

# Função para limpar processos ao sair
cleanup() {
    echo ""
    echo "🛑 Parando todos os processos..."
    pkill -f "node.*server.js" 2>/dev/null
    pkill -f "node.*main.js.*--username" 2>/dev/null
    echo "✅ Todos os processos foram parados"
    exit 0
}

# Capturar Ctrl+C
trap cleanup SIGINT SIGTERM

# Detectar qual gerenciador de terminais está disponível
TERMINAL_CMD=""
if command -v gnome-terminal > /dev/null 2>&1; then
    TERMINAL_CMD="gnome-terminal"
elif command -v xterm > /dev/null 2>&1; then
    TERMINAL_CMD="xterm"
elif command -v tmux > /dev/null 2>&1; then
    TERMINAL_CMD="tmux"
elif command -v screen > /dev/null 2>&1; then
    TERMINAL_CMD="screen"
else
    echo "❌ Nenhum gerenciador de terminal encontrado!"
    echo "💡 Instale: gnome-terminal, xterm, tmux ou screen"
    exit 1
fi

echo "📋 Configurações:"
echo "   - Servidor: $NODE_URL (porta ${NODE_PORT:-6666})"
echo "   - Terminal: $TERMINAL_CMD"
echo ""

# Iniciar servidor
echo "🖥️  Iniciando servidor..."
if [ "$TERMINAL_CMD" = "gnome-terminal" ]; then
    gnome-terminal --title="Servidor - Porta ${NODE_PORT:-6666}" -- bash -c "cd $(pwd) && export $(cat config.env | grep -v '^#' | xargs) && cd server && node server.js; exec bash" 2>/dev/null &
    SERVER_PID=$!
elif [ "$TERMINAL_CMD" = "xterm" ]; then
    xterm -title "Servidor - Porta ${NODE_PORT:-6666}" -e "cd $(pwd) && export $(cat config.env | grep -v '^#' | xargs) && cd server && node server.js" 2>/dev/null &
    SERVER_PID=$!
elif [ "$TERMINAL_CMD" = "tmux" ]; then
    tmux new-session -d -s message-idea-server "cd $(pwd) && export $(cat config.env | grep -v '^#' | xargs) && cd server && node server.js"
    SERVER_PID=$!
    echo "   ℹ️  Servidor iniciado em sessão tmux: message-idea-server"
    echo "   💡 Para ver: tmux attach -t message-idea-server"
elif [ "$TERMINAL_CMD" = "screen" ]; then
    screen -dmS message-idea-server bash -c "cd $(pwd) && export $(cat config.env | grep -v '^#' | xargs) && cd server && node server.js"
    SERVER_PID=$!
    echo "   ℹ️  Servidor iniciado em sessão screen: message-idea-server"
    echo "   💡 Para ver: screen -r message-idea-server"
fi

echo "⏳ Aguardando servidor inicializar..."
sleep 3

# Verificar se o servidor está rodando
if ! lsof -i :${NODE_PORT:-6666} > /dev/null 2>&1; then
    echo "❌ Erro: Servidor não iniciou corretamente"
    exit 1
fi

echo "✅ Servidor iniciado com sucesso!"
echo ""

# Iniciar cliente Alice
echo "👤 Iniciando cliente Alice..."
if [ "$TERMINAL_CMD" = "gnome-terminal" ]; then
    gnome-terminal --title="Alice - Cliente" -- bash -c "cd $(pwd) && node client/cli/main.js --username Alice $DEBUG_FLAG; exec bash" 2>/dev/null &
elif [ "$TERMINAL_CMD" = "xterm" ]; then
    xterm -title "Alice - Cliente" -e "cd $(pwd) && node client/cli/main.js --username Alice $DEBUG_FLAG" 2>/dev/null &
elif [ "$TERMINAL_CMD" = "tmux" ]; then
    tmux new-session -d -s message-idea-alice "cd $(pwd) && node client/cli/main.js --username Alice $DEBUG_FLAG"
    echo "   ℹ️  Cliente Alice iniciado em sessão tmux: message-idea-alice"
    echo "   💡 Para ver: tmux attach -t message-idea-alice"
elif [ "$TERMINAL_CMD" = "screen" ]; then
    screen -dmS message-idea-alice bash -c "cd $(pwd) && node client/cli/main.js --username Alice $DEBUG_FLAG"
    echo "   ℹ️  Cliente Alice iniciado em sessão screen: message-idea-alice"
    echo "   💡 Para ver: screen -r message-idea-alice"
fi

sleep 1

# Iniciar cliente Bob
echo "👤 Iniciando cliente Bob..."
if [ "$TERMINAL_CMD" = "gnome-terminal" ]; then
    gnome-terminal --title="Bob - Cliente" -- bash -c "cd $(pwd) && node client/cli/main.js --username Bob $DEBUG_FLAG; exec bash" 2>/dev/null &
elif [ "$TERMINAL_CMD" = "xterm" ]; then
    xterm -title "Bob - Cliente" -e "cd $(pwd) && node client/cli/main.js --username Bob $DEBUG_FLAG" 2>/dev/null &
elif [ "$TERMINAL_CMD" = "tmux" ]; then
    tmux new-session -d -s message-idea-bob "cd $(pwd) && node client/cli/main.js --username Bob $DEBUG_FLAG"
    echo "   ℹ️  Cliente Bob iniciado em sessão tmux: message-idea-bob"
    echo "   💡 Para ver: tmux attach -t message-idea-bob"
elif [ "$TERMINAL_CMD" = "screen" ]; then
    screen -dmS message-idea-bob bash -c "cd $(pwd) && node client/cli/main.js --username Bob $DEBUG_FLAG"
    echo "   ℹ️  Cliente Bob iniciado em sessão screen: message-idea-bob"
    echo "   💡 Para ver: screen -r message-idea-bob"
fi

sleep 1

# Iniciar cliente Charlie
echo "👤 Iniciando cliente Charlie..."
if [ "$TERMINAL_CMD" = "gnome-terminal" ]; then
    gnome-terminal --title="Charlie - Cliente" -- bash -c "cd $(pwd) && node client/cli/main.js --username Charlie $DEBUG_FLAG; exec bash" 2>/dev/null &
elif [ "$TERMINAL_CMD" = "xterm" ]; then
    xterm -title "Charlie - Cliente" -e "cd $(pwd) && node client/cli/main.js --username Charlie $DEBUG_FLAG" 2>/dev/null &
elif [ "$TERMINAL_CMD" = "tmux" ]; then
    tmux new-session -d -s message-idea-charlie "cd $(pwd) && node client/cli/main.js --username Charlie $DEBUG_FLAG"
    echo "   ℹ️  Cliente Charlie iniciado em sessão tmux: message-idea-charlie"
    echo "   💡 Para ver: tmux attach -t message-idea-charlie"
elif [ "$TERMINAL_CMD" = "screen" ]; then
    screen -dmS message-idea-charlie bash -c "cd $(pwd) && node client/cli/main.js --username Charlie $DEBUG_FLAG"
    echo "   ℹ️  Cliente Charlie iniciado em sessão screen: message-idea-charlie"
    echo "   💡 Para ver: screen -r message-idea-charlie"
fi

echo ""
echo "✅ Todos os componentes iniciados!"
echo ""
echo "📋 Resumo:"
echo "   - Servidor: Porta ${NODE_PORT:-6666}"
if [ "$TERMINAL_CMD" = "gnome-terminal" ] || [ "$TERMINAL_CMD" = "xterm" ]; then
    echo "   - Cliente Alice: Janela de terminal separada"
    echo "   - Cliente Bob: Janela de terminal separada"
    echo "   - Cliente Charlie: Janela de terminal separada"
else
    echo "   - Cliente Alice: Sessão $TERMINAL_CMD (message-idea-alice)"
    echo "   - Cliente Bob: Sessão $TERMINAL_CMD (message-idea-bob)"
    echo "   - Cliente Charlie: Sessão $TERMINAL_CMD (message-idea-charlie)"
fi
echo ""
echo "🚀 Comandos úteis:"
echo "   - Listar usuários: /users"
echo "   - Iniciar chat: /chat Bob (no terminal da Alice)"
echo "   - Criar grupo: /group Equipe"
echo "   - Sair do grupo: /leave (testa recriação do secret share)"
echo "   - Ver chaves: /keys (mostra ECDH, Ed25519, TOFU pins)"
if [ -n "$DEBUG_FLAG" ]; then
    echo ""
    echo "🔍 Modo DEBUG ativo - você verá:"
    echo "   🔑 Ed25519: Carregamento de keypair, assinaturas"
    echo "   🔍 TOFU: Pinning inicial e verificações"
    echo "   🔄 ECDH: Geração de chaves e shared secrets"
    echo "   🔑 HKDF: Derivação de encKey e authKey"
    echo "   📦 Envelope: Construção com nonce e tag GCM"
    echo "   📨 Validação: Timestamp, nonce replay, GCM auth"
fi
echo ""
if [ "$TERMINAL_CMD" = "tmux" ] || [ "$TERMINAL_CMD" = "screen" ]; then
    echo "💡 Para ver os terminais:"
    echo "   - Servidor: $TERMINAL_CMD attach -t message-idea-server"
    echo "   - Alice: $TERMINAL_CMD attach -t message-idea-alice"
    echo "   - Bob: $TERMINAL_CMD attach -t message-idea-bob"
    echo "   - Charlie: $TERMINAL_CMD attach -t message-idea-charlie"
    echo ""
fi
echo "🛑 Para parar tudo: Ctrl+C ou execute: pkill -f 'node.*(server|main)'"
if [ -z "$DEBUG_FLAG" ]; then
    echo "💡 Para testar com logs detalhados: ./start-test.sh --debug"
fi
echo ""

# Aguardar indefinidamente (ou até Ctrl+C)
if [ "$TERMINAL_CMD" = "gnome-terminal" ] || [ "$TERMINAL_CMD" = "xterm" ]; then
    echo "💡 Os terminais foram abertos em janelas separadas."
    echo "   Este script pode ser fechado - os processos continuarão rodando."
    echo "   Para parar tudo, execute: pkill -f 'node.*(server|main)'"
    wait
else
    wait
fi

