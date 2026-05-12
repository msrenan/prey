#!/bin/bash
IFACE="tap0"
MY_IP="10.0.0.1"
MY_MAC="aa:bb:cc:dd:ee:ff"

echo "🧹 Limpando configurações anteriores..."
sudo ip link delete $IFACE 2>/dev/null

echo "🏗️ Criando interface $IFACE com MAC $MY_MAC..."
sudo ip tuntap add dev $IFACE mode tap
sudo ip link set dev $IFACE address $MY_MAC
sudo ip addr add $MY_IP/24 dev $IFACE
sudo ip link set dev $IFACE up

# Importante: Para que o seu PC consiga "falar" com o IP .2, .3 etc 
# sem precisar de outra máquina real, vamos adicionar vizinhos es#!/bin/bash

# --- CONFIGURAÇÃO ---
PHYSICAL_IF="wlp0s20f3" 
TAP_IF="tap0"

echo "🚀 Iniciando configuração via Mirroring (Modo Wi-Fi)..."

# 1. Limpeza total
sudo ip link delete $TAP_IF 2>/dev/null
sudo tc qdisc del dev $PHYSICAL_IF ingress 2>/dev/null

# 2. Criar a interface TAP
echo "Criando interface $TAP_IF..."
sudo ip tuntap add dev $TAP_IF mode tap
sudo ip link set dev $TAP_IF up

# 3. Colocar a placa física em modo promíscuo
sudo ip link set dev $PHYSICAL_IF promisc on

# 4. A MÁGICA: Mirroring usando Traffic Control (tc)
# Isso diz ao Kernel: "Tudo que entrar na wlp0s20f3, mande uma cópia para a tap0"
echo "Espelhando tráfego de $PHYSICAL_IF para $TAP_IF..."

# Adiciona um filtro de entrada (ingress) na placa Wi-Fi
sudo tc qdisc add dev $PHYSICAL_IF handle ffff: ingress

# Redireciona (espelha) os pacotes capturados no ingresso para a tap0
sudo tc filter add dev $PHYSICAL_IF parent ffff: \
    protocol all \
    u32 match u32 0 0 \
    action mirred egress mirror dev $TAP_IF

echo "✅ Setup concluído!"
echo "Sua internet continua na $PHYSICAL_IF, mas a $TAP_IF está recebendo os mesmos pacotes."táticos
echo "🛰️ Configurando vizinhos de teste..."
sudo arp -s 10.0.0.2 aa:bb:cc:dd:ee:11 -i $IFACE