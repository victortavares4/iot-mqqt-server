#!/usr/bin/env python3
"""
Simulador de Dispositivos IoT Corrigido - Trabalho 3 Segurança IoT
UNISC - Prof. Charles Neu

Este arquivo foi corrigido para usar conexões persistentes e chaves compartilhadas.
"""

import socket
import time
import json
import random
import threading
import hashlib
import os
import base64
from datetime import datetime
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend

# --- Shared Configuration ---
# AVISO: Em uma aplicação real, não codifique chaves diretamente.
# Esta chave DEVE ser a mesma definida em app.py
SHARED_SECRET_PASSWORD = "unisc-iot-security-2025"
SALT = b'trabalho3-salt'

def get_shared_key():
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=SALT,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(SHARED_SECRET_PASSWORD.encode())

SHARED_SYMMETRIC_KEY = get_shared_key()
# --- End Shared Configuration ---

class IoTDevice:
    def __init__(self, device_id, device_type, server_host='127.0.0.1', server_port=65432):
        self.device_id = device_id
        self.device_type = device_type
        self.server_host = server_host
        self.server_port = server_port
        self.running = False
        self.socket = None
        self.max_attempts = 5
        
        # Chave de criptografia compartilhada
        self.symmetric_key = SHARED_SYMMETRIC_KEY
        print(f"[{self.device_id}] 🔐 Criptografia configurada com chave compartilhada.")
    
    def encrypt_aes(self, data):
        """Criptografia AES-256-GCM"""
        try:
            iv = os.urandom(12)
            cipher = Cipher(
                algorithms.AES(self.symmetric_key),
                modes.GCM(iv),
                backend=default_backend()
            )
            encryptor = cipher.encryptor()
            ciphertext = encryptor.update(data.encode()) + encryptor.finalize()
            print(f"[{self.device_id}] 🔐 Dados criptografados com sucesso")
            return base64.b64encode(iv + encryptor.tag + ciphertext).decode()        
        except Exception as e:
            print(f"[{self.device_id}] ❌ Erro na criptografia: {e}")
            return None
    
    def calculate_hash(self, data):
        """Calcula hash SHA-256"""
        return hashlib.sha256(data.encode()).hexdigest()
    
    def generate_sensor_data(self):
        """Gera dados do sensor baseado no tipo de dispositivo"""
        timestamp = datetime.now().isoformat()
        data_map = {
            'temperature': {'value': round(random.uniform(20.0, 30.0), 2), 'unit': 'celsius'},
            'humidity': {'value': round(random.uniform(40.0, 60.0), 2), 'unit': 'percent'},
            'pressure': {'value': round(random.uniform(1000.0, 1020.0), 2), 'unit': 'hPa'}
        }
        sensor_data = data_map.get(self.device_type, {'value': 0, 'unit': 'N/A'})
        
        return {
            'device_id': self.device_id,
            'type': self.device_type,
            'value': sensor_data['value'],
            'unit': sensor_data['unit'],
            'timestamp': timestamp,
            'battery': round(random.uniform(80.0, 100.0), 1)
        }
    
    def connect(self):
        """Estabelece uma conexão persistente com o servidor."""
        if self.socket:
            return True
        print(f"[{self.device_id}] 🔗 Tentando conectar a {self.server_host}:{self.server_port}...")
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.settimeout(10)
            self.socket.connect((self.server_host, self.server_port))
            print(f"[{self.device_id}] ✅ Conectado com sucesso!")
            return True
        except Exception as e:
            print(f"[{self.device_id}] 🔴 Falha ao conectar: {e}")
            self.socket = None
            return False

    def disconnect(self):
        """Fecha a conexão com o servidor."""
        if self.socket:
            self.socket.close()
            self.socket = None
            print(f"[{self.device_id}] 🔌 Desconectado.")

    def send_packet(self, data, use_encryption=False, use_hash=False):
        """Prepara e envia um único pacote de dados."""
        if not self.socket:
            print(f"[{self.device_id}] ❌ Não conectado. Tentando reconectar...")
            if not self.connect():
                return False

        try:
            json_data = json.dumps(data, ensure_ascii=False)
            packet = {
                'device_id': self.device_id,
                'timestamp': datetime.now().isoformat(),
                'original_data': json_data # Sempre inclui o original para verificação de hash
            }
            
            if use_encryption:
                encrypted_data = self.encrypt_aes(json_data)
                if encrypted_data:
                    packet['data'] = encrypted_data
                    packet['encrypted'] = True
                else:
                    packet['data'] = json_data
                    packet['encrypted'] = False
            else:
                packet['data'] = json_data
                packet['encrypted'] = False

            if use_hash:
                packet['hash'] = self.calculate_hash(json_data)
            
            # Envia o pacote como uma linha de JSON
            packet_json = json.dumps(packet, ensure_ascii=False)
            self.socket.sendall(packet_json.encode('utf-8'))
            
            print(f"[{self.device_id}] ✅ Dados enviados: {data.get('type', 'N/A')} = {data.get('value', 'N/A')}")
            return True
            
        except (socket.error, BrokenPipeError, ConnectionResetError) as e:
            print(f"[{self.device_id}] ❌ Erro de conexão ao enviar: {e}. Desconectando.")
            self.disconnect()
            return False
        except Exception as e:
            print(f"[{self.device_id}] ❌ Erro inesperado ao enviar dados: {e}")
            self.disconnect()
            return False

    def start_simulation(self, interval=5, use_encryption=False, use_hash=False, max_iterations=None):
        """Inicia simulação contínua com conexão persistente."""
        self.running = True
        iteration = 0
        
        print(f"[{self.device_id}] 🚀 Simulação iniciada (Intervalo: {interval}s, Cripto: {'Sim' if use_encryption else 'Não'})")
        
        if not self.connect():
            self.running = False
            print(f"[{self.device_id}] 🛑 Parando simulação, falha na conexão inicial.")
            return

        while self.running:
            if max_iterations and iteration >= max_iterations:
                print(f"[{self.device_id}] 🏁 Limite de iterações atingido.")
                break
            
            sensor_data = self.generate_sensor_data()
            if not self.send_packet(sensor_data, use_encryption, use_hash):
                # Se falhou, aguarda um pouco antes de tentar reconectar no próximo loop
                time.sleep(5)
            
            iteration += 1
            time.sleep(interval)
        
        self.disconnect()
        print(f"[{self.device_id}] 🏁 Simulação finalizada")

    def stop_simulation(self):
        """Para a simulação."""
        self.running = False

class DeviceManager:
    def __init__(self):
        self.devices = []
        self.threads = []
    
    def add_device(self, device_id, device_type):
        """Adiciona um dispositivo à simulação"""
        device = IoTDevice(device_id, device_type)
        self.devices.append(device)
        print(f"[MANAGER] ➕ Dispositivo {device_id} ({device_type}) adicionado")
        return device
    
    def test_server_connection(self):
        """Testa se o servidor está rodando antes de iniciar dispositivos"""
        print("[MANAGER] 🔍 Testando conexão com servidor...")
        
        try:
            test_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            test_socket.settimeout(5)
            test_socket.connect(('127.0.0.1', 65432))
            test_socket.close()
            print("[MANAGER] ✅ Servidor está rodando!")
            return True
        except:
            print("[MANAGER] ❌ ERRO: Servidor não está rodando!")
            print("[MANAGER] 💡 SOLUÇÃO: Execute 'python app.py' primeiro")
            print("[MANAGER] 📋 Passos:")
            print("[MANAGER]   1. Abra outro terminal")
            print("[MANAGER]   2. Execute: python app.py")
            print("[MANAGER]   3. Aguarde 'Servidor IoT iniciado'")
            print("[MANAGER]   4. Execute este simulador novamente")
            return False
    
    def start_all_devices(self, interval=2, use_encryption=False, use_hash=False, max_iterations=None):
        """Inicia todos os dispositivos"""
        if not self.test_server_connection():
            print("[MANAGER] 🛑 Não é possível iniciar dispositivos sem servidor")
            return
        
        print(f"[MANAGER] 🚀 Iniciando {len(self.devices)} dispositivos...")
        
        for device in self.devices:
            thread = threading.Thread(
                target=device.start_simulation,
                args=(interval, use_encryption, use_hash, max_iterations),
                daemon=True
            )
            thread.start()
            self.threads.append(thread)
            time.sleep(0.5)  # Pequeno delay entre dispositivos
        
        print(f"[MANAGER] ✅ Todos os dispositivos iniciados")
    
    def stop_all_devices(self):
        """Para todos os dispositivos"""
        print("[MANAGER] 🛑 Parando todos os dispositivos...")
        for device in self.devices:
            device.stop_simulation()
        print("[MANAGER] ✅ Todos os dispositivos parados")

def main():
    """Função principal para demonstração"""
    print("=" * 70)
    print("🤖 SIMULADOR DE DISPOSITIVOS IoT")
    print("UNISC - Trabalho 3 - Prof. Charles Neu")
    print("=" * 70)
    print("")
    print("⚠️  IMPORTANTE: Execute 'python app.py' ANTES deste simulador!")
    print("")
    
    print("Escolha o modo de operação:")
    print("1. Dispositivo único (temperatura)")
    print("2. Múltiplos dispositivos (básico)")
    print("3. Múltiplos dispositivos (com segurança)")
    print("4. Teste rápido (5 envios por dispositivo)")
    print("5. Demonstração completa")
    
    try:
        choice = input("\nOpção (1-5): ").strip()
    except KeyboardInterrupt:
        print("\n👋 Programa interrompido")
        return
    
    if choice == '1':
        # Dispositivo único
        device = IoTDevice('TEMP_001', 'temperature')
        print("\n🌡️  Iniciando dispositivo de temperatura...")
        device.start_simulation(interval=3)
    
    elif choice == '2':
        # Múltiplos dispositivos básicos
        manager = DeviceManager()
        
        # Adiciona dispositivos
        manager.add_device('TEMP_001', 'temperature')
        manager.add_device('HUM_001', 'humidity')
        manager.add_device('PRES_001', 'pressure')
        
        print("\n🔗 Iniciando múltiplos dispositivos...")
        manager.start_all_devices(interval=4)
        
        try:
            print("\n✅ Dispositivos rodando! Pressione Ctrl+C para parar.")
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print("\n🛑 Parando simulação...")
            manager.stop_all_devices()
    
    elif choice == '3':
        # Múltiplos dispositivos com segurança
        manager = DeviceManager()
        
        manager.add_device('TEMP_SEC_001', 'temperature')
        manager.add_device('HUM_SEC_001', 'humidity')
        manager.add_device('PRES_SEC_001', 'pressure')
        
        print("\n🔒 Iniciando dispositivos com segurança completa...")
        manager.start_all_devices(interval=5, use_encryption=True, use_hash=True)
        
        try:
            print("\n✅ Dispositivos seguros rodando! Pressione Ctrl+C para parar.")
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print("\n🛑 Parando simulação...")
            manager.stop_all_devices()
    
    elif choice == '4':
        # Teste rápido
        manager = DeviceManager()
        
        manager.add_device('TEMP_TEST', 'temperature')
        manager.add_device('HUM_TEST', 'humidity')
        
        print("\n⚡ Teste rápido (5 envios por dispositivo)...")
        manager.start_all_devices(interval=2, use_encryption=True, use_hash=True, max_iterations=5)
        
        # Aguarda threads terminarem
        print("\n⏳ Aguardando conclusão dos testes...")
        for thread in manager.threads:
            thread.join()
        
        print("\n✅ Teste rápido concluído!")
    
    elif choice == '5':
        # Demonstração completa
        print("\n🎭 DEMONSTRAÇÃO COMPLETA")
        print("Esta demonstração mostra todos os recursos de segurança")
        
        device = IoTDevice('DEMO_001', 'temperature')
        
        # Teste 1: Dados sem proteção
        print("\n1️⃣ Enviando dados sem proteção:")
        data = device.generate_sensor_data()
        device.send_data(data)
        time.sleep(2)
        
        # Teste 2: Dados com hash
        print("\n2️⃣ Enviando dados com hash:")
        data = device.generate_sensor_data()
        device.send_data(data, use_hash=True)
        time.sleep(2)
        
        # Teste 3: Dados criptografados
        print("\n3️⃣ Enviando dados criptografados:")
        data = device.generate_sensor_data()
        device.send_data(data, use_encryption=True)
        time.sleep(2)
        
        # Teste 4: Dados criptografados com hash
        print("\n4️⃣ Enviando dados com criptografia + hash:")
        data = device.generate_sensor_data()
        device.send_data(data, use_encryption=True, use_hash=True)
        
        print("\n🎉 Demonstração completa finalizada!")
    
    else:
        print("❌ Opção inválida!")

if __name__ == '__main__':
    main()