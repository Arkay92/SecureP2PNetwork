import asyncio
import socket
from zeroconf import ServiceBrowser, Zeroconf, ServiceInfo
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.serialization import PublicFormat, Encoding, load_pem_public_key
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding
import os

# DH parameter generation (should be done offline and reused)
parameters = dh.generate_parameters(generator=2, key_size=512, backend=default_backend())

# Function to perform DH key exchange
async def perform_dh_key_exchange(reader, writer, private_key):
    peer_public_key_pem = await reader.read(4096)
    peer_public_key = load_pem_public_key(peer_public_key_pem, backend=default_backend())

    # Send our public key
    public_key = private_key.public_key()
    pem = public_key.public_bytes(encoding=Encoding.PEM, format=PublicFormat.SubjectPublicKeyInfo)
    writer.write(pem)
    await writer.drain()

    # Generate shared secret
    shared_key = private_key.exchange(peer_public_key)

    # Derive a key from the shared secret
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'handshake data',
        backend=default_backend()
    ).derive(shared_key)

    return derived_key

# Function to derive AES key from shared DH key
def derive_aes_key(shared_key):
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,  # AES key length in bytes (256 bits)
        salt=None,
        info=b'p2p communication',
        backend=default_backend()
    )
    return hkdf.derive(shared_key)

# Function to encrypt message using AES
def aes_encrypt(message, key):
    padder = sym_padding.PKCS7(128).padder()
    padded_data = padder.update(message.encode()) + padder.finalize()

    iv = os.urandom(16)  # Generate a random IV
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ct = encryptor.update(padded_data) + encryptor.finalize()

    return iv + ct  # Prepend IV to ciphertext for use in decryption

# Function to decrypt message using AES
def aes_decrypt(ciphertext, key):
    iv, ct = ciphertext[:16], ciphertext[16:]  # Extract IV and actual ciphertext

    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(ct) + decryptor.finalize()

    unpadder = sym_padding.PKCS7(128).unpadder()
    decrypted_data = unpadder.update(padded_data) + unpadder.finalize()

    return decrypted_data.decode()

# Zeroconf service registration for peer discovery
class MyListener:
    def remove_service(self, zeroconf, type, name):
        print(f"Service {name} removed")

    def add_service(self, zeroconf, type, name):
        info = zeroconf.get_service_info(type, name)
        print(f"Service {name} added, service info: {info}")

zeroconf = Zeroconf()
listener = MyListener()
browser = ServiceBrowser(zeroconf, "_http._tcp.local.", listener)

# Handle incoming connections with secure key exchange and communication
async def handle_connection(reader, writer):
    try:
        private_key = parameters.generate_private_key()
        shared_key = await perform_dh_key_exchange(reader, writer, private_key)
        aes_key = derive_aes_key(shared_key)

        # Communication loop
        while True:
            data = await reader.read(4096)
            if not data:
                break
            decrypted_message = aes_decrypt(data, aes_key)
            print(f"Received: {decrypted_message}")

            # Process and respond
            response = "Acknowledged: " + decrypted_message
            encrypted_response = aes_encrypt(response, aes_key)
            writer.write(encrypted_response)
            await writer.drain()

    except Exception as e:
        print(f"Error handling connection: {e}")
    finally:
        writer.close()

# Start server to listen for incoming connections
async def run_server(port):
    server = await asyncio.start_server(handle_connection, 'localhost', port)
    async with server:
        await server.serve_forever()

# Main function to start server and connect to peers
async def main():
    server_port = 8888  # Example server port

    # Register service for peer discovery
    service_info = ServiceInfo(
        "_http._tcp.local.",
        "P2P Service._http._tcp.local.",
        socket.inet_aton("127.0.0.1"), server_port, 0, 0,
        {}, "ash-2.local."
    )
    zeroconf.register_service(service_info)

    try:
        # Start server
        await run_server(server_port)
    finally:
        zeroconf.unregister_service(service_info)
        zeroconf.close()

if __name__ == "__main__":
    asyncio.run(main())
