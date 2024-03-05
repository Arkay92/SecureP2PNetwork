# SecureP2PNetwork

SecureP2PNetwork is a Python-based secure peer-to-peer chat application that leverages the Diffie-Hellman key exchange and AES encryption to facilitate private and secure communication over local networks. This application is designed to provide users with a simple yet robust method of exchanging messages securely without the need for a central server.

## Features

- **Peer-to-Peer Communication**: Directly connect with peers without a central server.
- **Diffie-Hellman Key Exchange**: Securely exchange cryptographic keys with peers.
- **AES Encryption**: Ensure privacy and confidentiality of messages using AES encryption.
- **Zeroconf Integration**: Discover services on the local network effortlessly.
- **Asynchronous I/O**: Benefit from non-blocking network communication.

## Requirements

This application requires Python 3.7+ and the following Python libraries:

- aiohttp
- asyncio
- cryptography
- zeroconf

To install the required libraries, run the following command:

```bash
pip install -r requirements.txt
```

## Installation
Clone the repository to your local machine:

```bash
git clone https://github.com/Arkay92/SecureP2PNetwork.git
cd SecureP2PNetwork
```

Install the required Python packages:

```bash
pip install -r requirements.txt
```

## Usage
To start the application, run:

```bash
python SecureP2PChat.py
```
Follow the on-screen instructions to connect with peers and start chatting securely.

## Contributing
Contributions to SecureP2PChat are welcome! Please feel free to submit pull requests or open issues to suggest improvements or report bugs.

## License
This project is licensed under the MIT License - see the LICENSE file for details.
