from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256, SHA384, SHA512
import binascii
import base64
import os

def aes_encrypt_decrypt(file_path, key, iv, mode='encrypt', key_size=256, cipher_mode='CBC', encoding='hex'):
    with open(file_path, 'rb') as f:
        data = f.read()

    if len(key) * 8 != key_size:
        raise ValueError("Tamanho da chave incompatível com o tamanho especificado")

    # Configuração do modo de operação
    if cipher_mode == 'CBC':
        cipher = AES.new(key, AES.MODE_CBC, iv)
    elif cipher_mode == 'ECB':
        cipher = AES.new(key, AES.MODE_ECB)
    else:
        raise ValueError("Modo de operação inválido")

    if mode == 'encrypt':
        # Adicionar padding se necessário
        padding = AES.block_size - len(data) % AES.block_size
        data += bytes([padding] * padding)
        encrypted_data = cipher.encrypt(data)
        
        # Saída codificada
        if encoding == 'hex':
            output = encrypted_data.hex()
        elif encoding == 'base64':
            output = base64.b64encode(encrypted_data).decode()
        else:
            raise ValueError("Formato de codificação inválido")

        with open("texto_cifrado.txt", 'w') as f:
            f.write(output)

    elif mode == 'decrypt':
        # Decodificar entrada
        if encoding == 'hex':
            encrypted_data = bytes.fromhex(data.decode())
        elif encoding == 'base64':
            encrypted_data = base64.b64decode(data)
        else:
            raise ValueError("Formato de codificação inválido")
        
        decrypted_data = cipher.decrypt(encrypted_data)

        # Remover padding
        padding = decrypted_data[-1]
        output = decrypted_data[:-padding]

        with open("texto_decifrado.txt", 'w') as f:
            f.write(str(output))
    else:
        raise ValueError("Modo inválido (use 'encrypt' ou 'decrypt')")

    return output

def generate_rsa_keys(key_size=2048):
    key = RSA.generate(key_size)
    chave_privada = key.export_key()
    chave_publica = key.publickey().export_key()

    with open("chave_privada.pem", "wb") as f:
        f.write(chave_privada)
    with open("chave_publica.pem", "wb") as f:
        f.write(chave_publica)

    return chave_privada.decode(), chave_publica.decode()

def sign_file(file_path, private_key_path, sha_version=256):
    with open(file_path, "rb") as f:
        data = f.read()

    with open(private_key_path, "rb") as f:
        private_key = RSA.import_key(f.read())

    if sha_version == 256:
        h = SHA256.new(data)
    elif sha_version == 384:
        h = SHA384.new(data)
    elif sha_version == 512:
        h = SHA512.new(data)
    else:
        raise ValueError("Versão SHA não definida")

    signature = pkcs1_15.new(private_key).sign(h)

    with open("assinatura.sig", "wb") as f:
        f.write(signature)
    
    return signature

def verify_signature(file_path, public_key_path, signature_path, sha_version=256):
    with open(file_path, "rb") as f:
        data = f.read()

    with open(public_key_path, "rb") as f:
        public_key = RSA.import_key(f.read())

    with open(signature_path, "rb") as f:
        signature = f.read()

    if sha_version == 256:
        h = SHA256.new(data)
    elif sha_version == 384:
        h = SHA384.new(data)
    elif sha_version == 512:
        h = SHA512.new(data)
    else:
        raise ValueError("Versão SHA inválida")

    try:
        pkcs1_15.new(public_key).verify(h, signature)
        return "Assinatura válida"
    except (ValueError, TypeError):
        return "Assinatura inválida"

print("1 - Encrypt")
print("2 - Decrypt")
opcao = int(input("Opcao: "))
print()

print("Versoes do sha -> (256, 384, 512)")
sha_v = int(input("Digite a versao do sha: "))
print()

print("Tipos de encoding -> (hex, base64)")
encod = input("Digite o tipo de encoding: ")
print()

key = os.urandom(32)
iv = os.urandom(16)

if opcao == 1:
    msg = input("Digite a mensagem: ")
    with open("texto.txt", "w") as f:
        f.write(msg)
    print()
    print(f"Chave -> {key}")
    print(f"Vetor de Inicialização -> {iv}")

    encrypted = aes_encrypt_decrypt("texto.txt", key, iv, mode='encrypt', key_size=256, cipher_mode='CBC', encoding=encod)
    print(f"Mensagem encriptografada -> {encrypted}")
elif opcao == 2:
    #chave e iv fornecidos pelo usuário para decrypt
    key = b'\x00\x838\xff\xdb\xf2\x0c\xccK17l\xb5\xae\xe6\xccY\xce\x9d\x9c\x92\xd1\xdb\xfc\n\x06mIh\xae0_'
    iv = b'(\xb8\x91\x9c\x1a\xfb*m\xd0\x8e\xeb\x1e\xaa\xe9b('
    decrypted = aes_encrypt_decrypt("texto_cifrado.txt", key, iv, mode='decrypt', key_size=256, cipher_mode='CBC', encoding=encod)
    print(f"Mensagem descriptografada -> {decrypted}")

# 2. Geração de Chaves RSA
private_key, public_key = generate_rsa_keys(key_size=2048)

# 3. Assinatura RSA
signature = sign_file("texto.txt", "chave_privada.pem", sha_version=sha_v)

# 4. Verificação de Assinatura
is_valid = verify_signature("texto.txt", "chave_publica.pem", "assinatura.sig", sha_version=sha_v)

print(is_valid)
