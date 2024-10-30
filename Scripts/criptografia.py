from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
import base64

def encrypt(text, password):
    salt = get_random_bytes(16)
    key = PBKDF2(password, salt, dkLen=32, count=1000000)
    iv = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    
    # Padding do texto para múltiplos de 16 bytes
    pad_len = 16 - len(text) % 16
    text += chr(pad_len) * pad_len
    
    ciphertext = cipher.encrypt(text.encode('utf-8'))
    encrypted_data = base64.b64encode(salt + iv + ciphertext).decode('utf-8')
    
    return encrypted_data

def decrypt(encrypted_data, password):
    encrypted_data = base64.b64decode(encrypted_data)
    salt = encrypted_data[:16]
    iv = encrypted_data[16:32]
    ciphertext = encrypted_data[32:]
    
    key = PBKDF2(password, salt, dkLen=32, count=1000000)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    
    decrypted_text = cipher.decrypt(ciphertext).decode('utf-8')
    
    # Remove o padding
    pad_len = ord(decrypted_text[-1])
    decrypted_text = decrypted_text[:-pad_len]
    
    return decrypted_text

def main():
    while True:
        action = input("(d),(e) ou (s): ").strip().lower()
        
        if action == 's':
            break
        
        if action not in ['e', 'd']:
            print("Animal, burrão.")
            print("SAIA IMEDIATAMENTE DESSE CODIGO SE VC N SABE PRA QUE SERVE")
            print("Filho da puta.")
            continue
        
        password = input("Key: ").strip()
        
        if action == 'e':
            text = input("Seed: ").strip()
            encrypted_text = encrypt(text, password)
            print("Seed criptografada:", encrypted_text)
        elif action == 'd':
            try:
                text = input("Seed criptografada: ").strip()
                decrypted_text = decrypt(text, password)
                print("Seed descriptografada:", decrypted_text)
            except Exception as e:
                encrypted_text = encrypt(text, password)
                print("Seed descriptografada:", encrypted_text)

# limite = 10
# resposta_limitada = resposta[:limite]

if __name__ == "__main__":
    main()
