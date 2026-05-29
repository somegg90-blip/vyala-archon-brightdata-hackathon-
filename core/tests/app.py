"""
Legacy Fintech Payment Gateway Module
WARNING: Contains quantum-vulnerable cryptography.
"""
import rsa
from Crypto.Cipher import AES, DES
from Crypto.PublicKey import RSA, ECC
from Crypto.Hash import SHA1, MD5
import hashlib
import ecdsa
from cryptography.hazmat.primitives.asymmetric import rsa as crypto_rsa, ec
from cryptography.hazmat.primitives import hashes

class QuantumVulnerablePaymentGateway:
    def __init__(self):
        # Shor Vulnerable: RSA Key generation
        self.rsa_key_2048 = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.crypto_rsa_key = crypto_rsa.generate_private_key(public_exponent=65537, key_size=4096)
        
        # Shor Vulnerable: ECC Key generation
        self.ecc_key = ec.generate_private_key(ec.SECP256R1())
        self.ecdsa_key = ecdsa.SigningKey.generate(curve=ecdsa.NIST256p)

    def process_payment(self, card_data: dict):
        # Grover Weakened: Hashing
        txn_hash_md5 = hashlib.md5(card_data['txn_id'].encode()).hexdigest()
        txn_hash_sha1 = SHA1.new(card_data['amount'].encode()).hexdigest()
        
        # Grover Weakened / Bad Mode: Symmetric Encryption
        aes_key = b'16bytekey1234567' # AES-128
        cipher_aes = AES.new(aes_key, AES.MODE_ECB)
        encrypted_card = cipher_aes.encrypt(card_data['card_number'].encode())
        
        des_key = b'8bytekey'
        cipher_des = DES.new(des_key, DES.MODE_CBC, iv=b'12345678')
        encrypted_cvv = cipher_des.encrypt(card_data['cvv'].encode())

        # Shor Vulnerable: Signatures
        signature_rsa = self.rsa_key_2048.sign(card_data['amount'].encode(), 'SHA-256')
        signature_ecdsa = self.ecdsa_key.sign(card_data['txn_id'].encode(), hashfunc=hashlib.sha256)
        
        return encrypted_card