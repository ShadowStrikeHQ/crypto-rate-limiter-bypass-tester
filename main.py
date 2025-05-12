import argparse
import logging
import time
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import asymmetric
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, PrivateFormat, NoEncryption
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os
import secrets

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def setup_argparse():
    """
    Sets up the argument parser for the command-line interface.
    """
    parser = argparse.ArgumentParser(description="Crypto Rate Limiter Bypass Tester")
    parser.add_argument("--operation", choices=["hmac", "hkdf", "signature", "aes"], required=True,
                        help="The cryptographic operation to test (hmac, hkdf, signature, aes).")
    parser.add_argument("--iterations", type=int, default=100,
                        help="The number of iterations to perform.  Higher numbers may trigger rate limiting.")
    parser.add_argument("--key_size", type=int, default=32,
                        help="The size of the key to use in bytes (default: 32).")  # For HMAC and AES
    parser.add_argument("--hkdf_length", type=int, default=32,
                        help="The length of the output for HKDF (default: 32).")
    parser.add_argument("--signature_algorithm", choices=["ecdsa", "rsa"], default="ecdsa",
                        help="The signature algorithm to use (ecdsa, rsa). Relevant for signature testing.")
    parser.add_argument("--aes_mode", choices=["cbc", "ctr"], default="cbc",
                        help="The AES mode of operation (cbc, ctr).  Relevant for AES testing")
    return parser.parse_args()


def test_hmac(iterations, key_size):
    """
    Tests the HMAC operation for rate limiting vulnerabilities.
    """
    try:
        key = secrets.token_bytes(key_size)
        message = b"This is a test message."
        start_time = time.time()

        for i in range(iterations):
            h = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
            h.update(message)
            h.finalize()

        end_time = time.time()
        duration = end_time - start_time
        logging.info(f"HMAC completed in {duration:.4f} seconds for {iterations} iterations.")
        logging.info(f"Average time per HMAC operation: {(duration/iterations):.6f} seconds")

    except Exception as e:
        logging.error(f"Error during HMAC testing: {e}")


def test_hkdf(iterations, hkdf_length):
    """
    Tests the HKDF operation for rate limiting vulnerabilities.
    """
    try:
        salt = os.urandom(16)
        ikm = os.urandom(16)
        info = b"hkdf_test"

        start_time = time.time()
        for i in range(iterations):
            hkdf = HKDF(
                algorithm=hashes.SHA256(),
                length=hkdf_length,
                salt=salt,
                info=info,
                backend=default_backend()
            )
            hkdf.derive(ikm)  # Derive the key

        end_time = time.time()
        duration = end_time - start_time
        logging.info(f"HKDF completed in {duration:.4f} seconds for {iterations} iterations.")
        logging.info(f"Average time per HKDF operation: {(duration/iterations):.6f} seconds")

    except Exception as e:
        logging.error(f"Error during HKDF testing: {e}")


def test_signature(iterations, signature_algorithm):
    """
    Tests signature generation/verification for rate limiting vulnerabilities.
    """
    try:
        if signature_algorithm == "ecdsa":
            private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
            public_key = private_key.public_key()
            algorithm = asymmetric.ec.ECDSA(hashes.SHA256())

        elif signature_algorithm == "rsa":
            private_key = asymmetric.rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
            public_key = private_key.public_key()
            algorithm = asymmetric.rsa.PSS(mgf=asymmetric.rsa.MGF1(hashes.SHA256()), salt_length=asymmetric.rsa.PSS.MAX_LENGTH)

        else:
            raise ValueError("Invalid signature algorithm.")

        message = b"This is a test message to be signed."

        start_time = time.time()
        for i in range(iterations):
            signature = private_key.sign(message, algorithm)
            public_key.verify(signature, message, algorithm)

        end_time = time.time()
        duration = end_time - start_time
        logging.info(f"Signature ({signature_algorithm}) completed in {duration:.4f} seconds for {iterations} iterations.")
        logging.info(f"Average time per Signature operation: {(duration/iterations):.6f} seconds")

    except Exception as e:
        logging.error(f"Error during Signature ({signature_algorithm}) testing: {e}")



def test_aes(iterations, key_size, aes_mode):
    """
    Tests AES encryption/decryption for rate limiting vulnerabilities.
    """
    try:
        key = secrets.token_bytes(key_size)
        plaintext = b"This is a test message" * 16  # Ensure message is long enough

        if aes_mode == "cbc":
            iv = os.urandom(16)
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
            padder = padding.PKCS7(algorithms.AES.block_size).padder()
            padded_data = padder.update(plaintext) + padder.finalize()
            encryptor = cipher.encryptor()
            decryptor = cipher.decryptor()
        elif aes_mode == "ctr":
            iv = os.urandom(16)
            cipher = Cipher(algorithms.AES(key), modes.CTR(iv), backend=default_backend())
            encryptor = cipher.encryptor()
            decryptor = cipher.decryptor()
            padded_data = plaintext  # CTR doesn't require padding
        else:
            raise ValueError("Invalid AES mode.")


        start_time = time.time()
        for i in range(iterations):
            ciphertext = encryptor.update(padded_data) + encryptor.finalize()
            decrypted_text = decryptor.update(ciphertext) + decryptor.finalize()


        end_time = time.time()
        duration = end_time - start_time
        logging.info(f"AES ({aes_mode}) completed in {duration:.4f} seconds for {iterations} iterations.")
        logging.info(f"Average time per AES operation: {(duration/iterations):.6f} seconds")

    except Exception as e:
        logging.error(f"Error during AES ({aes_mode}) testing: {e}")


def main():
    """
    Main function to parse arguments and run the selected test.
    """
    args = setup_argparse()

    if args.operation == "hmac":
        test_hmac(args.iterations, args.key_size)
    elif args.operation == "hkdf":
        test_hkdf(args.iterations, args.hkdf_length)
    elif args.operation == "signature":
        test_signature(args.iterations, args.signature_algorithm)
    elif args.operation == "aes":
        test_aes(args.iterations, args.key_size, args.aes_mode)
    else:
        logging.error("Invalid operation selected.")


if __name__ == "__main__":
    main()