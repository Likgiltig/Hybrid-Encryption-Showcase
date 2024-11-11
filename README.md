
## Showcase of Hybrid Encryption

This Python project utilizes hybrid encryption using a combination of RSA (**asymmetric**) and AES (**symmetric**) algorithms to encrypt and decrypt files.

Here's a breakdown of how the functions work.

**Key Generation and Management:**

-   `generate_rsa_keypair`: Creates a RSA keypair with a specified key size (default 2048 bits).
-   `save_keys`: Saves the private and public keys to separate PEM files.
-   `load_keys`: Loads the private and public keys.
-   `load_private_key`: Loads the private key.
-   `load_public_key`: Loads the public key.

These functions allow you to generate and manage the key pairs used for encryption and decryption.

**Encryption and Decryption:**

-   `generate_aes_key`: Generates a random AES key (256-bit) and initialization vector (IV) for symmetric encryption.
-   `encrypt_file`: Encrypts a file using hybrid encryption:
    1.  Generates a random AES key and IV.
    2.  Encrypts the AES key with the public key using RSA-OAEP padding.
    3.  Initializes an AES cipher in CBC mode with the generated key and IV.
    4.  Reads the file in chunks, encrypts each chunk with AES, and writes it to the output file.
    5.  Stores the encrypted AES key, IV, and additional metadata (key length) at the beginning of the output file.
-   `decrypt_file`: Decrypts a file encrypted with hybrid encryption:
    1.  Reads the metadata (key length and IV) from the beginning of the file.
    2.  Reads the encrypted AES key.
    3.  Decrypts the AES key using the private key with RSA-OAEP padding.
    4.  Initializes an AES cipher in CBC mode with the decrypted key and IV.
    5.  Reads the encrypted data chunks, decrypts them with AES, and stores them in memory.
    6.  Removes PKCS#7 padding (if present) from the decrypted data.
    7.  Writes the decrypted data to the output file.

The `encrypt_file` function takes **unencrypted file**, **output filename**, and the **public key** as input. It encrypts the file with the secure combination of RSA and AES, making it accessible only to the one having the private key.

The `decrypt_file` function takes **encrypted file**, **output filename**, and the **private key** as input. It decrypts the file but it does not automatically know what filetype to create, so you need to specify what kind of file to decrypt to.

**Use Case:**
-   Securely transferring confidential files over insecure networks (e.g., email attachments).
-   Encrypting sensitive data at rest on disk drives.
-   Building secure communication channels by encrypting messages with a hybrid approach.

**Key Points:**
-   RSA is used for secure key exchange due to its public-key nature, ensuring the AES key remains confidential.
-   AES provides efficient encryption for large data volumes.
-   The code incorporates error handling and security best practices like secure key generation and padding schemes.

**Additional Notes:**
-   You'll need to install the `cryptography` library for this project to work. Install it by running:
	-  `pip install cryptography`
-   Consider adjusting the RSA key size based on your security requirements.
-   Implement proper key management strategies for secure storage and access control.
-   OpenSSL offers better performance and security, this is mainly a showcase of how to do it in Python.

By understanding the logic behind this code, you can use hybrid encryption for various security needs in your Python projects.
