import os, json, sys
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidKey

def generate_rsa_keypair(key_size=2048):
    """Generate a new RSA keypair with specified key size."""
    try:
        print(f"Generating {key_size}-bit RSA keypair...")
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
            backend=default_backend()
        )
        public_key = private_key.public_key()
        print("RSA keypair generated successfully!")
        return private_key, public_key
    except Exception as e:
        print(f"Error generating RSA keypair: {str(e)}", file=sys.stderr)
        raise

def save_keys(private_key, public_key, private_key_path="private_key.pem", public_key_path="public_key.pem"):
    """Save RSA keys to files."""
    try:
        # Save private key
        print(f"Saving private key to {private_key_path}...")
        with open(private_key_path, 'wb') as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))
        # Save public key
        print(f"Saving public key to {public_key_path}...")
        with open(public_key_path, 'wb') as f:
            f.write(public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ))
        print("Keys saved successfully!")
    except PermissionError:
        print(f"Error: Permission denied when trying to save keys. Check file permissions.", file=sys.stderr)
        raise
    except Exception as e:
        print(f"Error saving keys: {str(e)}", file=sys.stderr)
        raise

def load_keys(private_key_path="private_key.pem", public_key_path="public_key.pem"):
    """Load RSA keys from files."""
    try:
        # Load private key
        print(f"Loading private key from {private_key_path}...")
        if not os.path.exists(private_key_path):
            raise FileNotFoundError(f"Private key file not found: {private_key_path}")
        
        with open(private_key_path, 'rb') as f:
            private_key = serialization.load_pem_private_key(
                f.read(),
                password=None,
                backend=default_backend()
            )
        
        # Load public key
        print(f"Loading public key from {public_key_path}...")
        if not os.path.exists(public_key_path):
            raise FileNotFoundError(f"Public key file not found: {public_key_path}")
        
        with open(public_key_path, 'rb') as f:
            public_key = serialization.load_pem_public_key(
                f.read(),
                backend=default_backend()
            )
        
        print("Keys loaded successfully!")
        return private_key, public_key
    except FileNotFoundError as e:
        print(f"Error: {str(e)}", file=sys.stderr)
        raise
    except Exception as e:
        print(f"Error loading keys: {str(e)}", file=sys.stderr)
        raise

def load_private_key(private_key_path="private_key.pem"):
    """Load private key from file."""
    try:
        # Load private key
        print(f"Loading private key from {private_key_path}...")
        if not os.path.exists(private_key_path):
            raise FileNotFoundError(f"Private key file not found: {private_key_path}")
        
        with open(private_key_path, 'rb') as f:
            private_key = serialization.load_pem_private_key(
                f.read(),
                password=None,
                backend=default_backend()
            )
        
        print("Private key loaded successfully!")
        return private_key
    except FileNotFoundError as e:
        print(f"Error: {str(e)}", file=sys.stderr)
        raise
    except Exception as e:
        print(f"Error loading private key: {str(e)}", file=sys.stderr)
        raise

def load_public_key(public_key_path="public_key.pem"):
    """Load RSA public key from file."""
    try:
        # Load public key
        print(f"Loading public key from {public_key_path}...")
        if not os.path.exists(public_key_path):
            raise FileNotFoundError(f"Public key file not found: {public_key_path}")
        
        with open(public_key_path, 'rb') as f:
            public_key = serialization.load_pem_public_key(
                f.read(),
                backend=default_backend()
            )
        
        print("Public key loaded successfully!")
        return public_key
    except FileNotFoundError as e:
        print(f"Error: {str(e)}", file=sys.stderr)
        raise
    except Exception as e:
        print(f"Error loading public key: {str(e)}", file=sys.stderr)
        raise

def generate_aes_key():
    """Generate a random AES key and initialization vector."""
    try:
        print("Generating AES key and initialization vector...")
        key = os.urandom(32)  # 256-bit key
        iv = os.urandom(16)   # 128-bit IV
        print("AES key and IV generated successfully!")
        return key, iv
    except Exception as e:
        print(f"Error generating AES key: {str(e)}", file=sys.stderr)
        raise

def encrypt_file(input_file_path, output_file_path, public_key):
    """Encrypt a file using hybrid encryption (RSA + AES)."""
    try:
        # Check if input file exists
        if not os.path.exists(input_file_path):
            raise FileNotFoundError(f"Input file not found: {input_file_path}")
        
        # Check input file size
        file_size = os.path.getsize(input_file_path)
        print(f"Input file size: {file_size / (1024*1024):.2f} MB")
        
        # Generate AES key and IV
        aes_key, iv = generate_aes_key()
        
        print("Encrypting AES key with RSA...")
        # Encrypt the AES key with RSA
        encrypted_aes_key = public_key.encrypt(
            aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        # Create AES cipher
        print("Initializing AES cipher...")
        cipher = Cipher(
            algorithms.AES(aes_key),
            modes.CBC(iv),
            backend=default_backend()
        )
        encryptor = cipher.encryptor()
        
        # Read and encrypt the file
        print("Starting file encryption...")
        processed_size = 0
        with open(input_file_path, 'rb') as f_in, open(output_file_path, 'wb') as f_out:
            # Write metadata
            metadata = {
                'key_length': len(encrypted_aes_key),
                'iv': iv.hex()
            }
            metadata_bytes = json.dumps(metadata).encode()
            f_out.write(len(metadata_bytes).to_bytes(4, byteorder='big'))
            f_out.write(metadata_bytes)
            f_out.write(encrypted_aes_key)
            
            # Encrypt file contents
            while True:
                chunk = f_in.read(64 * 1024)  # 64KB chunks
                if not chunk:
                    break
                
                # Update progress
                processed_size += len(chunk)
                print(f"Progress: {processed_size / file_size * 100:.1f}% ({processed_size / (1024*1024):.2f} MB)", end='\r')
                
                # Pad the last chunk if necessary
                if len(chunk) % 16 != 0:
                    padding_length = 16 - (len(chunk) % 16)
                    chunk += bytes([padding_length]) * padding_length
                
                encrypted_chunk = encryptor.update(chunk)
                f_out.write(encrypted_chunk)
            
            f_out.write(encryptor.finalize())
            print("\nFile encrypted successfully!")
            
    except FileNotFoundError as e:
        print(f"Error: {str(e)}", file=sys.stderr)
        raise
    except PermissionError:
        print(f"Error: Permission denied when trying to access files.", file=sys.stderr)
        raise
    except Exception as e:
        print(f"Error during encryption: {str(e)}", file=sys.stderr)
        # Clean up partial output file if it exists
        if os.path.exists(output_file_path):
            try:
                os.remove(output_file_path)
                print(f"Cleaned up partial output file: {output_file_path}")
            except:
                pass
        raise

def decrypt_file(input_file_path, output_file_path, private_key):
    """Decrypt a file using hybrid encryption (RSA + AES)."""
    try:
        # Check if input file exists
        if not os.path.exists(input_file_path):
            raise FileNotFoundError(f"Input file not found: {input_file_path}")
        
        # Check input file size
        file_size = os.path.getsize(input_file_path)
        if file_size < 20:  # Minimum size for a valid encrypted file
            raise ValueError(f"File is too small to be a valid encrypted file: {file_size} bytes")
            
        print(f"Encrypted file size: {file_size / (1024*1024):.2f} MB")
        
        processed_size = 0
        decrypted_data = bytearray()  # Store all decrypted data here first
        
        with open(input_file_path, 'rb') as f_in:
            try:
                # Read metadata length
                print("Reading metadata length...")
                metadata_length_bytes = f_in.read(4)
                if len(metadata_length_bytes) != 4:
                    raise ValueError("Failed to read metadata length (file may be corrupted)")
                
                metadata_length = int.from_bytes(metadata_length_bytes, byteorder='big')
                print(f"Metadata length: {metadata_length} bytes")
                
                if metadata_length > file_size or metadata_length <= 0:
                    raise ValueError(f"Invalid metadata length: {metadata_length}")
                
                # Read metadata
                print("Reading metadata content...")
                metadata_bytes = f_in.read(metadata_length)
                if len(metadata_bytes) != metadata_length:
                    raise ValueError("Failed to read complete metadata (file may be corrupted)")
                
                try:
                    metadata = json.loads(metadata_bytes.decode())
                    print("Metadata successfully parsed")
                except json.JSONDecodeError:
                    raise ValueError("Failed to parse metadata JSON (file may be corrupted)")
                
                # Validate metadata
                required_fields = ['key_length', 'iv']
                for field in required_fields:
                    if field not in metadata:
                        raise ValueError(f"Missing required metadata field: {field}")
                
                # Read encrypted AES key
                print(f"Reading encrypted AES key ({metadata['key_length']} bytes)...")
                encrypted_aes_key = f_in.read(metadata['key_length'])
                if len(encrypted_aes_key) != metadata['key_length']:
                    raise ValueError("Failed to read complete encrypted AES key")
                
                # Decrypt AES key
                print("Attempting to decrypt AES key...")
                try:
                    aes_key = private_key.decrypt(
                        encrypted_aes_key,
                        padding.OAEP(
                            mgf=padding.MGF1(algorithm=hashes.SHA256()),
                            algorithm=hashes.SHA256(),
                            label=None
                        )
                    )
                    if len(aes_key) != 32:  # AES-256 key size
                        raise ValueError(f"Decrypted AES key has wrong length: {len(aes_key)} bytes (expected 32)")
                    print("AES key successfully decrypted")
                except Exception as e:
                    raise InvalidKey(f"Failed to decrypt AES key: {str(e)}. Make sure you're using the correct private key.")
                
                # Decode IV
                try:
                    iv = bytes.fromhex(metadata['iv'])
                    if len(iv) != 16:  # AES block size
                        raise ValueError(f"Invalid IV length: {len(iv)} bytes (expected 16)")
                    print("IV successfully decoded")
                except ValueError as e:
                    raise ValueError(f"Failed to decode IV: {str(e)}")
                
                # Create AES cipher
                print("Initializing AES cipher...")
                cipher = Cipher(
                    algorithms.AES(aes_key),
                    modes.CBC(iv),
                    backend=default_backend()
                )
                decryptor = cipher.decryptor()
                
                # Calculate the actual encrypted data size
                header_size = 4 + metadata_length + metadata['key_length']
                data_size = file_size - header_size
                
                if data_size <= 0 or data_size % 16 != 0:
                    raise ValueError(f"Invalid encrypted data size: {data_size} bytes (must be positive and multiple of 16)")
                
                print(f"Starting file decryption (data size: {data_size} bytes)...")
                # Decrypt file contents
                while True:
                    chunk = f_in.read(64 * 1024)  # 64KB chunks
                    if not chunk:
                        break
                    
                    # Update progress
                    processed_size += len(chunk)
                    print(f"Progress: {processed_size / data_size * 100:.1f}% ({processed_size / (1024*1024):.2f} MB)", end='\r')
                    
                    try:
                        decrypted_chunk = decryptor.update(chunk)
                        decrypted_data.extend(decrypted_chunk)
                    except Exception as e:
                        raise ValueError(f"Decryption failed at byte {processed_size}: {str(e)}")
                
                try:
                    final_chunk = decryptor.finalize()
                    decrypted_data.extend(final_chunk)
                except Exception as e:
                    raise ValueError(f"Failed to finalize decryption: {str(e)}")
                
                # Handle PKCS7 padding
                if len(decrypted_data) > 0:
                    padding_length = decrypted_data[-1]
                    if padding_length > 16:
                        raise ValueError(f"Invalid padding byte: {padding_length}")
                    
                    # Verify the padding is correct
                    for i in range(1, padding_length + 1):
                        if decrypted_data[-i] != padding_length:
                            raise ValueError("Invalid padding pattern")
                    
                    # Remove padding
                    decrypted_data = decrypted_data[:-padding_length]
                
                # Write decrypted data to output file
                with open(output_file_path, 'wb') as f_out:
                    f_out.write(decrypted_data)
                
                print("\nFile decrypted successfully!")
                    
            except Exception as e:
                raise ValueError(f"Decryption failed: {str(e)}")
                
    except FileNotFoundError as e:
        print(f"Error: {str(e)}", file=sys.stderr)
        raise
    except PermissionError:
        print(f"Error: Permission denied when trying to access files.", file=sys.stderr)
        raise
    except InvalidKey as e:
        print(f"Error: {str(e)}", file=sys.stderr)
        raise
    except ValueError as e:
        print(f"Error: {str(e)}", file=sys.stderr)
        raise
    except Exception as e:
        print(f"Error during decryption: {str(e)}", file=sys.stderr)
        # Clean up partial output file if it exists
        if os.path.exists(output_file_path):
            try:
                os.remove(output_file_path)
                print(f"Cleaned up partial output file: {output_file_path}")
            except:
                pass
        raise

# Generate Asymetric keys
#private_key, public_key = generate_rsa_keypair()
#save_keys(private_key, public_key)

# Encrypt a file
#public_key = load_public_key()
#encrypt_file('example.pdf', 'encrypted.bin', pub_key)

# Decrypt a file
#private_key = load_private_key()
#decrypt_file("encrypted.bin", "decrypted.pdf", priv_key)

# Load  both keys
#private_key, public_key = load_keys()
