import argparse, base64
from io import BytesIO
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import (hashes, padding)
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import (
    Cipher, algorithms, modes
)


"""

~~~ This script is a Python implementation of the encryption and decryption logic used in the C# code provided in the original question. It uses AES in CBC mode with PKCS7 padding, similar to the .NET Aes.Create() method.

```
public static class EncryptionHelper
{
    public static string Encrypt(string clearText)
    {
        string EncryptionKey = "abc123";
        byte[] clearBytes = Encoding.Unicode.GetBytes(clearText);
        using (Aes encryptor = Aes.Create())
        {
            Rfc2898DeriveBytes pdb = new Rfc2898DeriveBytes(EncryptionKey, new byte[] { 0x49, 0x76, 0x61, 0x6e, 0x20, 0x4d, 0x65, 0x64, 0x76, 0x65, 0x64, 0x65, 0x76 });
            encryptor.Key = pdb.GetBytes(32);
            encryptor.IV = pdb.GetBytes(16);
            using (MemoryStream ms = new MemoryStream())
            {
                using (CryptoStream cs = new CryptoStream(ms, encryptor.CreateEncryptor(), CryptoStreamMode.Write))
                {
                    cs.Write(clearBytes, 0, clearBytes.Length);
                    cs.Close();
                }
                clearText = Convert.ToBase64String(ms.ToArray());
            }
        }
        return clearText;
    }
    public static string Decrypt(string cipherText)
    {
        string EncryptionKey = "abc123";
        cipherText = cipherText.Replace(" ", "+");
        byte[] cipherBytes = Convert.FromBase64String(cipherText);
        using (Aes encryptor = Aes.Create())
        {
            Rfc2898DeriveBytes pdb = new Rfc2898DeriveBytes(EncryptionKey, new byte[] { 0x49, 0x76, 0x61, 0x6e, 0x20, 0x4d, 0x65, 0x64, 0x76, 0x65, 0x64, 0x65, 0x76 });
            encryptor.Key = pdb.GetBytes(32);
            encryptor.IV = pdb.GetBytes(16);
            using (MemoryStream ms = new MemoryStream())
            {
                using (CryptoStream cs = new CryptoStream(ms, encryptor.CreateDecryptor(), CryptoStreamMode.Write))
                {
                    cs.Write(cipherBytes, 0, cipherBytes.Length);
                    cs.Close();
                }
                cipherText = Encoding.Unicode.GetString(ms.ToArray());
            }
        }
        return cipherText;
    }
}
```

"""


def encrypt(text: str, key: bytes, iv: bytes) -> str:

    data = bytes(text, 'utf-16le') # matching the code `byte[] clearBytes = Encoding.Unicode.GetBytes(clearText);`

    # PKCS7-pad to AES block size (128 bits) 
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded = padder.update(data) + padder.finalize()
    # Create AES/CBC encryptor (defaults match .NET Aes.Create())
    cipher = Cipher(
        algorithms.AES(key),
        modes.CBC(iv),
        backend=default_backend()
    )
    encryptor = cipher.encryptor()
    # “Stream” the padded plaintext through the encryptor
    cyphertext = encryptor.update(padded) + encryptor.finalize()
    return base64.b64encode(cyphertext).decode('ascii')


def decrypt(ciphertext: str, key: bytes, iv: bytes) -> bytes:

    cypher64 = ciphertext.replace(' ', '+') # cipherText = cipherText.Replace(" ", "+");
    cipherbytes = bytes(base64.b64decode(ciphertext)) #byte[] cipherBytes = Convert.FromBase64String(cipherText);


    # Create AES/CBC decryptor
    cipher = Cipher(
        algorithms.AES(key),
        modes.CBC(iv),
        backend=default_backend()
    )
    decryptor = cipher.decryptor()
    # Stream the ciphertext through the decryptor
    padded = decryptor.update(cipherbytes) + decryptor.finalize()
    # Unpad via PKCS7
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    cleartext = unpadder.update(padded) + unpadder.finalize()
    
    return cleartext.decode('utf-16le')  # matching the code `cipherText = Encoding.Unicode.GetString(ms.ToArray());`


def PBKDF2(password, salt):
    """
    Pasword Based Key Derivation Function 2 Settings
    This outlines the settings used in the default C# Rfc2898DeriveBytes() constructor.

    ~~~The following are default values for the arguments in the constructor:
    (left is the name of the field as it appears at the class declaration, right is the default value from the source code)

    ```    
    private byte[] _salt;               = ivan medvedev
    private uint _iterations;           = default is 1000
    private IncrementalHash _hmac;      = HMACSHA1
    private readonly int _blockSize;    = `_blockSize = _hmac.HashLengthInBytes;` so for SHA1 it is 20 bytes
    ``` from Rfc2898DeriveBytes.cs

    ~~~The constructor initializes the following relevant fields:
    (the left is the name of the field as it appears at the class declaration, right is the initialization code from the source code)
    
    ```
                                        private void Initialize()
                                        {
                                            if (_buffer != null)
                                                Array.Clear(_buffer);   
    private byte[] _buffer;                 _buffer = new byte[_blockSize];
    private uint _block;                    _block = 0;
    private int _startIndex;                _startIndex = _endIndex = 0;
    private int _endIndex;              }
    ``` from Rfc2898DeriveBytes.cs
    """ 

    # The actual C# code for deriving the key and IV looks like this:
    """
    ```
    Rfc2898DeriveBytes pdb = new Rfc2898DeriveBytes(EncryptionKey, new byte[] { 0x49, 0x76, 0x61, 0x6e, 0x20, 0x4d, 0x65, 0x64, 0x76, 0x65, 0x64, 0x65, 0x76 });
            encryptor.Key = pdb.GetBytes(32);
            encryptor.IV = pdb.GetBytes(16);
    ``` https://stackoverflow.com/questions/10168240/encrypting-decrypting-a-string-in-c-sharp/27484425#27484425
    """ 
    pbkdf2 = PBKDF2HMAC(
    algorithm=hashes.SHA1(),      # Use SHA1 to match C# default
    length=48,                    # 32 bytes for key + 16 bytes for IV
    salt=salt,
    iterations=1000,              # Match C# default if using Rfc2898DeriveBytes
    backend=default_backend()
    )
    key_iv = pbkdf2.derive(password)

    # The derived key is 48 bytes long, split into 32 bytes for the key and 16 bytes for the IV
    key = key_iv[:32]
    iv = key_iv[32:48]

    return key, iv


def main():
    parser = argparse.ArgumentParser(description="CLI script that takes a password and crypttext.")
    parser.add_argument('-p', '--password', required=True, help='Password argument enumerated from sourcecode')
    parser.add_argument('-t', '--crypttext', required=True, help='Crypttext argument')
    
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-e', '--encrypt', action='store_const', dest='crypt', const='encrypt', help='Set mode to encrypt')
    group.add_argument('-d', '--decrypt', action='store_const', dest='crypt', const='decrypt', help='Set mode to decrypt')

    args = parser.parse_args()

    ### HARDCODED SALT ###
    # The C# array:
    # new byte[] { 0x49, 0x76, 0x61, 0x6e, 0x20, 0x4d, 0x65, 0x64, 0x76, 0x65, 0x64, 0x65, 0x76 }
    ivan_medvedev_bytes = b'Ivan Medvedev' 

    ### PASSWORD FOR PBKDF2 ###
    # Convert password to bytes, from the Rfc2898DeriveBytes() code `byte[] passwordBytes = Encoding.UTF8.GetBytes(password);
    password = bytes(args.password, 'utf-8')


    key, iv = PBKDF2(password, ivan_medvedev_bytes)

    # Output the derived key and IV
    print("Key:", key)
    print("IV:", iv)

    print(f"Password: {args.password}")
    print(f"Crypttext: {args.crypttext}")

    # if args.crypt == 'encrypt':
    #     result = encrypt(bytes(args.crypttext, "utf-8"), key, iv)
    # elif args.crypt == 'decrypt':
    #     result = decrypt(bytes(args.crypttext, "utf-8"), key, iv)
    # else:
    #     raise ValueError("Invalid operation specified. Use -e for encrypt or -d for decrypt.")
    
    # print("Result:", result)

    encryptresult = encrypt(args.crypttext, key, iv)
    print("Encrypted: ", encryptresult)

    decryptresult = decrypt(encryptresult, key, iv)
    print("decrypted: ", decryptresult)

if __name__ == "__main__":
    main()
