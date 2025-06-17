import argparse, base64, hashlib, math
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

    cipher64 = ciphertext.replace(' ', '+') # cipherText = cipherText.Replace(" ", "+");
    cipherbytes = bytes(base64.b64decode(cipher64)) #byte[] cipherBytes = Convert.FromBase64String(cipherText);

    #cipherbytes = bytes(base64.b64decode(ciphertext)) #byte[] cipherBytes = Convert.FromBase64String(cipherText);

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


def derive_key_iv(password: str, salt: bytes, iterations: int = 100): # This code attempts to mirror the PBKDF implementatoin in C#'s PasswordDeriveBytes() class https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.passwordderivebytes?view=net-9.0
    """
    Python implementation of .NET's PasswordDeriveBytes (SHA1, 100 iterations)
    matching the behavior of PasswordDeriveBytes.GetBytes for key + IV.
    """
    # 1) ComputeBaseValue: SHA1(password || salt), then iter-1 further SHA1s
    pwd_bytes = password
    h = hashlib.sha1()
    h.update(pwd_bytes)
    h.update(salt)
    base = h.digest()
    for _ in range(1, iterations - 1):
        base = hashlib.sha1(base).digest()

    # 2) First GetBytes(32) => key
    hash_size = 20
    total_key_len = 32
    nblocks = math.ceil(total_key_len / hash_size)
    result = b''
    prefix = 0
    for _ in range(nblocks):
        to_hash = (str(prefix).encode('ascii') + base) if prefix > 0 else base
        block = hashlib.sha1(to_hash).digest()
        result += block
        prefix += 1
    key = result[:total_key_len]
    extra = result
    extra_count = total_key_len

    # 3) Second GetBytes(16) => IV
    total_iv_len = 16
    ib = len(extra) - extra_count
    part1 = extra[ib:ib + ib]                       # from the leftover of first call
    to_compute = total_iv_len - ib

    # Compute blocks as needed (prefix continues from previous)
    iv_blocks = b''
    while len(iv_blocks) < to_compute:
        to_hash = str(prefix).encode('ascii') + base
        block = hashlib.sha1(to_hash).digest()
        iv_blocks += block
        prefix += 1

    iv = part1 + iv_blocks[:to_compute]
    return key, iv


def print_result(password: str, ciphertext: str, result: str):
   
    print("\u2554\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2557\n"+ 
        "\u2551  Ivan died from a stroke                      \u2551\n"+
        "\u2551 while he was playing chess with Bogdan Belsky \u2551\n"+ 
        "\u2551 on 28 March [O.S. 18 March] 1584...           \u2551\n"+
        "\u255a\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u255d\n")
   
    # 1) Build the three lines
    lines = [
        f"Password: {password}",
        f"Cryphertext: {ciphertext}",
        f"Result: {result}"
    ]
    # 2) Compute the width of the inner content (longest line)
    max_content = max(len(line) for line in lines)
    #   we add 2 for one space padding on left & right
    inner_width = max_content + 2

    # 3) Define all the box pieces
    top_left     = "\u2554"  # ╔
    top_right    = "\u2557"  # ╗
    bottom_left  = "\u255A"  # ╚
    bottom_right = "\u255D"  # ╝
    horiz_heavy  = "\u2550"  # ═
    vert_heavy   = "\u2551"  # ║
    sep_left     = "\u255F"  # ╟
    sep_right    = "\u2562"  # ╢
    horiz_light  = "\u2500"  # ─

    # 4) Print top border
    print(f"{top_left}{horiz_heavy * inner_width}{top_right}")
    # 5) Print line[0]
    print(f"{vert_heavy} {lines[0].ljust(max_content)} {vert_heavy}")
    # 6) Separator
    print(f"{sep_left}{horiz_light * inner_width}{sep_right}")
    # 7) Print line[1]
    print(f"{vert_heavy} {lines[1].ljust(max_content)} {vert_heavy}")
    # 8) Separator
    print(f"{sep_left}{horiz_light * inner_width}{sep_right}")
    # 9) Print line[2]
    print(f"{vert_heavy} {lines[2].ljust(max_content)} {vert_heavy}")
    # 10) Bottom border
    print(f"{bottom_left}{horiz_heavy * inner_width}{bottom_right}")


def main():

    parser = argparse.ArgumentParser(description="CLI script that takes a password and crypttext.")
    parser.add_argument('-p', '--password', required=True, help='Password argument enumerated from sourcecode')
    parser.add_argument('-t', '--crypttext', required=True, help='Crypttext argument')

    cryptgroup = parser.add_mutually_exclusive_group(required=True)
    cryptgroup.add_argument('-e', '--encrypt', action='store_const', dest='crypt', const='encrypt', help='Set mode to encrypt')
    cryptgroup.add_argument('-d', '--decrypt', action='store_const', dest='crypt', const='decrypt', help='Set mode to decrypt')

    keygroup = parser.add_mutually_exclusive_group(required=True)
    keygroup.add_argument('-1', '--PBKDF1', action='store_const', dest='pbkdf', const='1', help='Uses PBKDF1/PasswordDeriveBytes()')
    keygroup.add_argument('-2', '--PBKDF2', action='store_const', dest='pbkdf', const='2', help='Uses PBKDF2/RFC2898DeriveBytes()')

    args = parser.parse_args()

    ### HARDCODED SALT ###
    # The C# array:
    # new byte[] { 0x49, 0x76, 0x61, 0x6e, 0x20, 0x4d, 0x65, 0x64, 0x76, 0x65, 0x64, 0x65, 0x76 }
    ivan_medvedev_bytes = b'Ivan Medvedev' 

    ### PASSWORD FOR PBKDF2 ###
    # Convert password to bytes, from the Rfc2898DeriveBytes() code `byte[] passwordBytes = Encoding.UTF8.GetBytes(password);
    password = bytes(args.password, 'utf-8')

    if args.pbkdf == '1':
        key, iv = derive_key_iv(password, ivan_medvedev_bytes)
    elif args.pbkdf == '2':
        key, iv = PBKDF2(password, ivan_medvedev_bytes)
    else:
        raise ValueError("Invalid operation specified. Use -1 for PBKDF1/PasswordDeriveBytes() or -2 for PBDKF2/RFC2898DeriveBytes().")

    # print("Key: " + '-'.join(f"{b:02X}" for b in key))
    # print("IV:  " + '-'.join(f"{b:02X}" for b in iv))

    if args.crypt == 'encrypt':
        result = encrypt(args.crypttext, key, iv)
    elif args.crypt == 'decrypt':
        result = decrypt(args.crypttext, key, iv)
    else:
        raise ValueError("Invalid operation specified. Use -e for encrypt or -d for decrypt.")

    print_result(
        args.password, 
        args.crypttext, 
        result)

if __name__ == "__main__":
    main()
