# Belsky's Gambit

## Death

Ivan died from a stroke while he was playing chess with Bogdan Belsky on 28 March [O.S. 18 March] 1584. Upon Ivan's death, the Russian throne was left to his middle son, Feodor, a weak-minded figure. Feodor died childless in 1598, which ushered in the Time of Troubles. He was buried at the Cathedral of the Archangel in Moscow. 

---
---
## Usage

```
usage: belskysGambit.py [-h] -p PASSWORD -t CRYPTTEXT (-e | -d) (-1 | -2)

CLI script that decrypts strings using the Ivan Medvedev hardcoded salt function.

options:
  -h, --help            show this help message and exit
  -p, --password PASSWORD
                        Password argument enumerated from sourcecode
  -t, --crypttext CRYPTTEXT
                        Crypttext argument
  -e, --encrypt         Set mode to encrypt
  -d, --decrypt         Set mode to decrypt
  -1, --PBKDF1          Uses PBKDF1/PasswordDeriveBytes()
  -2, --PBKDF2          Uses PBKDF2/RFC2898DeriveBytes()
```

---
## Info

I wrote a little python script that does ONE thing for me. It decrypts strings that use the oft reused Ivan Medvedev salted encryption functions.

References 
- [My Writeup on 2 applications](https://mojibake.dev/belskys-gambit)
- [Blog Post that clued me in](https://littlemaninmyhead.wordpress.com/2021/09/15/if-you-copied-any-of-these-popular-stackoverflow-encryption-code-snippets-then-you-did-it-wrong/)
- Separate Occurence 
    - [CVE-2021-36799](https://www.cvedetails.com/cve/CVE-2021-36799/?utm_source=chatgpt.com)
    - [Password Recovery POC](https://github.com/robertguetzkow/ets5-password-recovery?utm_source=chatgpt.com)
- [Original Stack Overflow Post](https://stackoverflow.com/questions/10168240/encrypting-decrypting-a-string-in-c-sharp/27484425#27484425)



All implementations of the copied functions use the same salt- that's a given. They all use the same defaults for AES in .NET regardless of the object used `AES` or `Rijndael`. 

Where they differ is  
- what algorithm they use for their PBKDF derived decryption key. Some use `PasswordDeriveBytes()` which uses the PBKDF1, algorithm, while some use `Rfc2989DeriveBytes()` which uses the PBKDF2 algorithm. Both slightly different implementations. 
- what password is hardcoded in. 

As such this script allows for selecting either algorithm, and takes the string for the password to be fed into the algo chosen. 

---
Here's a disorganized list from my notes of some resources used to determine the functionality ported to python and the defaults. 

- [Rfc2898DeriveBytes()](https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.rfc2898derivebytes?view=net-5.0)
	- [GetBytes() method](https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.rfc2898derivebytes.getbytes?view=net-5.0)
		- Repeated calls to this method will not generate the same key; instead, appending two calls of the [GetBytes](https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.rfc2898derivebytes.getbytes?view=net-5.0) method with a `cb` parameter value of `20` is the equivalent of calling the [GetBytes](https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.rfc2898derivebytes.getbytes?view=net-5.0) method once with a `cb` parameter value of `40`.

[AES Class](https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.aes?view=net-9.0)
	- [Symmetric Encryption](https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.symmetricalgorithm)
		- Padding [PKCS7](https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.symmetricalgorithm.padding?view=net-9.0#system-security-cryptography-symmetricalgorithm-padding)
[Memory Stream Class](https://learn.microsoft.com/en-us/dotnet/api/system.io.memorystream?view=net-9.0)
[CryptoStream Class](https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.cryptostream?view=net-9.0)

[PasswordDeriveBytes()](https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.passwordderivebytes)
[PasswordDeriveBytes.cs](https://github.com/dotnet/runtime/blob/1d1bf92fcf43aa6981804dc53c5174445069c9e4/src/libraries/System.Security.Cryptography/src/System/Security/Cryptography/PasswordDeriveBytes.cs)
---