# String/File Encryptor
This script has the ability to encrypt both text, file and shellcode using AES and XOR.
## Usage
```
strfile-encryptor.py [-h] -t {text,file,shellcode} -e {xor,aes} -i INPUTS [-l KEY_LENGTH]

options:
  -h, --help            show this help message and exit
  -t {text,file,shellcode}, --input-type {text,file,shellcode}
                        'text', 'file' or 'shellcode'.
  -e {xor,aes}, --encryption-type {xor,aes}
                        'xor' or 'aes'.
  -i INPUTS, --inputs INPUTS
                        input filenames/texts separated by ','.
  -l KEY_LENGTH, --key-length KEY_LENGTH
                        XOR key length. default is '10'.
```
**Note:** If `-t` is `shellcode` it must be in a file in raw format.
## Decryption functions
<b>XOR</b>
```cpp
void XOR(unsigned char data[], int dataSize, char key[], int keySize) {
	for (int i = 0; i < (dataSize / sizeof(unsigned char)); i++) {
		char currentKey = key[i % (keySize - 1)];
		data[i] ^= currentKey;
	}
}
```
<b>AES</b>
```cpp
int AESDecrypt(unsigned char* payload, unsigned long payload_len, char* key, size_t keylen) {
	HCRYPTPROV hProv;
	HCRYPTHASH hHash;
	HCRYPTKEY hKey;

	if (!CryptAcquireContextW(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
		return -1;
	}
	if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) {
		return -1;
	}
	if (!CryptHashData(hHash, (const BYTE*)key, (DWORD)keylen, 0)) {
		return -1;
	}
	if (!CryptDeriveKey(hProv, CALG_AES_256, hHash, 0, &hKey)) {
		return -1;
	}

	if (!CryptDecrypt(hKey, (HCRYPTHASH)NULL, 0, 0, payload, &payload_len)) {
		return -1;
	}

	CryptReleaseContext(hProv, 0);
	CryptDestroyHash(hHash);
	CryptDestroyKey(hKey);
	return 0;
}
```