import string
from random import choice
from os import urandom
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import argparse



class Encryption:
    def __init__(self,input_type, enc_type,length=10):
        self.letters = string.ascii_lowercase+string.ascii_uppercase+string.digits
        self.length = length
        self.input_type = input_type
        self.enc_type = enc_type
    def __XOR_key_generator(self,length):
        "generate random XOR key"
        key = ""
        for i in range(length):
            key += choice(self.letters)
        return key
    def XOR(self,data):
        "XOR text/file"
        key = self.__XOR_key_generator(self.length)
        encoded_data = data if self.input_type == "file" else data.encode()+b'\x00'
        data_array = bytearray(encoded_data) #modifable when bytearray    
        for i in range(len(data_array)):
            current_key = key[i % len(key)]
            data_array[i] ^=  ord(current_key)
        
        encrypted = bytes(data_array)
        key_var = "XORKey" if self.input_type == "file" else "k"+data[0].upper()+data[1:]
        key_value = "{" + ", ".join(hex(x) for x in (key.encode()+b"\x00")) + "}"   
        key_info = f"char {key_var}[] = {key_value};\n"
        if(self.input_type == "file"):
            return [encrypted,key_info]
        else:
            ciphertext_value = "{" + ", ".join(hex(x) for x in encrypted) + "}"
            ciphertext_info = f"unsigned char s{data[0].upper()+data[1:]}[] = {ciphertext_value};\n"
            return [ciphertext_info, key_info]
        
    def AES(self, data):
        "AES encrypt text/file"
        key = urandom(16)
        aes_key = hashlib.sha256(key).digest()
  
        iv = b'\x00' * 16
        encoded_data = data if self.input_type == "file" else data.encode()+b'\x00'
        padded_data = pad(encoded_data, AES.block_size)
        cipher = AES.new(aes_key, AES.MODE_CBC, iv)

        key_var = "AESKey" if self.input_type == "file" else "k"+data[0].upper()+data[1:]
        key_info = f"char {key_var}[] ="+ "{ 0x" + ", 0x".join(hex(ord(chr(x)))[2:] for x in key) + "};\n"
        encrypted = cipher.encrypt(padded_data)
        if(self.input_type == "file"): return [encrypted,key_info]
        else:
            ciphertext_value = "{" + ", ".join(hex(x) for x in encrypted ) + "}"
            ciphertext_info = f"unsigned char s{data[0].upper()+data[1:]}[] = {ciphertext_value};\n"
            return [ciphertext_info, key_info]
    def encrypt(self,data):
        if self.input_type != "file":
            data_var = data[0].upper()+data[1:]
            decryption_function_call = f"(s{data_var}, sizeof(s{data_var}), k{data_var}, sizeof(k{data_var}));\n"
        if(enc_type == "aes"):
            result = self.AES(data)
            if self.input_type != "file": result.append("AESDecrypt"+decryption_function_call)
        elif(enc_type == "xor"):
            result = self.XOR(data)
            if self.input_type != "file": result.append("XOR"+decryption_function_call)
        return result
def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--input-type", help="'text' or 'file'.",choices=['text','file'],required=True,dest="input_type")
    parser.add_argument("-e","--encryption-type",help="'xor' or 'aes'.",dest="enc_type",required=True,choices=['xor','aes'])
    parser.add_argument("-i","--inputs",help="input filenames/texts separated by ','.",dest="inputs",required=True)
    parser.add_argument("-l","--key-length",help="XOR key length. default is '10'.",dest="key_length",default=10)
    return parser.parse_args()

if __name__ == "__main__":
    
    options = parse_args()
    input_type = options.input_type
    key_length = int(options.key_length)
    inputs = options.inputs
    enc_type = options.enc_type

    encryption = Encryption(input_type,enc_type,key_length)

    output_obj = {"ciphertexts":[],"keys":[],"decryption_function_calls":[]}

    if(input_type == "text"):
        for text in inputs.split(','):
            result = encryption.encrypt(text)

            output_obj["ciphertexts"].append(result[0])
            output_obj["keys"].append(result[1])
            output_obj["decryption_function_calls"].append(result[2])

        for key in list(output_obj.keys()):
            for item in output_obj[key]:
                with open("all.txt","a") as f:
                    f.write(item)
                    f.close()
            with open("all.txt","a") as f:
                f.write("\n")
                f.close()

    elif(input_type =="file"):
        for file in inputs.split(','):
            with open(file,"rb") as f:
                result = encryption.encrypt(f.read())
                print(f"file {file}.enc key:\n{result[1]}")
                with open(file+".enc", "wb") as out_file:
                    out_file.write(result[0])
                

            


    
