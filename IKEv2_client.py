#!/usr/bin/python
# -*- coding: UTF-8 -*-
import argparse, os, random, sys, traceback
import pproxy
import enums, crypto
from OpenSSL import crypto as crypto1
from cryptography.hazmat.primitives.ciphers import (
    Cipher,
    algorithms,
    modes,
)
from scapy.all import *
from scapy.contrib.ikev2 import *
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.backends import default_backend
from scapy.compat import orb


def _lcm(a, b):
    if a == 0 or b == 0:
        return 0
    else:
        return abs(a * b) // math.gcd(a, b)


def pad_and_encrypt(plain_text, key, iv):
    data_len = len(plain_text) + 1
    align = _lcm(64 // 8, 4)  # 3des block_size=8
    padlen = -data_len % align
    padding = struct.pack("B" * padlen, *[0 for i in range(padlen)])
    test_to_encrypt = plain_text + padding + bytes([padlen])
    cipher = Cipher(
        algorithms.TripleDES(key),
        modes.CBC(iv),
        default_backend(),
    )
    encryptor = cipher.encryptor()
    test_encrypted = encryptor.update(test_to_encrypt) + encryptor.finalize()
    return iv + test_encrypted


def decrypt(encrypted_text, key):  # encrypted_text does not include icv
    iv_size = 8  # 3des
    iv = encrypted_text[:iv_size]
    text_to_decrypt = encrypted_text[iv_size:]
    cipher = Cipher(
        algorithms.TripleDES(key),
        modes.CBC(iv),
        default_backend(),
    )
    decryptor = cipher.decryptor()
    try:
        data = decryptor.update(text_to_decrypt) + decryptor.finalize()
    except:
        print("devrypt error!")
        print(traceback.print_exc())
    return data[:len(data) - orb(data[-1]) - 1]

class IKEv2_Client():
    def __init__(self, target_IP, iface, my_IP, p12_cert=None, public_cert=None):
        self.target_IP = target_IP
        self.my_spi = os.urandom(8)
        self.peer_spi = b"\x00" * 8
        self.peer_msgid = 0
        self.crypto = None
        self.peer_crypto = None
        self.my_nonce = os.urandom(32)
        self.peer_nonce = None
        self.child_sa = []
        self.iface = iface
        self.my_IP = my_IP
        self.p12_cert = p12_cert
        self.p12_cert_passwd = b""
        self.public_cert = public_cert

    def sr_IKE_INIT(self):
        pkt_INIT = Ether() / IP(src=self.my_IP, dst=self.target_IP) / UDP(sport=500, dport=500)
        pkt_INIT /= IKEv2(init_SPI=self.my_spi, exch_type=34, flags=0x8)
        pkt_INIT /= IKEv2_payload_SA(next_payload=34, prop=IKEv2_payload_Proposal(trans_nb=4, trans=
                   IKEv2_payload_Transform(transform_type=1, transform_id=3)
                 / IKEv2_payload_Transform(transform_type=3, transform_id=2)
                 / IKEv2_payload_Transform(transform_type=2, transform_id=2)
                 / IKEv2_payload_Transform(transform_type=4, transform_id=2)))
        self.my_public_key, self.dh_a = crypto.DH_create_my_public_key(2)  # 1024 bit
        pkt_INIT /= IKEv2_payload_KE(next_payload=40, group=2, load=self.my_public_key)
        pkt_INIT /= IKEv2_payload_Nonce(next_payload=0, load=self.my_nonce)  # nonce 32 bytes
        self.my_pkt_INIT = pkt_INIT
        response_pkt_INIT = srp1(self.my_pkt_INIT, iface=self.iface, filter="udp and port 500", timeout=0.5, retry=0)
        if response_pkt_INIT is None:
            print("no response of pkt_INIT")
            return None
        self.peer_pkt_INIT = response_pkt_INIT[0]
        print(self.peer_pkt_INIT.summary())
        self.peer_spi = self.peer_pkt_INIT[IKEv2].resp_SPI
        self.peer_nonce = self.peer_pkt_INIT[IKEv2_payload_Nonce].load
        self.peer_public_key = self.peer_pkt_INIT[IKEv2_payload_KE].load
        self.shared_secret = crypto.DH_caculate_shared_secret(2, self.dh_a, self.peer_public_key)  # 1024 bit
        h = hmac.HMAC(self.my_nonce + self.peer_nonce, hashes.SHA1(), backend=default_backend())
        h.update(self.shared_secret)
        SKEYSEED = h.finalize()
        K = SKEYSEED
        S = self.my_nonce + self.peer_nonce + self.my_spi + self.peer_spi
        T = b""
        TotalKey = b""
        count_byte = b"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x10"
        for i in range(1, 10):
            data = T + S + count_byte[i - 1:i]
            h = hmac.HMAC(K, hashes.SHA1(), backend=default_backend())
            h.update(data)
            T = h.finalize()
            TotalKey += T
        self.SK_d = TotalKey[0:20]
        self.SK_ai = TotalKey[20:20 + 20]
        self.SK_ar = TotalKey[40:40 + 20]
        self.SK_ei = TotalKey[60:60 + 24]
        self.SK_er = TotalKey[84:84 + 24]
        self.SK_pi = TotalKey[108:108 + 20]
        self.SK_pr = TotalKey[128:128 + 20]

    def sr_IKE_AUTH(self, IDtype, ID_load):
        pkt_AUTH_plain = IKEv2_payload_IDi(next_payload=37, IDtype=IDtype, load=ID_load)
        with open(self.public_cert, 'rb') as f:
            x = f.read()
            CERT_data = b'\x04' + bytes(x)
        pkt_AUTH_plain /= IKEv2_payload_Nonce(next_payload=39, load=CERT_data)
        p12 = crypto1.load_pkcs12(open(self.p12_cert, 'rb').read(), b"")
        p12_privkey = p12.get_privatekey()
        id = bytes([IDtype]) + b"\x00\x00\x00" + pkt_AUTH_plain[IKEv2_payload_IDi].load
        h = hmac.HMAC(self.SK_pi, hashes.SHA1(), backend=default_backend())
        h.update(id)
        MACedIDForI = h.finalize()
        RealMessage1 = raw(self.my_pkt_INIT[IKEv2])
        InitiatorSignedOctets = RealMessage1 + self.peer_nonce + MACedIDForI
        sign_data = crypto1.sign(pkey=p12_privkey, data=InitiatorSignedOctets, digest='sha1')
        pkt_AUTH_plain /= IKEv2_payload_AUTH(next_payload=33, auth_type=1, load=sign_data)
        my_esp_spi = os.urandom(4)
        pkt_AUTH_plain /= IKEv2_payload_SA(next_payload=44, prop=
                        IKEv2_payload_Proposal(trans_nb=3, proto=3, SPIsize=4, SPI=my_esp_spi, trans=
                        IKEv2_payload_Transform(transform_type=1, transform_id=3) /
                        IKEv2_payload_Transform(transform_type=3, transform_id=2) /
                        IKEv2_payload_Transform(transform_type=5, transform_id=0)))
        pkt_AUTH_plain /= IKEv2_payload_TSi(next_payload=45, number_of_TSs=1, traffic_selector=[IPv4TrafficSelector()])
        pkt_AUTH_plain /= IKEv2_payload_TSr(next_payload=0, number_of_TSs=1, traffic_selector=[IPv4TrafficSelector()])
        pkt_AUTH_encrypted = pad_and_encrypt(plain_text=raw(pkt_AUTH_plain), key=self.SK_ei, iv=os.urandom(8))
        pkt_AUTH_1 = IKEv2(init_SPI=self.my_spi, resp_SPI=self.peer_spi, exch_type=35, flags=8, id=1)
        pkt_AUTH_1 /= IKEv2_payload_Encrypted(next_payload=35,
                                     load=pkt_AUTH_encrypted + struct.pack("B" * 12, *[0 for i in range(12)]))
        h = hmac.HMAC(self.SK_ai, hashes.SHA1(), backend=default_backend())
        h.update(raw(pkt_AUTH_1)[:len(pkt_AUTH_1) - 12])
        c = h.finalize()
        icv = c[:12]
        pkt_AUTH_1 = IKEv2(init_SPI=self.my_spi, resp_SPI=self.peer_spi, exch_type=35, flags=8, id=1)
        pkt_AUTH_1 /= IKEv2_payload_Encrypted(next_payload=35, load=pkt_AUTH_encrypted + icv)
        pkt_AUTH = Ether() / IP(src=self.my_IP, dst=self.target_IP) / UDP(sport=4500, dport=4500)
        pkt_AUTH /= ESP(seq=struct.unpack('>I', (raw(pkt_AUTH_1)[:4]))[0], data=raw(pkt_AUTH_1)[4:])
        self.my_pkt_AUTH = pkt_AUTH
        response_pkt_AUTH = srp1(self.my_pkt_AUTH, iface=self.iface, filter="udp and port 4500", timeout=0.5, retry=0)
        if response_pkt_AUTH is None:
            print("no response of pkt_AUTH")
            return None
        self.peer_pkt_AUTH = response_pkt_AUTH[0]
        print(self.peer_pkt_AUTH.summary())
        peer_pkt_AUTH_IKEv2_payload = IKEv2(raw(self.peer_pkt_AUTH[ESP])[4:])
        peer_pkt_AUTH_encrypted = raw(peer_pkt_AUTH_IKEv2_payload[IKEv2_payload_Encrypted].load)[:-12]
        peer_pkt_AUTH_plain = decrypt(peer_pkt_AUTH_encrypted, self.SK_er)
        peer_pkt_AUTH_plain = IKEv2_payload_Notify(peer_pkt_AUTH_plain)
        if peer_pkt_AUTH_IKEv2_payload[IKEv2_payload_Encrypted].next_payload == 41:
            print(IKEv2NotifyMessageTypes[peer_pkt_AUTH_plain[IKEv2_payload_Notify].type])
        else:
            print("AUTHENTICATION Succeed!")
        return


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="IKEv2 Client", epilog=f'')
    parser.add_argument('-t', dest='target_IP', default='192.168.0.128', help='target_IP (default: 192.168.0.128)')
    parser.add_argument('-i', dest='iface', default=None, help='iface (default: None)')
    parser.add_argument('-p12_cert', dest='p12_cert', default="./libswan_client_SAN_star_a_a.p12", help='p12_cert (default: ./libswan_client_SAN_star_a_a.p12)')
    parser.add_argument('-public_cert', dest='public_cert', default="./libswan_client_SAN_star_a_a.cer", help='public_cert (default: ./libswan_client_SAN_star_a_a.cer)')
    args = parser.parse_args()
    args.DIRECT = pproxy.Connection('direct://')
    my_IKEv2 = IKEv2_Client(target_IP=args.target_IP, iface=args.iface, my_IP="192.168.0.1", p12_cert=args.p12_cert,
                     public_cert=args.public_cert)
    my_IKEv2.sr_IKE_INIT()
    my_IKEv2.sr_IKE_AUTH(IDtype=2, ID_load=b"*.org")
