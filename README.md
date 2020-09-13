# IKEv2-Client-for-ID-match-test
Just test IPsec ID match.

Request Python3, scapy, cryptography, pyOpenSSL, etc.

Support IKEv2 3des-sha1-modp1024 RSA auth, now.

You can change parameters in main function.
```python
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
```
IDi Type and IDi Data can be controlled by the parameters of sr_IKE_AUTH() method.
