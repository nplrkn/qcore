# Transport key encryption of KI and OPC - specification for potential future feature 

To help protect KI and OPC, QCore could support use of AES-128(/256?)-CBC encryption of these values 
using a transport key.  This means that sims.toml does not need to be kept secret
(provided that the transport key is kept secret).  Encoded KI and OPC values are known as eKI and eOPC.

When QCore starts up, it could look for a key ("user", "transport_key") in the Linux keyring.
If found, it assumes that all of the KI and OPC values in sims.toml are encrypted with that key. 

To store a transport key in the Linux keyring for use by QCore, the person/entity in possession of 
the transport key could use the following command:
```
echo -n $TRANSPORT_KEY | keyctl padd user transport_key @u
``` 

This stores the hex string representation of the key.  To confirm it is stored correctly:
```
keyctl read $(keyctl search @u user transport_key)
```
...which should output 32 bytes of ASCII characters corresponding to the hex string.

Normally the encryption step is carried out as part of the SIM burning process, but
to give an example of how an eKI would be generated using a random transport key:
```
TRANSPORT_KEY=$(head -c 16 /dev/urandom | xxd -p)  
PLAINTEXT_KI="0123456789ABCDEF0123456789ABCDEF"
ENCODED_KI=$(echo -n $PLAINTEXT_KI | xxd -r | openssl aes-128-cbc -K $TRANSPORT_KEY -iv 00000000000000000000000000000000 | xxd -p) 
```