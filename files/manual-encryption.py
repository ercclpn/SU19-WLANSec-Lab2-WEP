#!/usr/bin/env python
# -*- coding: utf-8 -*-

""" Manually decrypt a wep message given the WEP key"""

__author__      = "Abraham Rubinstein"
__copyright__   = "Copyright 2017, HEIG-VD"
__license__ 	= "GPL"
__version__ 	= "1.0"
__email__ 		= "abraham.rubinstein@heig-vd.ch"
__status__ 		= "Prototype"

from scapy.all import *
import binascii
import rc4

# wep key AA:AA:AA:AA:AA
key='\xaa\xaa\xaa\xaa\xaa'

# We read the original encrypted message from the wireshark file - rdpcap always returns an array, even if the pcap only contains one frame
arp = wrpcap('arp.cap')[0]
arp_encryp = wrpcap('arp_encrypt.cap')



# I recover the ICV from the message (arp.icv). This is a long integer
# Wireshark likes to show this number in hex. And even if Wireshark knows the correct key and
# can decrypt the ICV, it will show the encrypted version only.

# I convert the icv to hex using '{:x}.format and then to it's ascii representation using decode("hex")
# This conversion is requiered by the rc4 implementation we are using.


# 0. Initialization (generate IV and payload)
iv = random.randint(0,2**24)
payload = b"aaaa03000000080600010800060400019027e4ea61f2c0a80164000000000000c0a801c8"


# 1. Calculate the CRC (A.K.A ICV) over the data payload
crc = binascii.crc32(payload)

# 2. Concatenate the ICV to the end of the data
data = payload + crc

# 3. Concatenate the 24 bits IV with shared key (40 bits or 104 bits)
#    to create the RC4 seed.
seed = arp.iv+key 

# 4. Generate a pseudo-random sequence with the same length as (payload + ICV). 
#    We call this the keystream 


# 5. Calculate the XOR of the keystream with the (payload + ICV)
rc4.rc4crypt(data, seed)
# 6. Add the IV to the beginning of the frame

# 7. Send frame as a normal frame






# icv_encrypted='{:x}'.format(arp.icv).decode("hex")

print 'icv as shown by Wireshark (encrypted): '+'{:x}'.format(arp.icv)

# Encrypted text including the icv. You need to produce this if you want to decrypt the ICV

message_encrypted=arp.wepdata+icv_encrypted 

# Decryption using rc4
cleartext=rc4.rc4crypt(message_encrypted,seed)  

# The ICV the last 4 bytes - I convert it to Long big endian using unpack
icv_unencrypted=cleartext[-4:]

# Extract the long value only.
(icv_numerique,)=struct.unpack('!L', icv_unencrypted)

# The payload is the messge minus the 4 last bytes
text_unencrypted=cleartext[:-4] 

print 'Unencrypted Message: ' + text_unencrypted.encode("hex")
print 'Unencrypte icv (hex):  ' + icv_unencrypted.encode("hex")
print 'Numerical value of icv: ' + str(icv_numerique)
