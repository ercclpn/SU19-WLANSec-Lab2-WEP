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
trame_template = rdpcap('arp.cap')[0]

# I recover the ICV from the message (arp.icv). This is a long integer
# Wireshark likes to show this number in hex. And even if Wireshark knows the correct key and
# can decrypt the ICV, it will show the encrypted version only.

# I convert the icv to hex using '{:x}.format and then to it's ascii representation using decode("hex")
# This conversion is requiered by the rc4 implementation we are using.


# 0. Initialization (generate IV and payload)
iv = random.randint(0,2**24)
iv = struct.pack("i",iv)
payload = b"aaaa03000000080600010800060400019027e4ea61f2c0a80164000000000000c0a801c8"
trame_template.wepdata = ""

# 1. Calculate the CRC (A.K.A ICV) over the data payload
crc = binascii.crc32(payload)

# 2. Concatenate the ICV to the end of the data
trame_template.icv = crc
data = payload + str(crc)
# 3. Concatenate the 24 bits IV with shared key (40 bits or 104 bits)
#    to create the RC4 seed.
seed = iv+key 

# 4. Generate a pseudo-random sequence with the same length as (payload + ICV). 
#    We call this the keystream (rc4.py manage this task) 


# 5. Calculate the XOR of the keystream with the (payload + ICV)
trame_template.wepdata = rc4.rc4crypt(data, seed)

# 6. Add the IV to the beginning of the frame
trame_template.iv = iv

# 7. Send frame as a normal frame
print "test"
wrpcap("arp_test.cap",trame_template)
