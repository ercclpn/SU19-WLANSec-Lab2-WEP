#!/usr/bin/env python
# -*- coding: utf-8 -*-

""" Manually encrypt a wep message given the WEP key"""

__author__      = "Tran Eric, Sangyoon Cha, Marques Alexandre"
__copyright__   = "Copyright 2019, HEIG-VD"
__license__ 	= "GPL"
__version__ 	= "1.0"
__status__ 		= "Prototype"

from scapy.all import *
import binascii
import rc4

# wep key AA:AA:AA:AA:AA
key='\xaa\xaa\xaa\xaa\xaa'

# We read the original encrypted message from the wireshark file - rdpcap always returns an array, even if the pcap only contains one frame
trame_template = rdpcap('arp.cap')[0]


# Initialization (generate IV and payload)
iv = trame_template.iv # Get the same IV from the original cap file.
payload = "\xaa\xaa\x03\x00\x00\x00\x08\x06\x00\x01\x08\x00\x06\x04\x00\x01\x90'\xe4\xeaa\xf2\xc0\xa8\x01d\x00\x00\x00\x00\x00\x00\xc0\xa8\x01\xc8"
# Calculate the CRC (A.K.A ICV) over the data payload
crc = binascii.crc32(payload)

# Concatenate the ICV to the end of the data
crc_little_endian = struct.pack("<l",crc)
data = payload + crc_little_endian
# Concatenate the 24 bits IV with shared key (40 bits or 104 bits)
# to create the RC4 seed.
seed = iv+key 


# Calculate the XOR of the keystream with the (payload + ICV)
data_encrypt = rc4.rc4crypt(data, seed)

# Extract crc encrypted and unpack using 
crc_big_endian_unpack = struct.unpack("!L",data_encrypt[-4:])


trame_template.wepdata = data_encrypt #store encrypted data in the wepdata field
trame_template.icv = crc_big_endian_unpack[0] #store the extracted icv in the frame

# Add frame in a new cap file
wrpcap("arp_rebuild.cap",trame_template)
