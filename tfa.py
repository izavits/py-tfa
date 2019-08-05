#!/usr/bin/env python
import base64
import hashlib
import hmac
import os
import time
import struct

appName = "TwoFactorAuthExample"

def newSecret():
    return base64.b32encode(os.urandom(10))

def getQRLink(name, secret):
    return "https://chart.googleapis.com/chart?chs=200x200&chld=M|0&cht=qr&chl=otpauth://totp/%s@%s?secret=%s"%(name, appName, secret)

def auth(secret, nstr):
    # raise if nstr contains anything but numbers
    int(nstr)
    tm = int(time.time() / 30)
    secret = base64.b32decode(secret)
    # try 30 seconds behind and ahead as well
    for ix in [-1, 0, 1]:
        # convert timestamp to raw bytes
        b = struct.pack(">q", tm + ix)
        # generate HMAC-SHA1 from timestamp based on secret key
        hm = hmac.HMAC(secret, b, hashlib.sha1).digest()
        # extract 4 bytes from digest based on LSB
        offset = ord(hm[-1]) & 0x0F
        truncatedHash = hm[offset:offset+4]
        # get the code from it
        code = struct.unpack(">L", truncatedHash)[0]
        code &= 0x7FFFFFFF;
        code %= 1000000;
        if ("%06d" % code) == nstr:
            return True
    return False

def main():
    name = raw_input("Hi! What's your name? ")
    pw = raw_input("What's your password? ")
    secret = newSecret() # store this with the other account information
    link = getQRLink(name, secret)
    print("Please scan this QR code with the Google Authenticator app:\n{0}\n".format(link))
    print("For installation instructions, see http://support.google.com/accounts/bin/answer.py?hl=en&answer=1066447")
    print("\n---\n")

    # Authentication
    opw = raw_input("Hi {0}! What's your password again? ".format(name))
    if opw != pw:
        print("Sorry, that's not the right password.")
    else:
        code = raw_input("Please enter your authenticator code: ")
        if auth(secret, code):
            print("Successfully authenticated! Score!")
        else:
            print("Sorry, that's a fail.")

if __name__ == "__main__":
    main()
