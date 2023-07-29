#!/usr/bin/env python

import sys

if len(sys.argv) < 2:
    print("Usage: decode_bufinfo.py <APDUResultAsHex>")
    sys.exit(1)

s = sys.argv[1]

b = bytes.fromhex(s)

def chop(x, amt):
    return x[amt:]

def short_as(x, desc):
    v = int.from_bytes(x[:2], byteorder='big', signed=True)
    print("%s: %d" % (desc, v))
    return chop(x, 2)

def check_transient(x, desc):
    if x[0] == 0:
        print("%s: PERSISTENT" % desc)
    elif x[0] == 2:
        print("%s: transient" % desc)
    else:
        print("%s: UNKNOWN" % desc)
    return chop(x, 1)

def check_type(x, desc, not_a_transient, transient_reset, transient_deselect):
    if x[0] == not_a_transient:
        print("%s: PERSISTENT" % desc)
    elif x[0] == transient_deselect:
        print("%s: transient" % desc)
    elif x[0] == transient_reset:
        print("%s: transient_RESET" % desc)
    else:
        print("%s: UNKNOWN" % desc)

    return chop(x, 1)

if b[0:2] != b'\xFE\xFF':
    print("Invalid APDU result")
    sys.exit(1)

b = chop(b, 2)
b = short_as(b, "APDU Buffer Length")
not_a_transient = b[0]
b = chop(b, 1)
transient_reset = b[0]
b = chop(b, 1)
transient_deselect = b[0]
b = chop(b, 1)
b = check_transient(b, "Authenticator Key Agreement Key")
b = check_transient(b, "Credential Key")
b = check_type(b, "PIN Token", not_a_transient, transient_reset, transient_deselect)
b = check_type(b, "Shared Secret Verify Key", not_a_transient, transient_reset, transient_deselect)
b = check_type(b, "Permissions RP ID", not_a_transient, transient_reset, transient_deselect)
b = check_transient(b, "Shared Secret AES Key")
b = check_transient(b, "PIN Wrapping Key")
b = check_type(b, "Request/Response Buffer Memory", not_a_transient, transient_reset, transient_deselect)
b = short_as(b, "Transient Scratch Buffer Size")
b = short_as(b, "Persistent Memory Remaining")
b = short_as(b, "Transient Reset Memory Remaining")
b = short_as(b, "Transient Deselect Memory Remaining")

if b[0:2] != b'\xFE\xFF':
    print("Invalid APDU result")
    sys.exit(1)
