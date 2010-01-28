from serial import Serial
from rdm880 import *

io = Serial('/dev/ttyUSB0', 115200, timeout=1)

p = Packet(ISO15693.Inventory)
reply = p.execute(io)
print reply
