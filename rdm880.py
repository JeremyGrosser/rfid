class Packet(object):
    def __init__(self, cmd=None, data=[], stationid=0x00):
        self.stationid = stationid
        self.cmd = cmd
        self.data = data
        self.length = None
        self.status = None
        self.bcc = None

    def build(self, debug=False):
        self.msgtype = 'command'

        pack = {
            'stationid': chr(self.stationid),
            'cmd': chr(self.cmd),
            'data': ''.join([chr(x) for x in self.data]),
        }
        pack['length'] = chr(len(pack['data']) + 1)
        pack['bcc'] = self.stationid ^ ord(pack['length']) ^ self.cmd
        for c in self.data:
            pack['bcc'] ^= c
        pack['bcc'] = chr(pack['bcc'])

        raw = '\xaa%(stationid)s%(length)s%(cmd)s%(data)s%(bcc)s\xbb' % pack

        if debug:
            for k, v in pack.items():
                print k.ljust(20, ' '), ' '.join(['%02x' % ord(x) for x in v])
            print 'raw'.ljust(20, ' '), ' '.join(['%02X' % ord(x) for x in raw])
        return raw

    def parse(self, raw):
        self.msgtype = 'reply'

        raw = [ord(x) for x in raw]
        if raw[0] != 0xAA or raw[-1] != 0xBB:
            print 'Missing STX or ETX'
            return None
        raw = raw[1:-1]

        self.stationid, self.length, self.status = raw[:3]
        raw = raw[4:]
        self.data = raw[:self.length - 2]
        raw = raw[self.length - 2:]
        self.bcc = raw[0]
        if len(raw) > 1:
            print 'Length did not match packet size!'
            return None

    def __str__(self):
        ret = 'msgtype        %s\n' % self.msgtype
        if self.msgtype == 'command':
            ret += 'stationid      %02X\n' % self.stationid
            ret += 'cmd            %02X\n' % self.cmd
            ret += 'data           %s\n' % ' '.join(['%02X' % x for x in self.data])
        else:
            ret += 'stationid      %02X\n' % self.stationid
            ret += 'length         %02X\n' % self.length
            ret += 'status         %02X (%s)\n' % (self.status, Status.get(self.status, 'Unknown status code'))
            ret += 'data           %s\n' % ' '.join(['%02X' % x for x in self.data])
            ret += 'bcc            %02X\n' % self.bcc
        return ret.rstrip('\n')

    def execute(self, io):
        raw = self.build()
        io.write(raw)

        raw = io.read(3)
        length = ord(raw[2])
        raw += io.read(length + 2)

        p = Packet()
        p.parse(raw)
        return p

class CommandSet(object):
    def __init__(self, name, data):
        self.name = name
        self.data = data

    def __getattr__(self, key):
        return self.data[key]

ISO14443A = CommandSet('ISO14443A', {
    'Request':          0x03,
    'Anticollision':    0x04,
    'Select':           0x05,
    'Halt':             0x06,
    'Transfer':         0x28,
})

ISO14443B = CommandSet('ISO14443B', {
    'Request':          0x09,
    'Anticollision':    0x0A,
    'Attrib':           0x0B,
    'Rst':              0x0C,
    'Transfer':         0x0D,
})

Mifare = CommandSet('Mifare', {
    'Read':             0x20,
    'Write':            0x21,
    'InitVal':          0x22,
    'Decrement':        0x23,
    'Increment':        0x24,
    'GetSNR':           0x25,
})

System = CommandSet('System', {
    'SetAddress':       0x80,
    'SetBaudrate':      0x81,
    'SetSerialNumber':  0x82,
    'GetSerialNumber':  0x83,
    'Write_UserInfo':   0x84,
    'Read_UserInfo':    0x85,
    'Get_VersionNum':   0x86,
    'Control_Led1':     0x87,
    'Control_Led2':     0x88,
    'Control_Buzzer':   0x89,
})

ISO15693 = CommandSet('ISO15693', {
    'Inventory':        0x10,
    'Read':             0x11,
    'Write':            0x12,
    'Lockblock':        0x13,
    'StayQuiet':        0x14,
    'Select':           0x15,
    'Resetready':       0x16,
    'Write_AFI':        0x17,
    'Lock_AFI':         0x18,
    'Write_DSFID':      0x19,
    'Lock_DSFID':       0x1A,
    'Get_Information':  0x1B,
    'Get_Multiple_Block_Security': 0x1C,
    'Transfer':         0x1D,
})

Status = {
    0x00:   'Command OK',
    0x01:   'Command failed',
    0x80:   'Set OK',
    0x81:   'Set failed',
    0x82:   'Reader reply timeout',
    0x83:   'Card does not exist',
    0x84:   'The data response from the card is error',
    0x85:   'Invalid command parameter',
    0x87:   'Unknown internal error',
    0x8f:   'Reader received unknown command',
    0x8a:   'ISO14443: Error in InitVal process',
    0x8b:   'ISO14443: Wrong SNR during anticollision loop',
    0x8c:   'ISO14443: Authentication failure',
    0x90:   'ISO15693: The card does not support this command',
    0x91:   'ISO15693: Invalid command format',
    0x92:   'ISO15693: Do not support option mode',
    0x93:   'ISO15693: Block does not exist',
    0x94:   'ISO15693: The object has been locked',
    0x95:   'ISO15693: Lock operation failed',
    0x96:   'ISO15693: Operation failed',
}

