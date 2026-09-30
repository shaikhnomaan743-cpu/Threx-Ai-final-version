import struct, os
p = r'C:\Users\shaik\.cline\data\sessions\session_1790475217011_a2lie\user-attachments\b839789b-7ffb-4ac0-86ce-0a5a7af153e3-.pptx'
d = open(p,'rb').read()
i = d.rfind(b'PK\x05\x06')
print('EOCD at', i, 'filesize', len(d))
if i>=0:
    print('EOCD bytes:', d[i:i+22].hex(' '))
    sig, disk, cddisk, n_this, n_tot, cd_size, cd_off, clen = struct.unpack('<IHHHHIIH', d[i:i+22])
    print('n_tot', n_tot, 'cd_size', cd_size, 'cd_off', cd_off, 'comment_len', clen)
    print('cd_off points at:', d[cd_off:cd_off+4].hex(' '))
    print('expected cd at file end-ish:', len(d)-22-cd_size)
