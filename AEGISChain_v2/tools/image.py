"""ESP32 unsigned Arduino image inspection; hashes only the actual image bytes."""
import hashlib
import struct

def inspect_image(data, payload=False):
    if len(data)<24 or data[0]!=0xe9 or not 1<=data[1]<=16 or data[23]!=1:
        raise ValueError('Invalid/unsupported ESP32 image header (appended hash required)')
    pos=24; checksum=0xef
    for _ in range(data[1]):
        if pos+8>len(data): raise ValueError('Truncated segment header')
        _,size=struct.unpack_from('<II',data,pos);pos+=8
        if size%4 or size>len(data)-pos: raise ValueError('Invalid segment size')
        for value in data[pos:pos+size]: checksum ^= value
        pos+=size
    end=(pos+16)&~15
    if end+32>len(data) or data[end-1]!=checksum: raise ValueError('Invalid image checksum/truncation')
    if hashlib.sha256(data[:end]).digest()!=data[end:end+32]: raise ValueError('Invalid appended image SHA256')
    length=end+32
    result={'length':length,'sha256':hashlib.sha256(data[:length]).hexdigest()}
    if payload:
        if length<0x134 or data[0x120:0x130]!=b'AEGIS-PAYLOAD-2\0': raise ValueError('Missing payload descriptor')
        version=struct.unpack_from('<I',data,0x130)[0]
        if not 1<=version<=2147483647: raise ValueError('Invalid payload version')
        result['version']=version
    return result
