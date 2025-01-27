'''
    binpattern - Extract code patterns on PE for build accurated yaras automatically.

    Recursive find .bin files and get common patterns based only on .text section.
    Ideally it identifies malware code by exluding the binary runtime.

    Usage:
        python3 binpattern.py [folder] [pattern len] [exclude binary]

    For example this will find patterns on the malware at folder/ that are not part of golang runtime, just compile a hello world.
        python3 binpattern.py samples/ 15 gohello.exe

    The more binaries the more slow is the process but more accurate yara pattern.

    sha0coder
'''

import binascii
import pefile
import sys
import os

files = set()
blobs = []

def crawl(path):
    global files

    for f in os.listdir(path):
        pf = path+'/'+f
        if os.path.isdir(pf):
            crawl(pf)
        elif pf.endswith('.bin'):
            global files
            files.add(pf)


def get_code(f):
    try:
        pe = pefile.PE(f)
    except:
        return None

    text_section = None
    for section in pe.sections:
        if section.Name.startswith(b'.text'):
            text_section = section
            break
    if not text_section:
        return None

    return text_section.get_data()


def find_patterns(n, rt):
    b = blobs[0]
    
    for i in range(len(b)-n):
        sys.stdout.write('progress: %d%%\r' % (i*100/len(b)))
        sys.stdout.flush()
        patt = b[i:i+n]
        if not patt or len(patt) < n or patt == b'\x00'*n or patt == b'\xff'*n or patt == b'\xcc'*n:
            continue
        if patt.count(b'\xcc') > 4 or patt.count(b'\x90') > 4 or patt.count(b'\x00') > 4:
            continue
        succ = 0
        for b in blobs:
            r = b.find(patt)
            if r >= 0:
                succ += 1
        if succ > 0:
            if rt.find(patt):
                continue  # the pattern is part of the runtime

            h = binascii.hexlify(patt)
            if succ == len(blobs):
                print(f'{succ} of {len(blobs)} {h} !!!!!!!!!!!')
            else:
                print(f'{succ} of {len(blobs)} {h}')


def main(src, n, runtime):
    global files, blobs
    print('loading ...')
    crawl(src)

    if not files:
        print('no files')
        return

    for f in files:
        c = get_code(f)
        if c:
            blobs.append(c)

    if len(blobs) == 0:
        print('no .text blobs found')
        return

    print(runtime)
    rt = get_code(runtime)
    if not rt:
        print('runtime not valid or not found')
        return

    print(f'loaded {len(blobs)} .text blobs')
    find_patterns(n, rt)


main(sys.argv[1], int(sys.argv[2]), sys.argv[3])



