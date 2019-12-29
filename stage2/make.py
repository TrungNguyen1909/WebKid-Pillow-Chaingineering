#!/usr/bin/env python

import subprocess

EXPORTS = [
        {'path': 'stage2_macOS.bin',                        'content_type': 'application/octet-stream'},
]

# Build payload
#subprocess.check_call(['clang', '-nostdlib', '-static', 'stage2_macOS.S', '-o', 'stage2_macOS.o'])
#subprocess.check_call(['/usr/local/opt/binutils/bin/gobjcopy', '-O', 'binary', 'stage2_macOS.o', 'stage2_macOS.bin'])
subprocess.run(['nasm', '-o', 'stage2_macOS.bin', 'stage2_macOS.S'], check=True)
'''
# Delete the generated source and binary
subprocess.check_call(['rm', 'stage2_macOS.S'])
subprocess.check_call(['rm', 'stage2_macOS.o'])
'''
