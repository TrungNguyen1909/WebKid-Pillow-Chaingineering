#!/usr/bin/env python

import subprocess

EXPORTS = [
	{'path': 'stage3_macOS.dylib', 'content_type': 'application/octet-stream'},
]

# Build payload
#subprocess.check_call(['clang', '-nostdlib', '-static', 'stage2_macOS.S', '-o', 'stage2_macOS.o'])
#subprocess.check_call(['/usr/local/opt/binutils/bin/gobjcopy', '-O', 'binary', 'stage2_macOS.o', 'stage2_macOS.bin'])
subprocess.run(['make'], check=True)
'''
# Delete the generated source and binary
subprocess.check_call(['rm', 'stage2_macOS.S'])
subprocess.check_call(['rm', 'stage2_macOS.o'])
'''
