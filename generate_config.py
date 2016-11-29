#!/usr/bin/env python

import sys
count = int(sys.argv[1])
out = sys.argv[2]

if __name__ == '__main__':

    config = '''ifaces: {
 count = %s;
 ids = [
 %s
 ];
}''' % (count, ','.join(['"02:00:00:00:00:%02x"' % i for i in range(1, count+1)]))

    with open(out, "wb") as f:
        f.write(config)