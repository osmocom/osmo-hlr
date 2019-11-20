#!/usr/bin/env python3
# vim: shiftwidth=4 tabstop=4 expandtab
import subprocess
import json

def query_mslookup(query_str):
    result = {'result': 'not-found'}
    proc = subprocess.Popen(('osmo-mslookup-client', '-f', 'json', query_str),
		            stdout=subprocess.PIPE)
    for line in iter(proc.stdout.readline,''):
        if not line:
            break
        response = json.loads(line)
        if response.get('result') == 'result':
                result = response
        print('Response: %r' % response)
    return result

if __name__ == '__main__':
    import sys
    query_str = '1000-5000@sip.voice.12345.msisdn'
    if len(sys.argv) > 1:
        query_str = sys.argv[1]
    print('Final result: %r' % query_mslookup(query_str))
