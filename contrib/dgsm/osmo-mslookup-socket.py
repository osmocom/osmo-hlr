#!/usr/bin/env python3
# vim: shiftwidth=4 tabstop=4 expandtab
import socket
import time

MSLOOKUP_SOCKET_PATH = '/tmp/mslookup'

def query_mslookup_socket(query_str, socket_path=MSLOOKUP_SOCKET_PATH):
    mslookup_socket = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    mslookup_socket.setblocking(True)
    mslookup_socket.connect(socket_path)
    result = {'result': 'not-found'}
    column_names = mslookup_socket.recv(1024).decode('ascii')
    if not column_names:
        return result
    column_names = column_names.split('\t')
    mslookup_socket.sendall(query_str.encode('ascii'))
    while True:
        csv = mslookup_socket.recv(1024).decode('ascii')
        if not csv:
            break
        response = dict(zip(column_names, csv.split('\t')))
        if response.get('result') == 'result':
            result = response
        print('Response: %r' % response)
    return result

if __name__ == '__main__':
    import sys
    print(
        '\nPlease run separately: osmo-mslookup-client --socket /tmp/mslookup -d\n')
    query_str = '1000-5000@sip.voice.12345.msisdn'
    if len(sys.argv) > 1:
        query_str = sys.argv[1]
    print('Final result: %r' % query_mslookup_socket(query_str))
