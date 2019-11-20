#!/usr/bin/env python3
"""
SPDX-License-Identifier: MIT
Copyright 2019 sysmocom s.f.m.c GmbH <info@sysmocom.de>

This is a freeswitch dialplan implementation, see:
https://freeswitch.org/confluence/display/FREESWITCH/mod_python

Find the right SIP server with mslookup (depending on the destination number)
and bridge calls accordingly.
"""
import json
import subprocess


def query_mslookup(service_type, id, id_type='msisdn'):
    query_str = '%s.%s.%s' % (service_type, id, id_type)
    print('[dialplan-dgsm] mslookup: ' + query_str)

    result_line = subprocess.check_output([
        'osmo-mslookup-client', query_str, '-f', 'json'])
    if isinstance(result_line, bytes):
        result_line = result_line.decode('ascii')

    print('[dialplan-dgsm] mslookup result: ' + result_line)
    return json.loads(result_line)


def handler(session, args):
    """ Handle calls: bridge to the SIP server found with mslookup. """
    print('[dialplan-dgsm] call handler')
    msisdn = session.getVariable('destination_number')

    # Run osmo-mslookup-client binary. We have also tried to directly call the
    # C functions with ctypes but this has lead to hard-to-debug segfaults.
    try:
        result = query_mslookup("sip.voice", msisdn)

        # This example only makes use of IPv4
        if not result['v4']:
            print('[dialplan-dgsm] no IPv4 result from mslookup')
            session.hangup('UNALLOCATED_NUMBER')
            return

        sip_ip, sip_port = result['v4']
        dial_str = 'sofia/internal/sip:{}@{}:{}'.format(
            msisdn, sip_ip, sip_port)
        print('[dialplan-dgsm] dial_str: ' + str(dial_str))

        session.execute('bridge', dial_str)
    except:
        print('[dialplan-dgsm]: exception during call handler')
        session.hangup('UNALLOCATED_NUMBER')


def fsapi(session, stream, env, args):
    """ Freeswitch refuses to load the module without this. """
    stream.write(env.serialize())


def main():
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument('id', type=int)
    parser.add_argument('-i', '--id-type', default='msisdn',
                        help='default: "msisdn"')
    parser.add_argument('-s', '--service', default='sip.voice',
                        help='default: "sip.voice"')
    args = parser.parse_args()

    result = query_mslookup(args.service, args.id, args.id_type)
    print(json.dumps(result))


if __name__ == '__main__':
    main()
