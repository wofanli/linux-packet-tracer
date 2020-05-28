# linux-packet-tracer
```
~/tracer
 
>>> help
 
Commands:
  clear             clear the screen
  debug             set debue level (debug, info, warn, error)
  dst               dst ip, like 1.2.3.0/24
  exit              exit the program
  help              display help
  max_duration      set max seconds to keep tracing, (1~60)
  max_pkt           set max pkt to cached, (1~2048)
  restart           restart packet tracing
  show              show the output
  src               src ip, like 1.2.3.0/24
  start             start to trace packet
  wait              wait until the tracing ends
 

root@vpe2:~# ~/tracer
Welcome to Packet Tracing for Linux
>>> show config   
match rules:
    dst: 0.0.0.0/0, src: 0.0.0.0/0
tracer parameters:
    debug level:info
    max packets: 512
    max duration: 5s
>>> start 
2017/05/30 17:12:24.798522 [INFO] tethrnet.com/packet-trace/agg/agg.go:135: Agg Run starts
>>> write(-:kprobes/-:kprobes/p_skb_release_all_bcc_7641): No such file or directory
write(-:kprobes/-:kprobes/p_consume_skb_bcc_7641): No such file or directory
write(-:kprobes/-:kprobes/p_napi_consume_skb_bcc_7641): No such file or directory
write(-:kprobes/-:kprobes/p_nf_hook_slow_bcc_7641): No such file or directory
write(-:kprobes/-:kprobes/r_nf_hook_slow_bcc_7641): No such file or directory
write(-:kprobes/-:kprobes/p_ip_finish_output_bcc_7641): No such file or directory
write(-:kprobes/-:kprobes/p_kfree_skb_partial_bcc_7641): No such file or directory
write(-:kprobes/-:kprobes/p_ip_rcv_bcc_7641): No such file or directory
write(-:kprobes/-:kprobes/p_ip_rcv_finish_bcc_7641): No such file or directory
write(-:kprobes/-:kprobes/p_ip_forward_bcc_7641): No such file or directory
write(-:kprobes/-:kprobes/r_fib_validate_source_bcc_7641): No such file or directory
write(-:kprobes/-:kprobes/p_ip_route_input_noref_bcc_7641): No such file or directory
write(-:kprobes/-:kprobes/p_ip_queue_xmit_bcc_7641): No such file or directory
write(-:kprobes/-:kprobes/p_ipt_do_table_bcc_7641): No such file or directory
write(-:kprobes/-:kprobes/r_ipt_do_table_bcc_7641): No such file or directory
write(-:kprobes/-:kprobes/p_kfree_skb_bcc_7641): No such file or directory
write(-:kprobes/-:kprobes/p_ip_forward_finish_bcc_7641): No such file or directory
write(-:kprobes/-:kprobes/p_fib_validate_source_bcc_7641): No such file or directory
write(-:kprobes/-:kprobes/r_ip_route_input_noref_bcc_7641): No such file or directory
2017/05/30 17:12:30.517616 [INFO] tethrnet.com/packet-trace/gluer/gluer.go:192: agger stoped 
>>> 
>>> show summary 
The number of packets we traced is: 18
>>> show 1 
0,kprobe__ip_rcv:
    222.186.19.243->10.128.0.9, tos:0x0, ttl:55, protocol:UDP(0x11), total_len:160  
1,kprobe__nf_hook_slow:
    Will check NFPROTO_IPV4(2), NF_INET_PRE_ROUTING(0), In_intf:eth0, Out_intf:unknown
2,kretprobe__nf_hook_slow:
    NFPROTO_IPV4(2), NF_INET_PRE_ROUTING(0), check done, PASS
3,kprobe__ip_rcv_finish:
    PRE_ROUTING check passed, UDP(0x11)
4,kretprobe__fib_validate_source:
    rp_filter check: src(222.186.19.243), iif(eth0),  PASS <— rp filter 过了
5,kretprobe__ip_route_input_noref:
    ip route lookup: dst(10.128.0.9), src(222.186.19.243), iif(eth0),  found route
6,kprobe__nf_hook_slow:
    Will check NFPROTO_IPV4(2), NF_INET_LOCAL_IN(1), In_intf:eth0, Out_intf:unknown
7,kprobe__ipt_do_table:
    Will check filter, NFPROTO_IPV4(2), NF_INET_LOCAL_IN(1), In_intf:eth0, Out_intf:unknown
8,kretprobe__ipt_do_table:
    filter, NFPROTO_IPV4(2), NF_INET_LOCAL_IN(1), check done, NF_ACCEPT(1)
9,kretprobe__nf_hook_slow:
    NFPROTO_IPV4(2), NF_INET_LOCAL_IN(1), check done, PASS
10,kprobe__ip_rcv:
    10.253.0.1->10.253.0.2, tos:0x0, ttl:64, protocol:ICMP(0x1), total_len:92 
11,kprobe__nf_hook_slow:
    Will check NFPROTO_IPV4(2), NF_INET_PRE_ROUTING(0), In_intf:vti2_1, Out_intf:unknown
12,kretprobe__nf_hook_slow:
    NFPROTO_IPV4(2), NF_INET_PRE_ROUTING(0), check done, PASS
13,kprobe__ip_rcv_finish:
    PRE_ROUTING check passed, ICMP(0x1), Echo Reply(0)(code:0)
14,kretprobe__fib_validate_source:
    rp_filter check: src(10.253.0.1), iif(vti2_1),  PASS
15,kretprobe__ip_route_input_noref:
    ip route lookup: dst(10.253.0.2), src(10.253.0.1), iif(vti2_1),  found route
16,kprobe__nf_hook_slow:
    Will check NFPROTO_IPV4(2), NF_INET_LOCAL_IN(1), In_intf:vti2_1, Out_intf:unknown
17,kprobe__ipt_do_table:
    Will check filter, NFPROTO_IPV4(2), NF_INET_LOCAL_IN(1), In_intf:vti2_1, Out_intf:unknown
18,kretprobe__ipt_do_table:
    filter, NFPROTO_IPV4(2), NF_INET_LOCAL_IN(1), check done, NF_ACCEPT(1)
19,kretprobe__nf_hook_slow:
    NFPROTO_IPV4(2), NF_INET_LOCAL_IN(1), check done, PASS
20,kprobe__kfree_skb: 
    Dropped or Skb destroyed
```
