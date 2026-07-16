# Test Evidence

## Forwarding and policy logs

- `allow-h1-h2.txt`: student-to-student forwarding is allowed.
- `allow-h3-h5.txt`: staff-to-admin forwarding is allowed.
- `allow-h4-h6.txt`: research-to-external forwarding is allowed.
- `deny-h1-h5.txt`: student-to-admin traffic is blocked.
- `deny-h6-h5.txt`: additional external-to-admin policy is blocked.
- `drop-ttl1.txt`: packets with TTL=1 are dropped.
- `drop-unknown.txt`: unknown IPv4 destinations are dropped.

## QoS packet captures

- `interactive-icmp.pcap`: ICMP, DSCP 46.
- `web-http.pcap`: TCP destination port 80, DSCP 34.
- `udp-service.pcap`: UDP destination port 5000, DSCP 26.
- `other-bulk.pcap`: TCP destination port 9000, DSCP 0.

Forwarded packets observed at the destination have TTL 63, confirming
that the switch decrements TTL from its initial value of 64.
