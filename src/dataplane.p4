#include <core.p4>
#include <v1model.p4>

/* ---------- Constants ---------- */

const bit<16> TYPE_IPV4 = 0x0800;

const bit<8> PROTO_ICMP = 1;
const bit<8> PROTO_TCP  = 6;
const bit<8> PROTO_UDP  = 17;

const bit<3> CLASS_OTHER       = 0;
const bit<3> CLASS_INTERACTIVE = 1;
const bit<3> CLASS_WEB         = 2;
const bit<3> CLASS_UDP_SERVICE = 3;


/* ---------- Headers ---------- */

header ethernet_t {
    bit<48> dstAddr;
    bit<48> srcAddr;
    bit<16> etherType;
}

header ipv4_t {
    bit<4>  version;
    bit<4>  ihl;
    bit<8>  diffserv;
    bit<16> totalLen;
    bit<16> identification;
    bit<3>  flags;
    bit<13> fragOffset;
    bit<8>  ttl;
    bit<8>  protocol;
    bit<16> hdrChecksum;
    bit<32> srcAddr;
    bit<32> dstAddr;
}

header tcp_ports_t {
    bit<16> srcPort;
    bit<16> dstPort;
}

header udp_ports_t {
    bit<16> srcPort;
    bit<16> dstPort;
}

header icmp_base_t {
    bit<8>  type;
    bit<8>  code;
    bit<16> checksum;
}


/* ---------- Structures ---------- */

struct headers {
    ethernet_t ethernet;
    ipv4_t ipv4;
    tcp_ports_t tcp;
    udp_ports_t udp;
    icmp_base_t icmp;
}

struct metadata {
    bit<3> traffic_class;
    bit<1> policy_drop;
}


/* ---------- Parser ---------- */

parser MyParser(
    packet_in packet,
    out headers hdr,
    inout metadata meta,
    inout standard_metadata_t standard_metadata)
{
    state start {
        packet.extract(hdr.ethernet);

        transition select(hdr.ethernet.etherType) {
            TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);

        transition select(hdr.ipv4.protocol) {
            PROTO_ICMP: parse_icmp;
            PROTO_TCP:  parse_tcp;
            PROTO_UDP:  parse_udp;
            default: accept;
        }
    }

    state parse_tcp {
        packet.extract(hdr.tcp);
        transition accept;
    }

    state parse_udp {
        packet.extract(hdr.udp);
        transition accept;
    }

    state parse_icmp {
        packet.extract(hdr.icmp);
        transition accept;
    }
}


/* ---------- Checksum verification ---------- */

control MyVerifyChecksum(
    inout headers hdr,
    inout metadata meta)
{
    apply {
        verify_checksum(
            hdr.ipv4.isValid(),
            {
                hdr.ipv4.version,
                hdr.ipv4.ihl,
                hdr.ipv4.diffserv,
                hdr.ipv4.totalLen,
                hdr.ipv4.identification,
                hdr.ipv4.flags,
                hdr.ipv4.fragOffset,
                hdr.ipv4.ttl,
                hdr.ipv4.protocol,
                hdr.ipv4.srcAddr,
                hdr.ipv4.dstAddr
            },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16
        );
    }
}


/* ---------- Ingress pipeline ---------- */

control MyIngress(
    inout headers hdr,
    inout metadata meta,
    inout standard_metadata_t standard_metadata)
{
    action drop() {
        mark_to_drop(standard_metadata);
    }

    action policy_deny() {
        meta.policy_drop = 1;
        mark_to_drop(standard_metadata);
    }

    action policy_allow() {
        meta.policy_drop = 0;
    }

    table firewall {
        key = {
            hdr.ipv4.srcAddr: ternary;
            hdr.ipv4.dstAddr: ternary;
        }

        actions = {
            policy_deny;
            policy_allow;
            NoAction;
        }

        size = 32;
        default_action = policy_allow();
    }


    action set_class(bit<3> class_id) {
        meta.traffic_class = class_id;
    }

    table tcp_classifier {
        key = {
            hdr.tcp.dstPort: exact;
        }

        actions = {
            set_class;
            NoAction;
        }

        size = 16;
        default_action = set_class(CLASS_OTHER);
    }


    action set_dscp(bit<6> dscp) {
        hdr.ipv4.diffserv = dscp ++ 2w0;
    }

    table qos_marking {
        key = {
            meta.traffic_class: exact;
        }

        actions = {
            set_dscp;
            NoAction;
        }

        size = 8;
        default_action = set_dscp(0);
    }


    action ipv4_forward(
        bit<48> dst_mac,
        bit<48> src_mac,
        bit<9> port)
    {
        hdr.ethernet.dstAddr = dst_mac;
        hdr.ethernet.srcAddr = src_mac;

        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
        standard_metadata.egress_spec = port;
    }

    table ipv4_lpm {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }

        actions = {
            ipv4_forward;
            drop;
            NoAction;
        }

        size = 32;
        default_action = drop();
    }


    apply {
        meta.policy_drop = 0;
        meta.traffic_class = CLASS_OTHER;

        if (!hdr.ipv4.isValid()) {
            drop();
        } else if (hdr.ipv4.ttl <= 1) {
            drop();
        } else {
            firewall.apply();

            if (meta.policy_drop == 0) {
                if (hdr.icmp.isValid()) {
                    meta.traffic_class = CLASS_INTERACTIVE;
                } else if (hdr.tcp.isValid()) {
                    tcp_classifier.apply();
                } else if (hdr.udp.isValid()) {
                    meta.traffic_class = CLASS_UDP_SERVICE;
                } else {
                    meta.traffic_class = CLASS_OTHER;
                }

                qos_marking.apply();
                ipv4_lpm.apply();
            }
        }
    }
}


/* ---------- Egress ---------- */

control MyEgress(
    inout headers hdr,
    inout metadata meta,
    inout standard_metadata_t standard_metadata)
{
    apply {
    }
}


/* ---------- Checksum recomputation ---------- */

control MyComputeChecksum(
    inout headers hdr,
    inout metadata meta)
{
    apply {
        update_checksum(
            hdr.ipv4.isValid(),
            {
                hdr.ipv4.version,
                hdr.ipv4.ihl,
                hdr.ipv4.diffserv,
                hdr.ipv4.totalLen,
                hdr.ipv4.identification,
                hdr.ipv4.flags,
                hdr.ipv4.fragOffset,
                hdr.ipv4.ttl,
                hdr.ipv4.protocol,
                hdr.ipv4.srcAddr,
                hdr.ipv4.dstAddr
            },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16
        );
    }
}


/* ---------- Deparser ---------- */

control MyDeparser(packet_out packet, in headers hdr)
{
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.tcp);
        packet.emit(hdr.udp);
        packet.emit(hdr.icmp);
    }
}


/* ---------- Main ---------- */

V1Switch(
    MyParser(),
    MyVerifyChecksum(),
    MyIngress(),
    MyEgress(),
    MyComputeChecksum(),
    MyDeparser()
) main;
