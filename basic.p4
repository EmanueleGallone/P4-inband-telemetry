/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV4 = 0x800;
const bit<8> IP_PROTO = 253;

#define MAX_HOPS 10
#define CONTROLLER_PORT 255


/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/


typedef bit<48> macAddr_t;
typedef bit<32> ipv4Addr_t;

typedef bit<31>  switchID_t;
typedef bit<9>   ingress_port_t;
typedef bit<9>   egress_port_t;
typedef bit<9>   egressSpec_t;
typedef bit<48>  ingress_global_timestamp_t;
typedef bit<48>  egress_global_timestamp_t;
typedef bit<32>  enq_timestamp_t;
typedef bit<19>  enq_qdepth_t;
typedef bit<32>  deq_timedelta_t;
typedef bit<19>  deq_qdepth_t;

header ethernet_h {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header ipv4_h {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    diffserv;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ipv4Addr_t srcAddr;
    ipv4Addr_t dstAddr;
}

@controller_header("packet_out")
header packet_out_header_t {
    egress_port_t egress_port;
    bit<7> _pad;
}

@controller_header("packet_in")
header packet_in_header_t {
    ingress_port_t ingress_port;
    bit<7> _pad;
}

header nodeCount_h{
    bit<16>  count;
}

header InBandNetworkTelemetry_h {
    switchID_t swid;
    ingress_port_t ingress_port;
    egress_port_t egress_port;
    egressSpec_t egress_spec;
    ingress_global_timestamp_t ingress_global_timestamp;
    egress_global_timestamp_t egress_global_timestamp;
    enq_timestamp_t enq_timestamp;
    enq_qdepth_t enq_qdepth;
    deq_timedelta_t deq_timedelta;
    deq_qdepth_t deq_qdepth;
}

struct ingress_metadata_t {
    bit<16>  count;
}

struct parser_metadata_t {
    bit<16>  remaining;
}

struct metadata {
    ingress_metadata_t   ingress_metadata;
    parser_metadata_t    parser_metadata;
}

struct headers_t {
    packet_out_header_t                packet_out;
    packet_in_header_t                 packet_in;
    ethernet_h                         ethernet;
    ipv4_h                             ipv4;
    nodeCount_h                        nodeCount;
    InBandNetworkTelemetry_h[MAX_HOPS] INT;
}

error {
    IPv4IncorrectVersion,
    IPv4OptionsNotSupported
}

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser MyParser(packet_in packet,
                out headers_t hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        transition select(standard_metadata.ingress_port) {
        	CONTROLLER_PORT: parse_controller_packet_out;
        	default:	     parse_ethernet;
        }
    }

    state parse_controller_packet_out {
    	packet.extract(hdr.packet_out);
    	transition accept;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_IPV4: parse_ipv4;
            default:   accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol){
            IP_PROTO: parse_count;
            default:  accept;
        }
    }

    state parse_count{
        packet.extract(hdr.nodeCount);
        meta.parser_metadata.remaining = hdr.nodeCount.count;
        transition select(meta.parser_metadata.remaining) {
            0 :      accept;
            default: parse_int;
        }
    }

    state parse_int {
        packet.extract(hdr.INT.next);
        meta.parser_metadata.remaining = meta.parser_metadata.remaining  - 1;
        transition select(meta.parser_metadata.remaining) {
            0 :      accept;
            default: parse_int;
        }
    }
}   
/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers_t hdr, inout metadata meta) {   
    apply {  }
}


/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers_t hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {
    action drop() {
        mark_to_drop(standard_metadata);
    }

    action send_to_controller() {
    	standard_metadata.egress_spec = CONTROLLER_PORT;
    }

    action ethernet_forward(macAddr_t dstAddr) {
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
    }

    action local_breakout(ipv4Addr_t dstAddr){
        // TODO is this the best way to perform a local breakout?
        hdr.ipv4.dstAddr = dstAddr;
    }
    
    action ipv4_forward(macAddr_t dstAddr, egressSpec_t port) {
        standard_metadata.egress_spec = port;
        ethernet_forward(dstAddr);

        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
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
        size = 1024;
        default_action = NoAction();
    }

    table ipv4_local_breakout {
        key = {
            hdr.ipv4.srcAddr: exact;
            hdr.ipv4.dstAddr: exact;
        }
        actions = {
            local_breakout;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = NoAction();

    }

     table dbg_table {
        key = {
            standard_metadata.ingress_port : exact;
            standard_metadata.egress_spec : exact;
            standard_metadata.egress_port : exact;
            hdr.ipv4.srcAddr : exact;
            hdr.ipv4.dstAddr : exact;
        }
        actions = { NoAction; }
        const default_action = NoAction();
    }

    
    apply {
        if (standard_metadata.ingress_port == CONTROLLER_PORT) {
            standard_metadata.egress_spec = (egress_port_t)hdr.packet_out.egress_port;
            hdr.packet_out.setInvalid();
            exit; // no need to further execute the pipeline
        }

        if (hdr.ipv4.isValid()) {
            dbg_table.apply();

            // check whether should perform local breakout
            ipv4_local_breakout.apply();

            if (ipv4_lpm.apply().hit) {
            }
            else { // miss
            	send_to_controller();
            }
        }
    } // end of apply section
} //end of MyIngress

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers_t hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {

    action add_swtrace(switchID_t swid) {
        hdr.nodeCount.count = hdr.nodeCount.count + 1;
        hdr.INT.push_front(1);
        hdr.INT[0].setValid();
        hdr.INT[0].swid = swid;
        hdr.INT[0].ingress_port = (ingress_port_t)standard_metadata.ingress_port;
        hdr.INT[0].ingress_global_timestamp = (ingress_global_timestamp_t)standard_metadata.ingress_global_timestamp;
        hdr.INT[0].egress_port = (egress_port_t)standard_metadata.egress_port;
        hdr.INT[0].egress_spec = (egressSpec_t)standard_metadata.egress_spec;
        hdr.INT[0].egress_global_timestamp = (egress_global_timestamp_t)standard_metadata.egress_global_timestamp;
        hdr.INT[0].enq_timestamp = (enq_timestamp_t)standard_metadata.enq_timestamp;
        hdr.INT[0].enq_qdepth = (enq_qdepth_t)standard_metadata.enq_qdepth;
        hdr.INT[0].deq_timedelta = (deq_timedelta_t)standard_metadata.deq_timedelta;
        hdr.INT[0].deq_qdepth = (deq_qdepth_t)standard_metadata.deq_qdepth;
        
        hdr.ipv4.totalLen = hdr.ipv4.totalLen + 32;
    }

    action set_packet_in_data() {
            hdr.packet_in.setValid();
            hdr.packet_in.ingress_port = standard_metadata.ingress_port;
    }

    table swtrace {
        actions = { 
	        add_swtrace; 
	        NoAction; 
        }
        default_action = NoAction();      
    }

     table dbg_table {
        key = {
            standard_metadata.ingress_port : exact;
            standard_metadata.egress_spec : exact;
            standard_metadata.egress_port : exact;
            hdr.ipv4.srcAddr : exact;
            hdr.ipv4.dstAddr : exact;
        }
        actions = { NoAction; }
        const default_action = NoAction();
    }
    
    apply {
        if (hdr.nodeCount.isValid()) {
            swtrace.apply();
        }
        if (standard_metadata.egress_port == CONTROLLER_PORT) {
            set_packet_in_data();
            dbg_table.apply();
        }
    } 
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers_t hdr, inout metadata meta) {
     apply {
	update_checksum(
	    hdr.ipv4.isValid(),
            { hdr.ipv4.version,
	      hdr.ipv4.ihl,
              hdr.ipv4.diffserv,
              hdr.ipv4.totalLen,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.fragOffset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16);
    }
}

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers_t hdr) {
    apply {
        packet.emit(hdr.packet_in);
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.nodeCount);
        packet.emit(hdr.INT);                 
    }
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;
