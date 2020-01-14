#include <pcv/rule_parser/rule.h>
#include "classifier-pcv-private.h"

using namespace pcv::rule_vec_format;

using in_packet_position_t = typename PcvClassifier::Search_t::in_packet_position_t;

typename PcvClassifier::formaters_t struct_flow_packet_formaters = {
	 rule_vec_format_ipv4_part,// tunnel.ip_dst-0
	 rule_vec_format_ipv4_part,// tunnel.ip_dst-2
	 rule_vec_format_ipv6_part,// tunnel.ipv6_dst-0
	 rule_vec_format_ipv6_part,// tunnel.ipv6_dst-2
	 rule_vec_format_ipv6_part,// tunnel.ipv6_dst-4
	 rule_vec_format_ipv6_part,// tunnel.ipv6_dst-6
	 rule_vec_format_ipv6_part,// tunnel.ipv6_dst-8
	 rule_vec_format_ipv6_part,// tunnel.ipv6_dst-10
	 rule_vec_format_ipv6_part,// tunnel.ipv6_dst-12
	 rule_vec_format_ipv6_part,// tunnel.ipv6_dst-14
	 rule_vec_format_ipv4_part,// tunnel.ip_src-0
	 rule_vec_format_ipv4_part,// tunnel.ip_src-2
	 rule_vec_format_ipv6_part,// tunnel.ipv6_src-0
	 rule_vec_format_ipv6_part,// tunnel.ipv6_src-2
	 rule_vec_format_ipv6_part,// tunnel.ipv6_src-4
	 rule_vec_format_ipv6_part,// tunnel.ipv6_src-6
	 rule_vec_format_ipv6_part,// tunnel.ipv6_src-8
	 rule_vec_format_ipv6_part,// tunnel.ipv6_src-10
	 rule_vec_format_ipv6_part,// tunnel.ipv6_src-12
	 rule_vec_format_ipv6_part,// tunnel.ipv6_src-14
	 rule_vec_format_default<uint16_t>,// tunnel.tun_id-0
	 rule_vec_format_default<uint16_t>,// tunnel.tun_id-2
	 rule_vec_format_default<uint16_t>,// tunnel.tun_id-4
	 rule_vec_format_default<uint16_t>,// tunnel.tun_id-6
	 rule_vec_format_default<uint16_t>,// tunnel.flags
	 rule_vec_format_default<uint16_t>,// tunnel.ip_tos
	 rule_vec_format_default<uint16_t>,// tunnel.ip_ttl
	 rule_vec_format_default<uint16_t>,// tunnel.tp_src
	 rule_vec_format_default<uint16_t>,// tunnel.tp_dst
	 rule_vec_format_default<uint16_t>,// tunnel.gbp_id
	 rule_vec_format_default<uint16_t>,// tunnel.gbp_flags
	 rule_vec_format_default<uint16_t>,// tunnel.erspan_ver
	 rule_vec_format_default<uint16_t>,// tunnel.erspan_idx-2
	 rule_vec_format_default<uint16_t>,// tunnel.erspan_idx-0
	 rule_vec_format_default<uint16_t>,// tunnel.erspan_dir
	 rule_vec_format_default<uint16_t>,// tunnel.erspan_hwid
	 rule_vec_format_default<uint16_t>,// tunnel.metadata.present-6
	 rule_vec_format_default<uint16_t>,// tunnel.metadata.present-4
	 rule_vec_format_default<uint16_t>,// tunnel.metadata.present-2
	 rule_vec_format_default<uint16_t>,// tunnel.metadata.present-0
	 rule_vec_format_default<uint16_t>,// tunnel.metadata.opts[0]
	 rule_vec_format_default<uint16_t>,// tunnel.metadata.opts[1]
	 rule_vec_format_default<uint16_t>,// tunnel.metadata.opts[2]
	 rule_vec_format_default<uint16_t>,// tunnel.metadata.opts[3]
	 rule_vec_format_default<uint16_t>,// tunnel.metadata.opts[4]
	 rule_vec_format_default<uint16_t>,// tunnel.metadata.opts[5]
	 rule_vec_format_default<uint16_t>,// tunnel.metadata.opts[6]
	 rule_vec_format_default<uint16_t>,// tunnel.metadata.opts[7]
	 rule_vec_format_default<uint16_t>,// tunnel.metadata.opts[8]
	 rule_vec_format_default<uint16_t>,// tunnel.metadata.opts[9]
	 rule_vec_format_default<uint16_t>,// tunnel.metadata.opts[10]
	 rule_vec_format_default<uint16_t>,// tunnel.metadata.opts[11]
	 rule_vec_format_default<uint16_t>,// tunnel.metadata.opts[12]
	 rule_vec_format_default<uint16_t>,// tunnel.metadata.opts[13]
	 rule_vec_format_default<uint16_t>,// tunnel.metadata.opts[14]
	 rule_vec_format_default<uint16_t>,// tunnel.metadata.opts[15]
	 rule_vec_format_default<uint16_t>,// tunnel.metadata.opts[16]
	 rule_vec_format_default<uint16_t>,// tunnel.metadata.opts[17]
	 rule_vec_format_default<uint16_t>,// tunnel.metadata.opts[18]
	 rule_vec_format_default<uint16_t>,// tunnel.metadata.opts[19]
	 rule_vec_format_default<uint16_t>,// tunnel.metadata.opts[20]
	 rule_vec_format_default<uint16_t>,// tunnel.metadata.opts[21]
	 rule_vec_format_default<uint16_t>,// tunnel.metadata.opts[22]
	 rule_vec_format_default<uint16_t>,// tunnel.metadata.opts[23]
	 rule_vec_format_default<uint16_t>,// tunnel.metadata.opts[24]
	 rule_vec_format_default<uint16_t>,// tunnel.metadata.opts[25]
	 rule_vec_format_default<uint16_t>,// tunnel.metadata.opts[26]
	 rule_vec_format_default<uint16_t>,// tunnel.metadata.opts[27]
	 rule_vec_format_default<uint16_t>,// tunnel.metadata.opts[28]
	 rule_vec_format_default<uint16_t>,// tunnel.metadata.opts[29]
	 rule_vec_format_default<uint16_t>,// tunnel.metadata.opts[30]
	 rule_vec_format_default<uint16_t>,// tunnel.metadata.opts[31]
	 rule_vec_format_default<uint16_t>,// tunnel.metadata.opts[32]
	 rule_vec_format_default<uint16_t>,// tunnel.metadata.opts[33]
	 rule_vec_format_default<uint16_t>,// tunnel.metadata.opts[34]
	 rule_vec_format_default<uint16_t>,// tunnel.metadata.opts[35]
	 rule_vec_format_default<uint16_t>,// tunnel.metadata.opts[36]
	 rule_vec_format_default<uint16_t>,// tunnel.metadata.opts[37]
	 rule_vec_format_default<uint16_t>,// tunnel.metadata.opts[38]
	 rule_vec_format_default<uint16_t>,// tunnel.metadata.opts[39]
	 rule_vec_format_default<uint16_t>,// tunnel.metadata.opts[40]
	 rule_vec_format_default<uint16_t>,// tunnel.metadata.opts[41]
	 rule_vec_format_default<uint16_t>,// tunnel.metadata.opts[42]
	 rule_vec_format_default<uint16_t>,// tunnel.metadata.opts[43]
	 rule_vec_format_default<uint16_t>,// tunnel.metadata.opts[44]
	 rule_vec_format_default<uint16_t>,// tunnel.metadata.opts[45]
	 rule_vec_format_default<uint16_t>,// tunnel.metadata.opts[46]
	 rule_vec_format_default<uint16_t>,// tunnel.metadata.opts[47]
	 rule_vec_format_default<uint16_t>,// tunnel.metadata.opts[48]
	 rule_vec_format_default<uint16_t>,// tunnel.metadata.opts[49]
	 rule_vec_format_default<uint16_t>,// tunnel.metadata.opts[50]
	 rule_vec_format_default<uint16_t>,// tunnel.metadata.opts[51]
	 rule_vec_format_default<uint16_t>,// tunnel.metadata.opts[52]
	 rule_vec_format_default<uint16_t>,// tunnel.metadata.opts[53]
	 rule_vec_format_default<uint16_t>,// tunnel.metadata.opts[54]
	 rule_vec_format_default<uint16_t>,// tunnel.metadata.opts[55]
	 rule_vec_format_default<uint16_t>,// tunnel.metadata.opts[56]
	 rule_vec_format_default<uint16_t>,// tunnel.metadata.opts[57]
	 rule_vec_format_default<uint16_t>,// tunnel.metadata.opts[58]
	 rule_vec_format_default<uint16_t>,// tunnel.metadata.opts[59]
	 rule_vec_format_default<uint16_t>,// tunnel.metadata.opts[60]
	 rule_vec_format_default<uint16_t>,// tunnel.metadata.opts[61]
	 rule_vec_format_default<uint16_t>,// tunnel.metadata.opts[62]
	 rule_vec_format_default<uint16_t>,// tunnel.metadata.opts[63]
	 rule_vec_format_default<uint16_t>,// tunnel.metadata.opts[64]
	 rule_vec_format_default<uint16_t>,// tunnel.metadata.opts[65]
	 rule_vec_format_default<uint16_t>,// tunnel.metadata.opts[66]
	 rule_vec_format_default<uint16_t>,// tunnel.metadata.opts[67]
	 rule_vec_format_default<uint16_t>,// tunnel.metadata.opts[68]
	 rule_vec_format_default<uint16_t>,// tunnel.metadata.opts[69]
	 rule_vec_format_default<uint16_t>,// tunnel.metadata.opts[70]
	 rule_vec_format_default<uint16_t>,// tunnel.metadata.opts[71]
	 rule_vec_format_default<uint16_t>,// tunnel.metadata.opts[72]
	 rule_vec_format_default<uint16_t>,// tunnel.metadata.opts[73]
	 rule_vec_format_default<uint16_t>,// tunnel.metadata.opts[74]
	 rule_vec_format_default<uint16_t>,// tunnel.metadata.opts[75]
	 rule_vec_format_default<uint16_t>,// tunnel.metadata.opts[76]
	 rule_vec_format_default<uint16_t>,// tunnel.metadata.opts[77]
	 rule_vec_format_default<uint16_t>,// tunnel.metadata.opts[78]
	 rule_vec_format_default<uint16_t>,// tunnel.metadata.opts[79]
	 rule_vec_format_default<uint16_t>,// tunnel.metadata.opts[80]
	 rule_vec_format_default<uint16_t>,// tunnel.metadata.opts[81]
	 rule_vec_format_default<uint16_t>,// tunnel.metadata.opts[82]
	 rule_vec_format_default<uint16_t>,// tunnel.metadata.opts[83]
	 rule_vec_format_default<uint16_t>,// tunnel.metadata.opts[84]
	 rule_vec_format_default<uint16_t>,// tunnel.metadata.opts[85]
	 rule_vec_format_default<uint16_t>,// tunnel.metadata.opts[86]
	 rule_vec_format_default<uint16_t>,// tunnel.metadata.opts[87]
	 rule_vec_format_default<uint16_t>,// tunnel.metadata.opts[88]
	 rule_vec_format_default<uint16_t>,// tunnel.metadata.opts[89]
	 rule_vec_format_default<uint16_t>,// tunnel.metadata.opts[90]
	 rule_vec_format_default<uint16_t>,// tunnel.metadata.opts[91]
	 rule_vec_format_default<uint16_t>,// tunnel.metadata.opts[92]
	 rule_vec_format_default<uint16_t>,// tunnel.metadata.opts[93]
	 rule_vec_format_default<uint16_t>,// tunnel.metadata.opts[94]
	 rule_vec_format_default<uint16_t>,// tunnel.metadata.opts[95]
	 rule_vec_format_default<uint16_t>,// tunnel.metadata.opts[96]
	 rule_vec_format_default<uint16_t>,// tunnel.metadata.opts[97]
	 rule_vec_format_default<uint16_t>,// tunnel.metadata.opts[98]
	 rule_vec_format_default<uint16_t>,// tunnel.metadata.opts[99]
	 rule_vec_format_default<uint16_t>,// tunnel.metadata.opts[100]
	 rule_vec_format_default<uint16_t>,// tunnel.metadata.opts[101]
	 rule_vec_format_default<uint16_t>,// tunnel.metadata.opts[102]
	 rule_vec_format_default<uint16_t>,// tunnel.metadata.opts[103]
	 rule_vec_format_default<uint16_t>,// tunnel.metadata.opts[104]
	 rule_vec_format_default<uint16_t>,// tunnel.metadata.opts[105]
	 rule_vec_format_default<uint16_t>,// tunnel.metadata.opts[106]
	 rule_vec_format_default<uint16_t>,// tunnel.metadata.opts[107]
	 rule_vec_format_default<uint16_t>,// tunnel.metadata.opts[108]
	 rule_vec_format_default<uint16_t>,// tunnel.metadata.opts[109]
	 rule_vec_format_default<uint16_t>,// tunnel.metadata.opts[110]
	 rule_vec_format_default<uint16_t>,// tunnel.metadata.opts[111]
	 rule_vec_format_default<uint16_t>,// tunnel.metadata.opts[112]
	 rule_vec_format_default<uint16_t>,// tunnel.metadata.opts[113]
	 rule_vec_format_default<uint16_t>,// tunnel.metadata.opts[114]
	 rule_vec_format_default<uint16_t>,// tunnel.metadata.opts[115]
	 rule_vec_format_default<uint16_t>,// tunnel.metadata.opts[116]
	 rule_vec_format_default<uint16_t>,// tunnel.metadata.opts[117]
	 rule_vec_format_default<uint16_t>,// tunnel.metadata.opts[118]
	 rule_vec_format_default<uint16_t>,// tunnel.metadata.opts[119]
	 rule_vec_format_default<uint16_t>,// tunnel.metadata.opts[120]
	 rule_vec_format_default<uint16_t>,// tunnel.metadata.opts[121]
	 rule_vec_format_default<uint16_t>,// tunnel.metadata.opts[122]
	 rule_vec_format_default<uint16_t>,// tunnel.metadata.opts[123]
	 rule_vec_format_default<uint16_t>,// tunnel.metadata.opts[124]
	 rule_vec_format_default<uint16_t>,// tunnel.metadata.opts[125]
	 rule_vec_format_default<uint16_t>,// tunnel.metadata.opts[126]
	 rule_vec_format_default<uint16_t>,// tunnel.metadata.opts[127]
	 rule_vec_format_default<uint16_t>,// metadata-0
	 rule_vec_format_default<uint16_t>,// metadata-2
	 rule_vec_format_default<uint16_t>,// metadata-4
	 rule_vec_format_default<uint16_t>,// metadata-6
	 rule_vec_format_default<uint16_t>,// regs[0]-2
	 rule_vec_format_default<uint16_t>,// regs[0]-0
	 rule_vec_format_default<uint16_t>,// regs[1]-2
	 rule_vec_format_default<uint16_t>,// regs[1]-0
	 rule_vec_format_default<uint16_t>,// regs[2]-2
	 rule_vec_format_default<uint16_t>,// regs[2]-0
	 rule_vec_format_default<uint16_t>,// regs[3]-2
	 rule_vec_format_default<uint16_t>,// regs[3]-0
	 rule_vec_format_default<uint16_t>,// regs[4]-2
	 rule_vec_format_default<uint16_t>,// regs[4]-0
	 rule_vec_format_default<uint16_t>,// regs[5]-2
	 rule_vec_format_default<uint16_t>,// regs[5]-0
	 rule_vec_format_default<uint16_t>,// regs[6]-2
	 rule_vec_format_default<uint16_t>,// regs[6]-0
	 rule_vec_format_default<uint16_t>,// regs[7]-2
	 rule_vec_format_default<uint16_t>,// regs[7]-0
	 rule_vec_format_default<uint16_t>,// regs[8]-2
	 rule_vec_format_default<uint16_t>,// regs[8]-0
	 rule_vec_format_default<uint16_t>,// regs[9]-2
	 rule_vec_format_default<uint16_t>,// regs[9]-0
	 rule_vec_format_default<uint16_t>,// regs[10]-2
	 rule_vec_format_default<uint16_t>,// regs[10]-0
	 rule_vec_format_default<uint16_t>,// regs[11]-2
	 rule_vec_format_default<uint16_t>,// regs[11]-0
	 rule_vec_format_default<uint16_t>,// regs[12]-2
	 rule_vec_format_default<uint16_t>,// regs[12]-0
	 rule_vec_format_default<uint16_t>,// regs[13]-2
	 rule_vec_format_default<uint16_t>,// regs[13]-0
	 rule_vec_format_default<uint16_t>,// regs[14]-2
	 rule_vec_format_default<uint16_t>,// regs[14]-0
	 rule_vec_format_default<uint16_t>,// regs[15]-2
	 rule_vec_format_default<uint16_t>,// regs[15]-0
	 rule_vec_format_default<uint16_t>,// skb_priority-2
	 rule_vec_format_default<uint16_t>,// skb_priority-0
	 rule_vec_format_default<uint16_t>,// pkt_mark-2
	 rule_vec_format_default<uint16_t>,// pkt_mark-0
	 rule_vec_format_default<uint16_t>,// dp_hash-2
	 rule_vec_format_default<uint16_t>,// dp_hash-0
	 rule_vec_format_default<uint16_t>,// in_port-2
	 rule_vec_format_default<uint16_t>,// in_port-0
	 rule_vec_format_default<uint16_t>,// recirc_id-2
	 rule_vec_format_default<uint16_t>,// recirc_id-0
	 rule_vec_format_default<uint16_t>,// ct_state
	 rule_vec_format_default<uint16_t>,// ct_nw_proto
	 rule_vec_format_default<uint16_t>,// ct_zone
	 rule_vec_format_default<uint16_t>,// ct_mark-2
	 rule_vec_format_default<uint16_t>,// ct_mark-0
	 rule_vec_format_default<uint16_t>,// packet_type-0
	 rule_vec_format_default<uint16_t>,// packet_type-2
	 rule_vec_format_default<uint16_t>,// ct_label-14
	 rule_vec_format_default<uint16_t>,// ct_label-12
	 rule_vec_format_default<uint16_t>,// ct_label-10
	 rule_vec_format_default<uint16_t>,// ct_label-8
	 rule_vec_format_default<uint16_t>,// ct_label-6
	 rule_vec_format_default<uint16_t>,// ct_label-4
	 rule_vec_format_default<uint16_t>,// ct_label-2
	 rule_vec_format_default<uint16_t>,// ct_label-0
	 rule_vec_format_default<uint16_t>,// conj_id-2
	 rule_vec_format_default<uint16_t>,// conj_id-0
	 rule_vec_format_default<uint16_t>,// actset_output-2
	 rule_vec_format_default<uint16_t>,// actset_output-0
	 rule_vec_format_default<uint16_t>,// dl_dst-0
	 rule_vec_format_default<uint16_t>,// dl_dst-2
	 rule_vec_format_default<uint16_t>,// dl_dst-4
	 rule_vec_format_default<uint16_t>,// dl_src-0
	 rule_vec_format_default<uint16_t>,// dl_src-2
	 rule_vec_format_default<uint16_t>,// dl_src-4
	 rule_vec_format_default<uint16_t>,// dl_type
	 rule_vec_format_default<uint16_t>,// vlans[0]-0
	 rule_vec_format_default<uint16_t>,// vlans[0]-2
	 rule_vec_format_default<uint16_t>,// vlans[1]-0
	 rule_vec_format_default<uint16_t>,// vlans[1]-2
	 rule_vec_format_default<uint16_t>,// mpls_lse[0]-0
	 rule_vec_format_default<uint16_t>,// mpls_lse[0]-2
	 rule_vec_format_default<uint16_t>,// mpls_lse[1]-0
	 rule_vec_format_default<uint16_t>,// mpls_lse[1]-2
	 rule_vec_format_ipv4_part,// nw_src-0
	 rule_vec_format_ipv4_part,// nw_src-2
	 rule_vec_format_ipv4_part,// nw_dst-0
	 rule_vec_format_ipv4_part,// nw_dst-2
	 rule_vec_format_ipv4_part,// ct_nw_src-0
	 rule_vec_format_ipv4_part,// ct_nw_src-2
	 rule_vec_format_ipv4_part,// ct_nw_dst-0
	 rule_vec_format_ipv4_part,// ct_nw_dst-2
	 rule_vec_format_ipv6_part,// ipv6_src-0
	 rule_vec_format_ipv6_part,// ipv6_src-2
	 rule_vec_format_ipv6_part,// ipv6_src-4
	 rule_vec_format_ipv6_part,// ipv6_src-6
	 rule_vec_format_ipv6_part,// ipv6_src-8
	 rule_vec_format_ipv6_part,// ipv6_src-10
	 rule_vec_format_ipv6_part,// ipv6_src-12
	 rule_vec_format_ipv6_part,// ipv6_src-14
	 rule_vec_format_ipv6_part,// ipv6_dst-0
	 rule_vec_format_ipv6_part,// ipv6_dst-2
	 rule_vec_format_ipv6_part,// ipv6_dst-4
	 rule_vec_format_ipv6_part,// ipv6_dst-6
	 rule_vec_format_ipv6_part,// ipv6_dst-8
	 rule_vec_format_ipv6_part,// ipv6_dst-10
	 rule_vec_format_ipv6_part,// ipv6_dst-12
	 rule_vec_format_ipv6_part,// ipv6_dst-14
	 rule_vec_format_ipv6_part,// ct_ipv6_src-0
	 rule_vec_format_ipv6_part,// ct_ipv6_src-2
	 rule_vec_format_ipv6_part,// ct_ipv6_src-4
	 rule_vec_format_ipv6_part,// ct_ipv6_src-6
	 rule_vec_format_ipv6_part,// ct_ipv6_src-8
	 rule_vec_format_ipv6_part,// ct_ipv6_src-10
	 rule_vec_format_ipv6_part,// ct_ipv6_src-12
	 rule_vec_format_ipv6_part,// ct_ipv6_src-14
	 rule_vec_format_default<uint16_t>,// ct_ipv6_dst-0
	 rule_vec_format_default<uint16_t>,// ct_ipv6_dst-2
	 rule_vec_format_default<uint16_t>,// ct_ipv6_dst-4
	 rule_vec_format_default<uint16_t>,// ct_ipv6_dst-6
	 rule_vec_format_default<uint16_t>,// ct_ipv6_dst-8
	 rule_vec_format_default<uint16_t>,// ct_ipv6_dst-10
	 rule_vec_format_default<uint16_t>,// ct_ipv6_dst-12
	 rule_vec_format_default<uint16_t>,// ct_ipv6_dst-14
	 rule_vec_format_default<uint16_t>,// ipv6_label-0
	 rule_vec_format_default<uint16_t>,// ipv6_label-2
	 rule_vec_format_default<uint16_t>,// nw_frag
	 rule_vec_format_default<uint16_t>,// nw_tos
	 rule_vec_format_default<uint16_t>,// nw_ttl
	 rule_vec_format_default<uint16_t>,// nw_proto
	 rule_vec_format_ipv6_part,// nd_target-0
	 rule_vec_format_ipv6_part,// nd_target-2
	 rule_vec_format_ipv6_part,// nd_target-4
	 rule_vec_format_ipv6_part,// nd_target-6
	 rule_vec_format_ipv6_part,// nd_target-8
	 rule_vec_format_ipv6_part,// nd_target-10
	 rule_vec_format_ipv6_part,// nd_target-12
	 rule_vec_format_ipv6_part,// nd_target-14
	 rule_vec_format_default<uint16_t>,// arp_sha-0
	 rule_vec_format_default<uint16_t>,// arp_sha-2
	 rule_vec_format_default<uint16_t>,// arp_sha-4
	 rule_vec_format_default<uint16_t>,// arp_tha-0
	 rule_vec_format_default<uint16_t>,// arp_tha-2
	 rule_vec_format_default<uint16_t>,// arp_tha-4
	 rule_vec_format_default<uint16_t>,// tcp_flags
	 rule_vec_format_default<uint16_t>,// nsh.flags
	 rule_vec_format_default<uint16_t>,// nsh.ttl
	 rule_vec_format_default<uint16_t>,// nsh.mdtype
	 rule_vec_format_default<uint16_t>,// nsh.np
	 rule_vec_format_default<uint16_t>,// nsh.path_hdr-0
	 rule_vec_format_default<uint16_t>,// nsh.path_hdr-2
	 rule_vec_format_default<uint16_t>,// nsh.context[0]-0
	 rule_vec_format_default<uint16_t>,// nsh.context[0]-2
	 rule_vec_format_default<uint16_t>,// nsh.context[1]-0
	 rule_vec_format_default<uint16_t>,// nsh.context[1]-2
	 rule_vec_format_default<uint16_t>,// nsh.context[2]-0
	 rule_vec_format_default<uint16_t>,// nsh.context[2]-2
	 rule_vec_format_default<uint16_t>,// nsh.context[3]-0
	 rule_vec_format_default<uint16_t>,// nsh.context[3]-2
	 rule_vec_format_default<uint16_t>,// tp_src
	 rule_vec_format_default<uint16_t>,// tp_dst
	 rule_vec_format_default<uint16_t>,// ct_tp_src
	 rule_vec_format_default<uint16_t>,// ct_tp_dst
	 rule_vec_format_default<uint16_t>,// igmp_group_ip4-0
	 rule_vec_format_default<uint16_t>,// igmp_group_ip4-2
};

typename PcvClassifier::names_t struct_flow_packet_names = {
	"tunnel.ip_dst-0", //
	"tunnel.ip_dst-2", //
	"tunnel.ipv6_dst-0", //
	"tunnel.ipv6_dst-2", //
	"tunnel.ipv6_dst-4", //
	"tunnel.ipv6_dst-6", //
	"tunnel.ipv6_dst-8", //
	"tunnel.ipv6_dst-10", //
	"tunnel.ipv6_dst-12", //
	"tunnel.ipv6_dst-14", //
	"tunnel.ip_src-0", //
	"tunnel.ip_src-2", //
	"tunnel.ipv6_src-0", //
	"tunnel.ipv6_src-2", //
	"tunnel.ipv6_src-4", //
	"tunnel.ipv6_src-6", //
	"tunnel.ipv6_src-8", //
	"tunnel.ipv6_src-10", //
	"tunnel.ipv6_src-12", //
	"tunnel.ipv6_src-14", //
	"tunnel.tun_id-0", //
	"tunnel.tun_id-2", //
	"tunnel.tun_id-4", //
	"tunnel.tun_id-6", //
	"tunnel.flags", //
	"tunnel.ip_tos", //
	"tunnel.ip_ttl", //
	"tunnel.tp_src", //
	"tunnel.tp_dst", //
	"tunnel.gbp_id", //
	"tunnel.gbp_flags", //
	"tunnel.erspan_ver", //
	"tunnel.erspan_idx-2", //
	"tunnel.erspan_idx-0", //
	"tunnel.erspan_dir", //
	"tunnel.erspan_hwid", //
	"tunnel.metadata.present-6", //
	"tunnel.metadata.present-4", //
	"tunnel.metadata.present-2", //
	"tunnel.metadata.present-0", //
	"tunnel.metadata.opts[0]", //
	"tunnel.metadata.opts[1]", //
	"tunnel.metadata.opts[2]", //
	"tunnel.metadata.opts[3]", //
	"tunnel.metadata.opts[4]", //
	"tunnel.metadata.opts[5]", //
	"tunnel.metadata.opts[6]", //
	"tunnel.metadata.opts[7]", //
	"tunnel.metadata.opts[8]", //
	"tunnel.metadata.opts[9]", //
	"tunnel.metadata.opts[10]", //
	"tunnel.metadata.opts[11]", //
	"tunnel.metadata.opts[12]", //
	"tunnel.metadata.opts[13]", //
	"tunnel.metadata.opts[14]", //
	"tunnel.metadata.opts[15]", //
	"tunnel.metadata.opts[16]", //
	"tunnel.metadata.opts[17]", //
	"tunnel.metadata.opts[18]", //
	"tunnel.metadata.opts[19]", //
	"tunnel.metadata.opts[20]", //
	"tunnel.metadata.opts[21]", //
	"tunnel.metadata.opts[22]", //
	"tunnel.metadata.opts[23]", //
	"tunnel.metadata.opts[24]", //
	"tunnel.metadata.opts[25]", //
	"tunnel.metadata.opts[26]", //
	"tunnel.metadata.opts[27]", //
	"tunnel.metadata.opts[28]", //
	"tunnel.metadata.opts[29]", //
	"tunnel.metadata.opts[30]", //
	"tunnel.metadata.opts[31]", //
	"tunnel.metadata.opts[32]", //
	"tunnel.metadata.opts[33]", //
	"tunnel.metadata.opts[34]", //
	"tunnel.metadata.opts[35]", //
	"tunnel.metadata.opts[36]", //
	"tunnel.metadata.opts[37]", //
	"tunnel.metadata.opts[38]", //
	"tunnel.metadata.opts[39]", //
	"tunnel.metadata.opts[40]", //
	"tunnel.metadata.opts[41]", //
	"tunnel.metadata.opts[42]", //
	"tunnel.metadata.opts[43]", //
	"tunnel.metadata.opts[44]", //
	"tunnel.metadata.opts[45]", //
	"tunnel.metadata.opts[46]", //
	"tunnel.metadata.opts[47]", //
	"tunnel.metadata.opts[48]", //
	"tunnel.metadata.opts[49]", //
	"tunnel.metadata.opts[50]", //
	"tunnel.metadata.opts[51]", //
	"tunnel.metadata.opts[52]", //
	"tunnel.metadata.opts[53]", //
	"tunnel.metadata.opts[54]", //
	"tunnel.metadata.opts[55]", //
	"tunnel.metadata.opts[56]", //
	"tunnel.metadata.opts[57]", //
	"tunnel.metadata.opts[58]", //
	"tunnel.metadata.opts[59]", //
	"tunnel.metadata.opts[60]", //
	"tunnel.metadata.opts[61]", //
	"tunnel.metadata.opts[62]", //
	"tunnel.metadata.opts[63]", //
	"tunnel.metadata.opts[64]", //
	"tunnel.metadata.opts[65]", //
	"tunnel.metadata.opts[66]", //
	"tunnel.metadata.opts[67]", //
	"tunnel.metadata.opts[68]", //
	"tunnel.metadata.opts[69]", //
	"tunnel.metadata.opts[70]", //
	"tunnel.metadata.opts[71]", //
	"tunnel.metadata.opts[72]", //
	"tunnel.metadata.opts[73]", //
	"tunnel.metadata.opts[74]", //
	"tunnel.metadata.opts[75]", //
	"tunnel.metadata.opts[76]", //
	"tunnel.metadata.opts[77]", //
	"tunnel.metadata.opts[78]", //
	"tunnel.metadata.opts[79]", //
	"tunnel.metadata.opts[80]", //
	"tunnel.metadata.opts[81]", //
	"tunnel.metadata.opts[82]", //
	"tunnel.metadata.opts[83]", //
	"tunnel.metadata.opts[84]", //
	"tunnel.metadata.opts[85]", //
	"tunnel.metadata.opts[86]", //
	"tunnel.metadata.opts[87]", //
	"tunnel.metadata.opts[88]", //
	"tunnel.metadata.opts[89]", //
	"tunnel.metadata.opts[90]", //
	"tunnel.metadata.opts[91]", //
	"tunnel.metadata.opts[92]", //
	"tunnel.metadata.opts[93]", //
	"tunnel.metadata.opts[94]", //
	"tunnel.metadata.opts[95]", //
	"tunnel.metadata.opts[96]", //
	"tunnel.metadata.opts[97]", //
	"tunnel.metadata.opts[98]", //
	"tunnel.metadata.opts[99]", //
	"tunnel.metadata.opts[100]", //
	"tunnel.metadata.opts[101]", //
	"tunnel.metadata.opts[102]", //
	"tunnel.metadata.opts[103]", //
	"tunnel.metadata.opts[104]", //
	"tunnel.metadata.opts[105]", //
	"tunnel.metadata.opts[106]", //
	"tunnel.metadata.opts[107]", //
	"tunnel.metadata.opts[108]", //
	"tunnel.metadata.opts[109]", //
	"tunnel.metadata.opts[110]", //
	"tunnel.metadata.opts[111]", //
	"tunnel.metadata.opts[112]", //
	"tunnel.metadata.opts[113]", //
	"tunnel.metadata.opts[114]", //
	"tunnel.metadata.opts[115]", //
	"tunnel.metadata.opts[116]", //
	"tunnel.metadata.opts[117]", //
	"tunnel.metadata.opts[118]", //
	"tunnel.metadata.opts[119]", //
	"tunnel.metadata.opts[120]", //
	"tunnel.metadata.opts[121]", //
	"tunnel.metadata.opts[122]", //
	"tunnel.metadata.opts[123]", //
	"tunnel.metadata.opts[124]", //
	"tunnel.metadata.opts[125]", //
	"tunnel.metadata.opts[126]", //
	"tunnel.metadata.opts[127]", //
	"metadata-0", //
	"metadata-2", //
	"metadata-4", //
	"metadata-6", //
	"regs[0]-2", //
	"regs[0]-0", //
	"regs[1]-2", //
	"regs[1]-0", //
	"regs[2]-2", //
	"regs[2]-0", //
	"regs[3]-2", //
	"regs[3]-0", //
	"regs[4]-2", //
	"regs[4]-0", //
	"regs[5]-2", //
	"regs[5]-0", //
	"regs[6]-2", //
	"regs[6]-0", //
	"regs[7]-2", //
	"regs[7]-0", //
	"regs[8]-2", //
	"regs[8]-0", //
	"regs[9]-2", //
	"regs[9]-0", //
	"regs[10]-2", //
	"regs[10]-0", //
	"regs[11]-2", //
	"regs[11]-0", //
	"regs[12]-2", //
	"regs[12]-0", //
	"regs[13]-2", //
	"regs[13]-0", //
	"regs[14]-2", //
	"regs[14]-0", //
	"regs[15]-2", //
	"regs[15]-0", //
	"skb_priority-2", //
	"skb_priority-0", //
	"pkt_mark-2", //
	"pkt_mark-0", //
	"dp_hash-2", //
	"dp_hash-0", //
	"in_port-2", //
	"in_port-0", //
	"recirc_id-2", //
	"recirc_id-0", //
	"ct_state", //
	"ct_nw_proto", //
	"ct_zone", //
	"ct_mark-2", //
	"ct_mark-0", //
	"packet_type-0", //
	"packet_type-2", //
	"ct_label-14", //
	"ct_label-12", //
	"ct_label-10", //
	"ct_label-8", //
	"ct_label-6", //
	"ct_label-4", //
	"ct_label-2", //
	"ct_label-0", //
	"conj_id-2", //
	"conj_id-0", //
	"actset_output-2", //
	"actset_output-0", //
	"dl_dst-0", //
	"dl_dst-2", //
	"dl_dst-4", //
	"dl_src-0", //
	"dl_src-2", //
	"dl_src-4", //
	"dl_type", //
	"vlans[0]-0", //
	"vlans[0]-2", //
	"vlans[1]-0", //
	"vlans[1]-2", //
	"mpls_lse[0]-0", //
	"mpls_lse[0]-2", //
	"mpls_lse[1]-0", //
	"mpls_lse[1]-2", //
	"nw_src-0", //
	"nw_src-2", //
	"nw_dst-0", //
	"nw_dst-2", //
	"ct_nw_src-0", //
	"ct_nw_src-2", //
	"ct_nw_dst-0", //
	"ct_nw_dst-2", //
	"ipv6_src-0", //
	"ipv6_src-2", //
	"ipv6_src-4", //
	"ipv6_src-6", //
	"ipv6_src-8", //
	"ipv6_src-10", //
	"ipv6_src-12", //
	"ipv6_src-14", //
	"ipv6_dst-0", //
	"ipv6_dst-2", //
	"ipv6_dst-4", //
	"ipv6_dst-6", //
	"ipv6_dst-8", //
	"ipv6_dst-10", //
	"ipv6_dst-12", //
	"ipv6_dst-14", //
	"ct_ipv6_src-0", //
	"ct_ipv6_src-2", //
	"ct_ipv6_src-4", //
	"ct_ipv6_src-6", //
	"ct_ipv6_src-8", //
	"ct_ipv6_src-10", //
	"ct_ipv6_src-12", //
	"ct_ipv6_src-14", //
	"ct_ipv6_dst-0", //
	"ct_ipv6_dst-2", //
	"ct_ipv6_dst-4", //
	"ct_ipv6_dst-6", //
	"ct_ipv6_dst-8", //
	"ct_ipv6_dst-10", //
	"ct_ipv6_dst-12", //
	"ct_ipv6_dst-14", //
	"ipv6_label-0", //
	"ipv6_label-2", //
	"nw_frag", //
	"nw_tos", //
	"nw_ttl", //
	"nw_proto", //
	"nd_target-0", //
	"nd_target-2", //
	"nd_target-4", //
	"nd_target-6", //
	"nd_target-8", //
	"nd_target-10", //
	"nd_target-12", //
	"nd_target-14", //
	"arp_sha-0", //
	"arp_sha-2", //
	"arp_sha-4", //
	"arp_tha-0", //
	"arp_tha-2", //
	"arp_tha-4", //
	"tcp_flags", //
	"nsh.flags", //
	"nsh.ttl", //
	"nsh.mdtype", //
	"nsh.np", //
	"nsh.path_hdr-0", //
	"nsh.path_hdr-2", //
	"nsh.context[0]-0", //
	"nsh.context[0]-2", //
	"nsh.context[1]-0", //
	"nsh.context[1]-2", //
	"nsh.context[2]-0", //
	"nsh.context[2]-2", //
	"nsh.context[3]-0", //
	"nsh.context[3]-2", //
	"tp_src", //
	"tp_dst", //
	"ct_tp_src", //
	"ct_tp_dst", //
	"igmp_group_ip4-0", //
	"igmp_group_ip4-2", //
};

typename PcvClassifier::packet_spec_t struct_flow_packet_spec = {
	in_packet_position_t(offsetof(flow, tunnel) + offsetof(flow_tnl, ip_dst) + 0, 2,  1), // tunnel.ip_dst-0
	in_packet_position_t(offsetof(flow, tunnel) + offsetof(flow_tnl, ip_dst) + 2, 2,  1), // tunnel.ip_dst-2
	in_packet_position_t(offsetof(flow, tunnel) + offsetof(flow_tnl, ipv6_dst) + 0, 2,  1), // tunnel.ipv6_dst-0
	in_packet_position_t(offsetof(flow, tunnel) + offsetof(flow_tnl, ipv6_dst) + 2, 2,  1), // tunnel.ipv6_dst-2
	in_packet_position_t(offsetof(flow, tunnel) + offsetof(flow_tnl, ipv6_dst) + 4, 2,  1), // tunnel.ipv6_dst-4
	in_packet_position_t(offsetof(flow, tunnel) + offsetof(flow_tnl, ipv6_dst) + 6, 2,  1), // tunnel.ipv6_dst-6
	in_packet_position_t(offsetof(flow, tunnel) + offsetof(flow_tnl, ipv6_dst) + 8, 2,  1), // tunnel.ipv6_dst-8
	in_packet_position_t(offsetof(flow, tunnel) + offsetof(flow_tnl, ipv6_dst) + 10, 2,  1), // tunnel.ipv6_dst-10
	in_packet_position_t(offsetof(flow, tunnel) + offsetof(flow_tnl, ipv6_dst) + 12, 2,  1), // tunnel.ipv6_dst-12
	in_packet_position_t(offsetof(flow, tunnel) + offsetof(flow_tnl, ipv6_dst) + 14, 2,  1), // tunnel.ipv6_dst-14
	in_packet_position_t(offsetof(flow, tunnel) + offsetof(flow_tnl, ip_src) + 0, 2,  1), // tunnel.ip_src-0
	in_packet_position_t(offsetof(flow, tunnel) + offsetof(flow_tnl, ip_src) + 2, 2,  1), // tunnel.ip_src-2
	in_packet_position_t(offsetof(flow, tunnel) + offsetof(flow_tnl, ipv6_src) + 0, 2,  1), // tunnel.ipv6_src-0
	in_packet_position_t(offsetof(flow, tunnel) + offsetof(flow_tnl, ipv6_src) + 2, 2,  1), // tunnel.ipv6_src-2
	in_packet_position_t(offsetof(flow, tunnel) + offsetof(flow_tnl, ipv6_src) + 4, 2,  1), // tunnel.ipv6_src-4
	in_packet_position_t(offsetof(flow, tunnel) + offsetof(flow_tnl, ipv6_src) + 6, 2,  1), // tunnel.ipv6_src-6
	in_packet_position_t(offsetof(flow, tunnel) + offsetof(flow_tnl, ipv6_src) + 8, 2,  1), // tunnel.ipv6_src-8
	in_packet_position_t(offsetof(flow, tunnel) + offsetof(flow_tnl, ipv6_src) + 10, 2,  1), // tunnel.ipv6_src-10
	in_packet_position_t(offsetof(flow, tunnel) + offsetof(flow_tnl, ipv6_src) + 12, 2,  1), // tunnel.ipv6_src-12
	in_packet_position_t(offsetof(flow, tunnel) + offsetof(flow_tnl, ipv6_src) + 14, 2,  1), // tunnel.ipv6_src-14
	in_packet_position_t(offsetof(flow, tunnel) + offsetof(flow_tnl, tun_id) + 0, 2,  1), // tunnel.tun_id-0
	in_packet_position_t(offsetof(flow, tunnel) + offsetof(flow_tnl, tun_id) + 2, 2,  1), // tunnel.tun_id-2
	in_packet_position_t(offsetof(flow, tunnel) + offsetof(flow_tnl, tun_id) + 4, 2,  1), // tunnel.tun_id-4
	in_packet_position_t(offsetof(flow, tunnel) + offsetof(flow_tnl, tun_id) + 6, 2,  1), // tunnel.tun_id-6
	in_packet_position_t(offsetof(flow, tunnel) + offsetof(flow_tnl, flags), 2,  0), // tunnel.flags
	in_packet_position_t(offsetof(flow, tunnel) + offsetof(flow_tnl, ip_tos), 1,  0), // tunnel.ip_tos
	in_packet_position_t(offsetof(flow, tunnel) + offsetof(flow_tnl, ip_ttl), 1,  0), // tunnel.ip_ttl
	in_packet_position_t(offsetof(flow, tunnel) + offsetof(flow_tnl, tp_src), 2,  1), // tunnel.tp_src
	in_packet_position_t(offsetof(flow, tunnel) + offsetof(flow_tnl, tp_dst), 2,  1), // tunnel.tp_dst
	in_packet_position_t(offsetof(flow, tunnel) + offsetof(flow_tnl, gbp_id), 2,  1), // tunnel.gbp_id
	in_packet_position_t(offsetof(flow, tunnel) + offsetof(flow_tnl, gbp_flags), 1,  0), // tunnel.gbp_flags
	in_packet_position_t(offsetof(flow, tunnel) + offsetof(flow_tnl, erspan_ver), 1,  0), // tunnel.erspan_ver
	in_packet_position_t(offsetof(flow, tunnel) + offsetof(flow_tnl, erspan_idx) + 2, 2,  0), // tunnel.erspan_idx-2
	in_packet_position_t(offsetof(flow, tunnel) + offsetof(flow_tnl, erspan_idx) + 0, 2,  0), // tunnel.erspan_idx-0
	in_packet_position_t(offsetof(flow, tunnel) + offsetof(flow_tnl, erspan_dir), 1,  0), // tunnel.erspan_dir
	in_packet_position_t(offsetof(flow, tunnel) + offsetof(flow_tnl, erspan_hwid), 1,  0), // tunnel.erspan_hwid
	in_packet_position_t(offsetof(flow_tnl, metadata) + offsetof(tun_metadata, present) + 6, 2,  0), // tunnel.metadata.present-6
	in_packet_position_t(offsetof(flow_tnl, metadata) + offsetof(tun_metadata, present) + 4, 2,  0), // tunnel.metadata.present-4
	in_packet_position_t(offsetof(flow_tnl, metadata) + offsetof(tun_metadata, present) + 2, 2,  0), // tunnel.metadata.present-2
	in_packet_position_t(offsetof(flow_tnl, metadata) + offsetof(tun_metadata, present) + 0, 2,  0), // tunnel.metadata.present-0
	in_packet_position_t(offsetof(flow_tnl, metadata) + offsetof(tun_metadata, opts) + 0, 2,  0), // tunnel.metadata.opts[0]
	in_packet_position_t(offsetof(flow_tnl, metadata) + offsetof(tun_metadata, opts) + 2, 2,  0), // tunnel.metadata.opts[1]
	in_packet_position_t(offsetof(flow_tnl, metadata) + offsetof(tun_metadata, opts) + 4, 2,  0), // tunnel.metadata.opts[2]
	in_packet_position_t(offsetof(flow_tnl, metadata) + offsetof(tun_metadata, opts) + 6, 2,  0), // tunnel.metadata.opts[3]
	in_packet_position_t(offsetof(flow_tnl, metadata) + offsetof(tun_metadata, opts) + 8, 2,  0), // tunnel.metadata.opts[4]
	in_packet_position_t(offsetof(flow_tnl, metadata) + offsetof(tun_metadata, opts) + 10, 2,  0), // tunnel.metadata.opts[5]
	in_packet_position_t(offsetof(flow_tnl, metadata) + offsetof(tun_metadata, opts) + 12, 2,  0), // tunnel.metadata.opts[6]
	in_packet_position_t(offsetof(flow_tnl, metadata) + offsetof(tun_metadata, opts) + 14, 2,  0), // tunnel.metadata.opts[7]
	in_packet_position_t(offsetof(flow_tnl, metadata) + offsetof(tun_metadata, opts) + 16, 2,  0), // tunnel.metadata.opts[8]
	in_packet_position_t(offsetof(flow_tnl, metadata) + offsetof(tun_metadata, opts) + 18, 2,  0), // tunnel.metadata.opts[9]
	in_packet_position_t(offsetof(flow_tnl, metadata) + offsetof(tun_metadata, opts) + 20, 2,  0), // tunnel.metadata.opts[10]
	in_packet_position_t(offsetof(flow_tnl, metadata) + offsetof(tun_metadata, opts) + 22, 2,  0), // tunnel.metadata.opts[11]
	in_packet_position_t(offsetof(flow_tnl, metadata) + offsetof(tun_metadata, opts) + 24, 2,  0), // tunnel.metadata.opts[12]
	in_packet_position_t(offsetof(flow_tnl, metadata) + offsetof(tun_metadata, opts) + 26, 2,  0), // tunnel.metadata.opts[13]
	in_packet_position_t(offsetof(flow_tnl, metadata) + offsetof(tun_metadata, opts) + 28, 2,  0), // tunnel.metadata.opts[14]
	in_packet_position_t(offsetof(flow_tnl, metadata) + offsetof(tun_metadata, opts) + 30, 2,  0), // tunnel.metadata.opts[15]
	in_packet_position_t(offsetof(flow_tnl, metadata) + offsetof(tun_metadata, opts) + 32, 2,  0), // tunnel.metadata.opts[16]
	in_packet_position_t(offsetof(flow_tnl, metadata) + offsetof(tun_metadata, opts) + 34, 2,  0), // tunnel.metadata.opts[17]
	in_packet_position_t(offsetof(flow_tnl, metadata) + offsetof(tun_metadata, opts) + 36, 2,  0), // tunnel.metadata.opts[18]
	in_packet_position_t(offsetof(flow_tnl, metadata) + offsetof(tun_metadata, opts) + 38, 2,  0), // tunnel.metadata.opts[19]
	in_packet_position_t(offsetof(flow_tnl, metadata) + offsetof(tun_metadata, opts) + 40, 2,  0), // tunnel.metadata.opts[20]
	in_packet_position_t(offsetof(flow_tnl, metadata) + offsetof(tun_metadata, opts) + 42, 2,  0), // tunnel.metadata.opts[21]
	in_packet_position_t(offsetof(flow_tnl, metadata) + offsetof(tun_metadata, opts) + 44, 2,  0), // tunnel.metadata.opts[22]
	in_packet_position_t(offsetof(flow_tnl, metadata) + offsetof(tun_metadata, opts) + 46, 2,  0), // tunnel.metadata.opts[23]
	in_packet_position_t(offsetof(flow_tnl, metadata) + offsetof(tun_metadata, opts) + 48, 2,  0), // tunnel.metadata.opts[24]
	in_packet_position_t(offsetof(flow_tnl, metadata) + offsetof(tun_metadata, opts) + 50, 2,  0), // tunnel.metadata.opts[25]
	in_packet_position_t(offsetof(flow_tnl, metadata) + offsetof(tun_metadata, opts) + 52, 2,  0), // tunnel.metadata.opts[26]
	in_packet_position_t(offsetof(flow_tnl, metadata) + offsetof(tun_metadata, opts) + 54, 2,  0), // tunnel.metadata.opts[27]
	in_packet_position_t(offsetof(flow_tnl, metadata) + offsetof(tun_metadata, opts) + 56, 2,  0), // tunnel.metadata.opts[28]
	in_packet_position_t(offsetof(flow_tnl, metadata) + offsetof(tun_metadata, opts) + 58, 2,  0), // tunnel.metadata.opts[29]
	in_packet_position_t(offsetof(flow_tnl, metadata) + offsetof(tun_metadata, opts) + 60, 2,  0), // tunnel.metadata.opts[30]
	in_packet_position_t(offsetof(flow_tnl, metadata) + offsetof(tun_metadata, opts) + 62, 2,  0), // tunnel.metadata.opts[31]
	in_packet_position_t(offsetof(flow_tnl, metadata) + offsetof(tun_metadata, opts) + 64, 2,  0), // tunnel.metadata.opts[32]
	in_packet_position_t(offsetof(flow_tnl, metadata) + offsetof(tun_metadata, opts) + 66, 2,  0), // tunnel.metadata.opts[33]
	in_packet_position_t(offsetof(flow_tnl, metadata) + offsetof(tun_metadata, opts) + 68, 2,  0), // tunnel.metadata.opts[34]
	in_packet_position_t(offsetof(flow_tnl, metadata) + offsetof(tun_metadata, opts) + 70, 2,  0), // tunnel.metadata.opts[35]
	in_packet_position_t(offsetof(flow_tnl, metadata) + offsetof(tun_metadata, opts) + 72, 2,  0), // tunnel.metadata.opts[36]
	in_packet_position_t(offsetof(flow_tnl, metadata) + offsetof(tun_metadata, opts) + 74, 2,  0), // tunnel.metadata.opts[37]
	in_packet_position_t(offsetof(flow_tnl, metadata) + offsetof(tun_metadata, opts) + 76, 2,  0), // tunnel.metadata.opts[38]
	in_packet_position_t(offsetof(flow_tnl, metadata) + offsetof(tun_metadata, opts) + 78, 2,  0), // tunnel.metadata.opts[39]
	in_packet_position_t(offsetof(flow_tnl, metadata) + offsetof(tun_metadata, opts) + 80, 2,  0), // tunnel.metadata.opts[40]
	in_packet_position_t(offsetof(flow_tnl, metadata) + offsetof(tun_metadata, opts) + 82, 2,  0), // tunnel.metadata.opts[41]
	in_packet_position_t(offsetof(flow_tnl, metadata) + offsetof(tun_metadata, opts) + 84, 2,  0), // tunnel.metadata.opts[42]
	in_packet_position_t(offsetof(flow_tnl, metadata) + offsetof(tun_metadata, opts) + 86, 2,  0), // tunnel.metadata.opts[43]
	in_packet_position_t(offsetof(flow_tnl, metadata) + offsetof(tun_metadata, opts) + 88, 2,  0), // tunnel.metadata.opts[44]
	in_packet_position_t(offsetof(flow_tnl, metadata) + offsetof(tun_metadata, opts) + 90, 2,  0), // tunnel.metadata.opts[45]
	in_packet_position_t(offsetof(flow_tnl, metadata) + offsetof(tun_metadata, opts) + 92, 2,  0), // tunnel.metadata.opts[46]
	in_packet_position_t(offsetof(flow_tnl, metadata) + offsetof(tun_metadata, opts) + 94, 2,  0), // tunnel.metadata.opts[47]
	in_packet_position_t(offsetof(flow_tnl, metadata) + offsetof(tun_metadata, opts) + 96, 2,  0), // tunnel.metadata.opts[48]
	in_packet_position_t(offsetof(flow_tnl, metadata) + offsetof(tun_metadata, opts) + 98, 2,  0), // tunnel.metadata.opts[49]
	in_packet_position_t(offsetof(flow_tnl, metadata) + offsetof(tun_metadata, opts) + 100, 2,  0), // tunnel.metadata.opts[50]
	in_packet_position_t(offsetof(flow_tnl, metadata) + offsetof(tun_metadata, opts) + 102, 2,  0), // tunnel.metadata.opts[51]
	in_packet_position_t(offsetof(flow_tnl, metadata) + offsetof(tun_metadata, opts) + 104, 2,  0), // tunnel.metadata.opts[52]
	in_packet_position_t(offsetof(flow_tnl, metadata) + offsetof(tun_metadata, opts) + 106, 2,  0), // tunnel.metadata.opts[53]
	in_packet_position_t(offsetof(flow_tnl, metadata) + offsetof(tun_metadata, opts) + 108, 2,  0), // tunnel.metadata.opts[54]
	in_packet_position_t(offsetof(flow_tnl, metadata) + offsetof(tun_metadata, opts) + 110, 2,  0), // tunnel.metadata.opts[55]
	in_packet_position_t(offsetof(flow_tnl, metadata) + offsetof(tun_metadata, opts) + 112, 2,  0), // tunnel.metadata.opts[56]
	in_packet_position_t(offsetof(flow_tnl, metadata) + offsetof(tun_metadata, opts) + 114, 2,  0), // tunnel.metadata.opts[57]
	in_packet_position_t(offsetof(flow_tnl, metadata) + offsetof(tun_metadata, opts) + 116, 2,  0), // tunnel.metadata.opts[58]
	in_packet_position_t(offsetof(flow_tnl, metadata) + offsetof(tun_metadata, opts) + 118, 2,  0), // tunnel.metadata.opts[59]
	in_packet_position_t(offsetof(flow_tnl, metadata) + offsetof(tun_metadata, opts) + 120, 2,  0), // tunnel.metadata.opts[60]
	in_packet_position_t(offsetof(flow_tnl, metadata) + offsetof(tun_metadata, opts) + 122, 2,  0), // tunnel.metadata.opts[61]
	in_packet_position_t(offsetof(flow_tnl, metadata) + offsetof(tun_metadata, opts) + 124, 2,  0), // tunnel.metadata.opts[62]
	in_packet_position_t(offsetof(flow_tnl, metadata) + offsetof(tun_metadata, opts) + 126, 2,  0), // tunnel.metadata.opts[63]
	in_packet_position_t(offsetof(flow_tnl, metadata) + offsetof(tun_metadata, opts) + 128, 2,  0), // tunnel.metadata.opts[64]
	in_packet_position_t(offsetof(flow_tnl, metadata) + offsetof(tun_metadata, opts) + 130, 2,  0), // tunnel.metadata.opts[65]
	in_packet_position_t(offsetof(flow_tnl, metadata) + offsetof(tun_metadata, opts) + 132, 2,  0), // tunnel.metadata.opts[66]
	in_packet_position_t(offsetof(flow_tnl, metadata) + offsetof(tun_metadata, opts) + 134, 2,  0), // tunnel.metadata.opts[67]
	in_packet_position_t(offsetof(flow_tnl, metadata) + offsetof(tun_metadata, opts) + 136, 2,  0), // tunnel.metadata.opts[68]
	in_packet_position_t(offsetof(flow_tnl, metadata) + offsetof(tun_metadata, opts) + 138, 2,  0), // tunnel.metadata.opts[69]
	in_packet_position_t(offsetof(flow_tnl, metadata) + offsetof(tun_metadata, opts) + 140, 2,  0), // tunnel.metadata.opts[70]
	in_packet_position_t(offsetof(flow_tnl, metadata) + offsetof(tun_metadata, opts) + 142, 2,  0), // tunnel.metadata.opts[71]
	in_packet_position_t(offsetof(flow_tnl, metadata) + offsetof(tun_metadata, opts) + 144, 2,  0), // tunnel.metadata.opts[72]
	in_packet_position_t(offsetof(flow_tnl, metadata) + offsetof(tun_metadata, opts) + 146, 2,  0), // tunnel.metadata.opts[73]
	in_packet_position_t(offsetof(flow_tnl, metadata) + offsetof(tun_metadata, opts) + 148, 2,  0), // tunnel.metadata.opts[74]
	in_packet_position_t(offsetof(flow_tnl, metadata) + offsetof(tun_metadata, opts) + 150, 2,  0), // tunnel.metadata.opts[75]
	in_packet_position_t(offsetof(flow_tnl, metadata) + offsetof(tun_metadata, opts) + 152, 2,  0), // tunnel.metadata.opts[76]
	in_packet_position_t(offsetof(flow_tnl, metadata) + offsetof(tun_metadata, opts) + 154, 2,  0), // tunnel.metadata.opts[77]
	in_packet_position_t(offsetof(flow_tnl, metadata) + offsetof(tun_metadata, opts) + 156, 2,  0), // tunnel.metadata.opts[78]
	in_packet_position_t(offsetof(flow_tnl, metadata) + offsetof(tun_metadata, opts) + 158, 2,  0), // tunnel.metadata.opts[79]
	in_packet_position_t(offsetof(flow_tnl, metadata) + offsetof(tun_metadata, opts) + 160, 2,  0), // tunnel.metadata.opts[80]
	in_packet_position_t(offsetof(flow_tnl, metadata) + offsetof(tun_metadata, opts) + 162, 2,  0), // tunnel.metadata.opts[81]
	in_packet_position_t(offsetof(flow_tnl, metadata) + offsetof(tun_metadata, opts) + 164, 2,  0), // tunnel.metadata.opts[82]
	in_packet_position_t(offsetof(flow_tnl, metadata) + offsetof(tun_metadata, opts) + 166, 2,  0), // tunnel.metadata.opts[83]
	in_packet_position_t(offsetof(flow_tnl, metadata) + offsetof(tun_metadata, opts) + 168, 2,  0), // tunnel.metadata.opts[84]
	in_packet_position_t(offsetof(flow_tnl, metadata) + offsetof(tun_metadata, opts) + 170, 2,  0), // tunnel.metadata.opts[85]
	in_packet_position_t(offsetof(flow_tnl, metadata) + offsetof(tun_metadata, opts) + 172, 2,  0), // tunnel.metadata.opts[86]
	in_packet_position_t(offsetof(flow_tnl, metadata) + offsetof(tun_metadata, opts) + 174, 2,  0), // tunnel.metadata.opts[87]
	in_packet_position_t(offsetof(flow_tnl, metadata) + offsetof(tun_metadata, opts) + 176, 2,  0), // tunnel.metadata.opts[88]
	in_packet_position_t(offsetof(flow_tnl, metadata) + offsetof(tun_metadata, opts) + 178, 2,  0), // tunnel.metadata.opts[89]
	in_packet_position_t(offsetof(flow_tnl, metadata) + offsetof(tun_metadata, opts) + 180, 2,  0), // tunnel.metadata.opts[90]
	in_packet_position_t(offsetof(flow_tnl, metadata) + offsetof(tun_metadata, opts) + 182, 2,  0), // tunnel.metadata.opts[91]
	in_packet_position_t(offsetof(flow_tnl, metadata) + offsetof(tun_metadata, opts) + 184, 2,  0), // tunnel.metadata.opts[92]
	in_packet_position_t(offsetof(flow_tnl, metadata) + offsetof(tun_metadata, opts) + 186, 2,  0), // tunnel.metadata.opts[93]
	in_packet_position_t(offsetof(flow_tnl, metadata) + offsetof(tun_metadata, opts) + 188, 2,  0), // tunnel.metadata.opts[94]
	in_packet_position_t(offsetof(flow_tnl, metadata) + offsetof(tun_metadata, opts) + 190, 2,  0), // tunnel.metadata.opts[95]
	in_packet_position_t(offsetof(flow_tnl, metadata) + offsetof(tun_metadata, opts) + 192, 2,  0), // tunnel.metadata.opts[96]
	in_packet_position_t(offsetof(flow_tnl, metadata) + offsetof(tun_metadata, opts) + 194, 2,  0), // tunnel.metadata.opts[97]
	in_packet_position_t(offsetof(flow_tnl, metadata) + offsetof(tun_metadata, opts) + 196, 2,  0), // tunnel.metadata.opts[98]
	in_packet_position_t(offsetof(flow_tnl, metadata) + offsetof(tun_metadata, opts) + 198, 2,  0), // tunnel.metadata.opts[99]
	in_packet_position_t(offsetof(flow_tnl, metadata) + offsetof(tun_metadata, opts) + 200, 2,  0), // tunnel.metadata.opts[100]
	in_packet_position_t(offsetof(flow_tnl, metadata) + offsetof(tun_metadata, opts) + 202, 2,  0), // tunnel.metadata.opts[101]
	in_packet_position_t(offsetof(flow_tnl, metadata) + offsetof(tun_metadata, opts) + 204, 2,  0), // tunnel.metadata.opts[102]
	in_packet_position_t(offsetof(flow_tnl, metadata) + offsetof(tun_metadata, opts) + 206, 2,  0), // tunnel.metadata.opts[103]
	in_packet_position_t(offsetof(flow_tnl, metadata) + offsetof(tun_metadata, opts) + 208, 2,  0), // tunnel.metadata.opts[104]
	in_packet_position_t(offsetof(flow_tnl, metadata) + offsetof(tun_metadata, opts) + 210, 2,  0), // tunnel.metadata.opts[105]
	in_packet_position_t(offsetof(flow_tnl, metadata) + offsetof(tun_metadata, opts) + 212, 2,  0), // tunnel.metadata.opts[106]
	in_packet_position_t(offsetof(flow_tnl, metadata) + offsetof(tun_metadata, opts) + 214, 2,  0), // tunnel.metadata.opts[107]
	in_packet_position_t(offsetof(flow_tnl, metadata) + offsetof(tun_metadata, opts) + 216, 2,  0), // tunnel.metadata.opts[108]
	in_packet_position_t(offsetof(flow_tnl, metadata) + offsetof(tun_metadata, opts) + 218, 2,  0), // tunnel.metadata.opts[109]
	in_packet_position_t(offsetof(flow_tnl, metadata) + offsetof(tun_metadata, opts) + 220, 2,  0), // tunnel.metadata.opts[110]
	in_packet_position_t(offsetof(flow_tnl, metadata) + offsetof(tun_metadata, opts) + 222, 2,  0), // tunnel.metadata.opts[111]
	in_packet_position_t(offsetof(flow_tnl, metadata) + offsetof(tun_metadata, opts) + 224, 2,  0), // tunnel.metadata.opts[112]
	in_packet_position_t(offsetof(flow_tnl, metadata) + offsetof(tun_metadata, opts) + 226, 2,  0), // tunnel.metadata.opts[113]
	in_packet_position_t(offsetof(flow_tnl, metadata) + offsetof(tun_metadata, opts) + 228, 2,  0), // tunnel.metadata.opts[114]
	in_packet_position_t(offsetof(flow_tnl, metadata) + offsetof(tun_metadata, opts) + 230, 2,  0), // tunnel.metadata.opts[115]
	in_packet_position_t(offsetof(flow_tnl, metadata) + offsetof(tun_metadata, opts) + 232, 2,  0), // tunnel.metadata.opts[116]
	in_packet_position_t(offsetof(flow_tnl, metadata) + offsetof(tun_metadata, opts) + 234, 2,  0), // tunnel.metadata.opts[117]
	in_packet_position_t(offsetof(flow_tnl, metadata) + offsetof(tun_metadata, opts) + 236, 2,  0), // tunnel.metadata.opts[118]
	in_packet_position_t(offsetof(flow_tnl, metadata) + offsetof(tun_metadata, opts) + 238, 2,  0), // tunnel.metadata.opts[119]
	in_packet_position_t(offsetof(flow_tnl, metadata) + offsetof(tun_metadata, opts) + 240, 2,  0), // tunnel.metadata.opts[120]
	in_packet_position_t(offsetof(flow_tnl, metadata) + offsetof(tun_metadata, opts) + 242, 2,  0), // tunnel.metadata.opts[121]
	in_packet_position_t(offsetof(flow_tnl, metadata) + offsetof(tun_metadata, opts) + 244, 2,  0), // tunnel.metadata.opts[122]
	in_packet_position_t(offsetof(flow_tnl, metadata) + offsetof(tun_metadata, opts) + 246, 2,  0), // tunnel.metadata.opts[123]
	in_packet_position_t(offsetof(flow_tnl, metadata) + offsetof(tun_metadata, opts) + 248, 2,  0), // tunnel.metadata.opts[124]
	in_packet_position_t(offsetof(flow_tnl, metadata) + offsetof(tun_metadata, opts) + 250, 2,  0), // tunnel.metadata.opts[125]
	in_packet_position_t(offsetof(flow_tnl, metadata) + offsetof(tun_metadata, opts) + 252, 2,  0), // tunnel.metadata.opts[126]
	in_packet_position_t(offsetof(flow_tnl, metadata) + offsetof(tun_metadata, opts) + 254, 2,  0), // tunnel.metadata.opts[127]
	in_packet_position_t(offsetof(flow, metadata) + 0, 2,  1), // metadata-0
	in_packet_position_t(offsetof(flow, metadata) + 2, 2,  1), // metadata-2
	in_packet_position_t(offsetof(flow, metadata) + 4, 2,  1), // metadata-4
	in_packet_position_t(offsetof(flow, metadata) + 6, 2,  1), // metadata-6
	in_packet_position_t(offsetof(flow, regs) + 0 + 2, 2,  0), // regs[0]-2
	in_packet_position_t(offsetof(flow, regs) + 0 + 0, 2,  0), // regs[0]-0
	in_packet_position_t(offsetof(flow, regs) + 4 + 2, 2,  0), // regs[1]-2
	in_packet_position_t(offsetof(flow, regs) + 4 + 0, 2,  0), // regs[1]-0
	in_packet_position_t(offsetof(flow, regs) + 8 + 2, 2,  0), // regs[2]-2
	in_packet_position_t(offsetof(flow, regs) + 8 + 0, 2,  0), // regs[2]-0
	in_packet_position_t(offsetof(flow, regs) + 12 + 2, 2,  0), // regs[3]-2
	in_packet_position_t(offsetof(flow, regs) + 12 + 0, 2,  0), // regs[3]-0
	in_packet_position_t(offsetof(flow, regs) + 16 + 2, 2,  0), // regs[4]-2
	in_packet_position_t(offsetof(flow, regs) + 16 + 0, 2,  0), // regs[4]-0
	in_packet_position_t(offsetof(flow, regs) + 20 + 2, 2,  0), // regs[5]-2
	in_packet_position_t(offsetof(flow, regs) + 20 + 0, 2,  0), // regs[5]-0
	in_packet_position_t(offsetof(flow, regs) + 24 + 2, 2,  0), // regs[6]-2
	in_packet_position_t(offsetof(flow, regs) + 24 + 0, 2,  0), // regs[6]-0
	in_packet_position_t(offsetof(flow, regs) + 28 + 2, 2,  0), // regs[7]-2
	in_packet_position_t(offsetof(flow, regs) + 28 + 0, 2,  0), // regs[7]-0
	in_packet_position_t(offsetof(flow, regs) + 32 + 2, 2,  0), // regs[8]-2
	in_packet_position_t(offsetof(flow, regs) + 32 + 0, 2,  0), // regs[8]-0
	in_packet_position_t(offsetof(flow, regs) + 36 + 2, 2,  0), // regs[9]-2
	in_packet_position_t(offsetof(flow, regs) + 36 + 0, 2,  0), // regs[9]-0
	in_packet_position_t(offsetof(flow, regs) + 40 + 2, 2,  0), // regs[10]-2
	in_packet_position_t(offsetof(flow, regs) + 40 + 0, 2,  0), // regs[10]-0
	in_packet_position_t(offsetof(flow, regs) + 44 + 2, 2,  0), // regs[11]-2
	in_packet_position_t(offsetof(flow, regs) + 44 + 0, 2,  0), // regs[11]-0
	in_packet_position_t(offsetof(flow, regs) + 48 + 2, 2,  0), // regs[12]-2
	in_packet_position_t(offsetof(flow, regs) + 48 + 0, 2,  0), // regs[12]-0
	in_packet_position_t(offsetof(flow, regs) + 52 + 2, 2,  0), // regs[13]-2
	in_packet_position_t(offsetof(flow, regs) + 52 + 0, 2,  0), // regs[13]-0
	in_packet_position_t(offsetof(flow, regs) + 56 + 2, 2,  0), // regs[14]-2
	in_packet_position_t(offsetof(flow, regs) + 56 + 0, 2,  0), // regs[14]-0
	in_packet_position_t(offsetof(flow, regs) + 60 + 2, 2,  0), // regs[15]-2
	in_packet_position_t(offsetof(flow, regs) + 60 + 0, 2,  0), // regs[15]-0
	in_packet_position_t(offsetof(flow, skb_priority) + 2, 2,  0), // skb_priority-2
	in_packet_position_t(offsetof(flow, skb_priority) + 0, 2,  0), // skb_priority-0
	in_packet_position_t(offsetof(flow, pkt_mark) + 2, 2,  0), // pkt_mark-2
	in_packet_position_t(offsetof(flow, pkt_mark) + 0, 2,  0), // pkt_mark-0
	in_packet_position_t(offsetof(flow, dp_hash) + 2, 2,  0), // dp_hash-2
	in_packet_position_t(offsetof(flow, dp_hash) + 0, 2,  0), // dp_hash-0
	in_packet_position_t(offsetof(flow, in_port) + 2, 2,  0), // in_port-2
	in_packet_position_t(offsetof(flow, in_port) + 0, 2,  0), // in_port-0
	in_packet_position_t(offsetof(flow, recirc_id) + 2, 2,  0), // recirc_id-2
	in_packet_position_t(offsetof(flow, recirc_id) + 0, 2,  0), // recirc_id-0
	in_packet_position_t(offsetof(flow, ct_state), 1,  0), // ct_state
	in_packet_position_t(offsetof(flow, ct_nw_proto), 1,  0), // ct_nw_proto
	in_packet_position_t(offsetof(flow, ct_zone), 2,  0), // ct_zone
	in_packet_position_t(offsetof(flow, ct_mark) + 2, 2,  0), // ct_mark-2
	in_packet_position_t(offsetof(flow, ct_mark) + 0, 2,  0), // ct_mark-0
	in_packet_position_t(offsetof(flow, packet_type) + 0, 2,  1), // packet_type-0
	in_packet_position_t(offsetof(flow, packet_type) + 2, 2,  1), // packet_type-2
	in_packet_position_t(offsetof(flow, ct_label) + 14, 2,  0), // ct_label-14
	in_packet_position_t(offsetof(flow, ct_label) + 12, 2,  0), // ct_label-12
	in_packet_position_t(offsetof(flow, ct_label) + 10, 2,  0), // ct_label-10
	in_packet_position_t(offsetof(flow, ct_label) + 8, 2,  0), // ct_label-8
	in_packet_position_t(offsetof(flow, ct_label) + 6, 2,  0), // ct_label-6
	in_packet_position_t(offsetof(flow, ct_label) + 4, 2,  0), // ct_label-4
	in_packet_position_t(offsetof(flow, ct_label) + 2, 2,  0), // ct_label-2
	in_packet_position_t(offsetof(flow, ct_label) + 0, 2,  0), // ct_label-0
	in_packet_position_t(offsetof(flow, conj_id) + 2, 2,  0), // conj_id-2
	in_packet_position_t(offsetof(flow, conj_id) + 0, 2,  0), // conj_id-0
	in_packet_position_t(offsetof(flow, actset_output) + 2, 2,  0), // actset_output-2
	in_packet_position_t(offsetof(flow, actset_output) + 0, 2,  0), // actset_output-0
	in_packet_position_t(offsetof(flow, dl_dst) + 0, 2,  1), // dl_dst-0
	in_packet_position_t(offsetof(flow, dl_dst) + 2, 2,  1), // dl_dst-2
	in_packet_position_t(offsetof(flow, dl_dst) + 4, 2,  1), // dl_dst-4
	in_packet_position_t(offsetof(flow, dl_src) + 0, 2,  1), // dl_src-0
	in_packet_position_t(offsetof(flow, dl_src) + 2, 2,  1), // dl_src-2
	in_packet_position_t(offsetof(flow, dl_src) + 4, 2,  1), // dl_src-4
	in_packet_position_t(offsetof(flow, dl_type), 2,  1), // dl_type
	in_packet_position_t(offsetof(flow, vlans) + 0 + 0, 2,  1), // vlans[0]-0
	in_packet_position_t(offsetof(flow, vlans) + 0 + 2, 2,  1), // vlans[0]-2
	in_packet_position_t(offsetof(flow, vlans) + 4 + 0, 2,  1), // vlans[1]-0
	in_packet_position_t(offsetof(flow, vlans) + 4 + 2, 2,  1), // vlans[1]-2
	in_packet_position_t(offsetof(flow, mpls_lse) + 0 + 0, 2,  1), // mpls_lse[0]-0
	in_packet_position_t(offsetof(flow, mpls_lse) + 0 + 2, 2,  1), // mpls_lse[0]-2
	in_packet_position_t(offsetof(flow, mpls_lse) + 4 + 0, 2,  1), // mpls_lse[1]-0
	in_packet_position_t(offsetof(flow, mpls_lse) + 4 + 2, 2,  1), // mpls_lse[1]-2
	in_packet_position_t(offsetof(flow, nw_src) + 0, 2,  1), // nw_src-0
	in_packet_position_t(offsetof(flow, nw_src) + 2, 2,  1), // nw_src-2
	in_packet_position_t(offsetof(flow, nw_dst) + 0, 2,  1), // nw_dst-0
	in_packet_position_t(offsetof(flow, nw_dst) + 2, 2,  1), // nw_dst-2
	in_packet_position_t(offsetof(flow, ct_nw_src) + 0, 2,  1), // ct_nw_src-0
	in_packet_position_t(offsetof(flow, ct_nw_src) + 2, 2,  1), // ct_nw_src-2
	in_packet_position_t(offsetof(flow, ct_nw_dst) + 0, 2,  1), // ct_nw_dst-0
	in_packet_position_t(offsetof(flow, ct_nw_dst) + 2, 2,  1), // ct_nw_dst-2
	in_packet_position_t(offsetof(flow, ipv6_src) + 0, 2,  1), // ipv6_src-0
	in_packet_position_t(offsetof(flow, ipv6_src) + 2, 2,  1), // ipv6_src-2
	in_packet_position_t(offsetof(flow, ipv6_src) + 4, 2,  1), // ipv6_src-4
	in_packet_position_t(offsetof(flow, ipv6_src) + 6, 2,  1), // ipv6_src-6
	in_packet_position_t(offsetof(flow, ipv6_src) + 8, 2,  1), // ipv6_src-8
	in_packet_position_t(offsetof(flow, ipv6_src) + 10, 2,  1), // ipv6_src-10
	in_packet_position_t(offsetof(flow, ipv6_src) + 12, 2,  1), // ipv6_src-12
	in_packet_position_t(offsetof(flow, ipv6_src) + 14, 2,  1), // ipv6_src-14
	in_packet_position_t(offsetof(flow, ipv6_dst) + 0, 2,  1), // ipv6_dst-0
	in_packet_position_t(offsetof(flow, ipv6_dst) + 2, 2,  1), // ipv6_dst-2
	in_packet_position_t(offsetof(flow, ipv6_dst) + 4, 2,  1), // ipv6_dst-4
	in_packet_position_t(offsetof(flow, ipv6_dst) + 6, 2,  1), // ipv6_dst-6
	in_packet_position_t(offsetof(flow, ipv6_dst) + 8, 2,  1), // ipv6_dst-8
	in_packet_position_t(offsetof(flow, ipv6_dst) + 10, 2,  1), // ipv6_dst-10
	in_packet_position_t(offsetof(flow, ipv6_dst) + 12, 2,  1), // ipv6_dst-12
	in_packet_position_t(offsetof(flow, ipv6_dst) + 14, 2,  1), // ipv6_dst-14
	in_packet_position_t(offsetof(flow, ct_ipv6_src) + 0, 2,  1), // ct_ipv6_src-0
	in_packet_position_t(offsetof(flow, ct_ipv6_src) + 2, 2,  1), // ct_ipv6_src-2
	in_packet_position_t(offsetof(flow, ct_ipv6_src) + 4, 2,  1), // ct_ipv6_src-4
	in_packet_position_t(offsetof(flow, ct_ipv6_src) + 6, 2,  1), // ct_ipv6_src-6
	in_packet_position_t(offsetof(flow, ct_ipv6_src) + 8, 2,  1), // ct_ipv6_src-8
	in_packet_position_t(offsetof(flow, ct_ipv6_src) + 10, 2,  1), // ct_ipv6_src-10
	in_packet_position_t(offsetof(flow, ct_ipv6_src) + 12, 2,  1), // ct_ipv6_src-12
	in_packet_position_t(offsetof(flow, ct_ipv6_src) + 14, 2,  1), // ct_ipv6_src-14
	in_packet_position_t(offsetof(flow, ct_ipv6_dst) + 0, 2,  1), // ct_ipv6_dst-0
	in_packet_position_t(offsetof(flow, ct_ipv6_dst) + 2, 2,  1), // ct_ipv6_dst-2
	in_packet_position_t(offsetof(flow, ct_ipv6_dst) + 4, 2,  1), // ct_ipv6_dst-4
	in_packet_position_t(offsetof(flow, ct_ipv6_dst) + 6, 2,  1), // ct_ipv6_dst-6
	in_packet_position_t(offsetof(flow, ct_ipv6_dst) + 8, 2,  1), // ct_ipv6_dst-8
	in_packet_position_t(offsetof(flow, ct_ipv6_dst) + 10, 2,  1), // ct_ipv6_dst-10
	in_packet_position_t(offsetof(flow, ct_ipv6_dst) + 12, 2,  1), // ct_ipv6_dst-12
	in_packet_position_t(offsetof(flow, ct_ipv6_dst) + 14, 2,  1), // ct_ipv6_dst-14
	in_packet_position_t(offsetof(flow, ipv6_label) + 0, 2,  1), // ipv6_label-0
	in_packet_position_t(offsetof(flow, ipv6_label) + 2, 2,  1), // ipv6_label-2
	in_packet_position_t(offsetof(flow, nw_frag), 1,  0), // nw_frag
	in_packet_position_t(offsetof(flow, nw_tos), 1,  0), // nw_tos
	in_packet_position_t(offsetof(flow, nw_ttl), 1,  0), // nw_ttl
	in_packet_position_t(offsetof(flow, nw_proto), 1,  0), // nw_proto
	in_packet_position_t(offsetof(flow, nd_target) + 0, 2,  1), // nd_target-0
	in_packet_position_t(offsetof(flow, nd_target) + 2, 2,  1), // nd_target-2
	in_packet_position_t(offsetof(flow, nd_target) + 4, 2,  1), // nd_target-4
	in_packet_position_t(offsetof(flow, nd_target) + 6, 2,  1), // nd_target-6
	in_packet_position_t(offsetof(flow, nd_target) + 8, 2,  1), // nd_target-8
	in_packet_position_t(offsetof(flow, nd_target) + 10, 2,  1), // nd_target-10
	in_packet_position_t(offsetof(flow, nd_target) + 12, 2,  1), // nd_target-12
	in_packet_position_t(offsetof(flow, nd_target) + 14, 2,  1), // nd_target-14
	in_packet_position_t(offsetof(flow, arp_sha) + 0, 2,  1), // arp_sha-0
	in_packet_position_t(offsetof(flow, arp_sha) + 2, 2,  1), // arp_sha-2
	in_packet_position_t(offsetof(flow, arp_sha) + 4, 2,  1), // arp_sha-4
	in_packet_position_t(offsetof(flow, arp_tha) + 0, 2,  1), // arp_tha-0
	in_packet_position_t(offsetof(flow, arp_tha) + 2, 2,  1), // arp_tha-2
	in_packet_position_t(offsetof(flow, arp_tha) + 4, 2,  1), // arp_tha-4
	in_packet_position_t(offsetof(flow, tcp_flags), 2,  1), // tcp_flags
	in_packet_position_t(offsetof(flow, nsh) + offsetof(ovs_key_nsh, flags), 1,  0), // nsh.flags
	in_packet_position_t(offsetof(flow, nsh) + offsetof(ovs_key_nsh, ttl), 1,  0), // nsh.ttl
	in_packet_position_t(offsetof(flow, nsh) + offsetof(ovs_key_nsh, mdtype), 1,  0), // nsh.mdtype
	in_packet_position_t(offsetof(flow, nsh) + offsetof(ovs_key_nsh, np), 1,  0), // nsh.np
	in_packet_position_t(offsetof(flow, nsh) + offsetof(ovs_key_nsh, path_hdr) + 0, 2,  1), // nsh.path_hdr-0
	in_packet_position_t(offsetof(flow, nsh) + offsetof(ovs_key_nsh, path_hdr) + 2, 2,  1), // nsh.path_hdr-2
	in_packet_position_t(offsetof(flow, nsh) + offsetof(ovs_key_nsh, context) + 0 + 0, 2,  1), // nsh.context[0]-0
	in_packet_position_t(offsetof(flow, nsh) + offsetof(ovs_key_nsh, context) + 0 + 2, 2,  1), // nsh.context[0]-2
	in_packet_position_t(offsetof(flow, nsh) + offsetof(ovs_key_nsh, context) + 4 + 0, 2,  1), // nsh.context[1]-0
	in_packet_position_t(offsetof(flow, nsh) + offsetof(ovs_key_nsh, context) + 4 + 2, 2,  1), // nsh.context[1]-2
	in_packet_position_t(offsetof(flow, nsh) + offsetof(ovs_key_nsh, context) + 8 + 0, 2,  1), // nsh.context[2]-0
	in_packet_position_t(offsetof(flow, nsh) + offsetof(ovs_key_nsh, context) + 8 + 2, 2,  1), // nsh.context[2]-2
	in_packet_position_t(offsetof(flow, nsh) + offsetof(ovs_key_nsh, context) + 12 + 0, 2,  1), // nsh.context[3]-0
	in_packet_position_t(offsetof(flow, nsh) + offsetof(ovs_key_nsh, context) + 12 + 2, 2,  1), // nsh.context[3]-2
	in_packet_position_t(offsetof(flow, tp_src), 2,  1), // tp_src
	in_packet_position_t(offsetof(flow, tp_dst), 2,  1), // tp_dst
	in_packet_position_t(offsetof(flow, ct_tp_src), 2,  1), // ct_tp_src
	in_packet_position_t(offsetof(flow, ct_tp_dst), 2,  1), // ct_tp_dst
	in_packet_position_t(offsetof(flow, igmp_group_ip4) + 0, 2,  1), // igmp_group_ip4-0
	in_packet_position_t(offsetof(flow, igmp_group_ip4) + 2, 2,  1), // igmp_group_ip4-2
};


