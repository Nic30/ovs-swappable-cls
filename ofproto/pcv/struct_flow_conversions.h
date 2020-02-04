#pragma once

#include <byteswap.h>

#include <pcv/rule_parser/rule_vec_utils.h>
#include "classifier-pcv-private.h"

// used for on demand data extraction form the struct_flow
extern typename PcvClassifier::packet_spec_t struct_flow_packet_spec;
// used for dumping of the classifier to a tree in "dot" format
extern typename PcvClassifier::formaters_t struct_flow_packet_formaters;
extern typename PcvClassifier::names_t struct_flow_packet_names;



inline void flow_to_array(const struct flow * f,
        const struct flow_wildcards * masks,
        std::array<pcv::Range1d<uint16_t>, struct_flow_D> & _r) {
    auto _masks = &masks->masks;

    uint16_t i = 0;
    for (auto spec : struct_flow_packet_spec) {
        auto _v =
                reinterpret_cast<const uint16_t*>(&reinterpret_cast<const uint8_t*>(f)[spec.offset]);
        auto _m =
                reinterpret_cast<const uint16_t*>(&reinterpret_cast<const uint8_t*>(_masks)[spec.offset]);
        uint16_t v, m;

        if (spec.is_big_endian) {
            assert(spec.size == 2);
            v = __swab16p(_v);
            m = __swab16p(_m);
        } else {
            v = *_v;
            m = *_m;
        }

        if (spec.size == 1) {
            v &= 0xff;
            m &= 0xff;
            if (m == 0) {
                // to let the classifier known that this field is ignored
                v = 0;
            }
        }
        _r[i] = pcv::Range1d<uint16_t>::from_mask(v, m);
        i++;
    }
}

