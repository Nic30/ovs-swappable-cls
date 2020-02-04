#ifndef CLASSIFIER_PCV_H
#define CLASSIFIER_PCV_H 1

#include "openvswitch/match.h"
#include "openvswitch/meta-flow.h"
#include "pvector.h"
#include "rculist.h"
#include "openvswitch/type-props.h"
#include "versions.h"
#include "lib/classifier.h"

#ifdef __cplusplus
extern "C" {
#endif

/* A flow pcv_classifier. */
struct pcv_classifier {
    void * priv; /* [TODO] place object data directly in struct, problem: resolve size of cls in C */
    bool publish;                   /* Make changes visible to lookups? */
};

/* Constructor/destructor.  Must run single-threaded. */
void pcv_classifier_init(struct pcv_classifier *, const uint8_t *flow_segments);
void pcv_classifier_destroy(struct pcv_classifier *);

/* Modifiers.  Caller MUST exclude concurrent calls from other threads. */
bool pcv_classifier_set_prefix_fields(struct pcv_classifier *,
                                  const enum mf_field_id *trie_fields,
                                  unsigned int n_trie_fields);


void pcv_classifier_insert(struct pcv_classifier *, const struct cls_rule *,
                       ovs_version_t, const struct cls_conjunction *,
                       size_t n_conjunctions);
const struct cls_rule *pcv_classifier_replace(struct pcv_classifier *,
                                          const struct cls_rule *,
                                          ovs_version_t,
                                          const struct cls_conjunction *,
                                          size_t n_conjunctions);
bool pcv_classifier_remove(struct pcv_classifier *, const struct cls_rule *);
void pcv_classifier_remove_assert(struct pcv_classifier *, const struct cls_rule *);
static inline void pcv_classifier_defer(struct pcv_classifier *);
static inline void pcv_classifier_publish(struct pcv_classifier *);

/* Lookups.  These are RCU protected and may run concurrently with modifiers
 * and each other. */
const struct cls_rule *pcv_classifier_lookup(const struct pcv_classifier *,
                                         ovs_version_t, struct flow *,
                                         struct flow_wildcards *);
bool pcv_classifier_rule_overlaps(const struct pcv_classifier *,
                              const struct cls_rule *, ovs_version_t);
const struct cls_rule *pcv_classifier_find_rule_exactly(const struct pcv_classifier *,
                                                    const struct cls_rule *,
                                                    ovs_version_t);
const struct cls_rule *pcv_classifier_find_match_exactly(const struct pcv_classifier *,
                                                     const struct match *,
                                                     int priority,
                                                     ovs_version_t);
const struct cls_rule *pcv_classifier_find_minimatch_exactly(
    const struct pcv_classifier *, const struct minimatch *,
    int priority, ovs_version_t);

bool pcv_classifier_is_empty(const struct pcv_classifier *);
int pcv_classifier_count(const struct pcv_classifier *);

/* Iteration.
 *
 * Iteration is lockless and RCU-protected.  Concurrent threads may perform all
 * kinds of concurrent modifications without ruining the iteration.  Obviously,
 * any modifications may or may not be visible to the concurrent iterator, but
 * all the rules not deleted are visited by the iteration.  The iterating
 * thread may also modify the pcv_classifier rules itself.
 *
 * 'TARGET' iteration only iterates rules matching the 'TARGET' criteria.
 * Rather than looping through all the rules and skipping ones that can't
 * match, 'TARGET' iteration skips whole subtables, if the 'TARGET' happens to
 * be more specific than the subtable. */
struct pcv_cls_cursor {
    const struct pcv_classifier *cls;
    const struct cls_rule *target;
    void * pos;
    const struct cls_rule *rule;
};

struct pcv_cls_cursor pcv_cls_cursor_start(const struct pcv_classifier *,
                                   const struct cls_rule *target,
                                   ovs_version_t);
void pcv_cls_cursor_advance(struct pcv_cls_cursor *);

#define PCV_CLS_FOR_EACH(RULE, MEMBER, CLS)             \
    PCV_CLS_FOR_EACH_TARGET(RULE, MEMBER, CLS, NULL, OVS_VERSION_MAX)
#define PCV_CLS_FOR_EACH_TARGET(RULE, MEMBER, CLS, TARGET, VERSION)         \
    for (struct pcv_cls_cursor cursor__ = pcv_cls_cursor_start(CLS, TARGET, VERSION); \
         (cursor__.rule                                                 \
          ? (INIT_CONTAINER(RULE, cursor__.rule, MEMBER),               \
         pcv_cls_cursor_advance(&cursor__),                             \
             true)                                                      \
          : false);                                                     \
        )


static inline void
pcv_classifier_defer(struct pcv_classifier *cls)
{
    cls->publish = false;
}

static inline void
pcv_classifier_publish(struct pcv_classifier *cls)
{
    cls->publish = true;
}

#ifdef __cplusplus
}
#endif
#endif /* classifier-pcv.h */
