#include <config.h>
#include "classifier-pcv.h"

/* Inserts 'rule' into 'cls'.  Until 'rule' is removed from 'cls', the caller
 * must not modify or free it.
 *
 * 'cls' must not contain an identical rule (including wildcards, values of
 * fixed fields, and priority).  Use pcv_classifier_find_rule_exactly() to find
 * such a rule. */
void pcv_classifier_insert(struct pcv_classifier *cls, const struct cls_rule *rule,
        ovs_version_t version, const struct cls_conjunction conj[],
        size_t n_conj) {
    printf(">>>>>>>>>>>pcv_classifier_insert/n");
    const struct cls_rule *displaced_rule = pcv_classifier_replace(cls, rule,
            version, conj, n_conj);
    ovs_assert(!displaced_rule);
}

/* Finds and returns a rule in 'cls' with priority 'priority' and exactly the
 * same matching criteria as 'target', and that is visible in 'version'.
 * Returns a null pointer if 'cls' doesn't contain an exact match visible in
 * 'version'. */
const struct cls_rule *
pcv_classifier_find_match_exactly(const struct pcv_classifier *cls,
                              const struct match *target, int priority,
                              ovs_version_t version)
{
    const struct cls_rule *retval;
    struct cls_rule cr;

    cls_rule_init(&cr, target, priority);
    retval = pcv_classifier_find_rule_exactly(cls, &cr, version);
    cls_rule_destroy(&cr);

    return retval;
}

/* Finds and returns a rule in 'cls' with priority 'priority' and exactly the
 * same matching criteria as 'target', and that is visible in 'version'.
 * Returns a null pointer if 'cls' doesn't contain an exact match visible in
 * 'version'. */
const struct cls_rule *
pcv_classifier_find_minimatch_exactly(const struct pcv_classifier *cls,
                              const struct minimatch *target, int priority,
                              ovs_version_t version)
{
    const struct cls_rule *retval;
    struct cls_rule cr;

    cls_rule_init_from_minimatch(&cr, target, priority);
    retval = pcv_classifier_find_rule_exactly(cls, &cr, version);
    cls_rule_destroy(&cr);

    return retval;
}
