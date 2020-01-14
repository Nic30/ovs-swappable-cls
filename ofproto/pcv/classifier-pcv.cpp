#include "classifier-pcv.h"
#undef atomic_init
#undef atomic_store
#undef atomic_compare_exchange_strong_explicit
#undef atomic_compare_exchange_strong
#undef atomic_compare_exchange_weak_explicit
#undef atomic_compare_exchange_weak

#include "classifier-pcv-private.h"
#include "struct_flow_conversions.h"
#include <assert.h>

pcv_classifier_priv::pcv_classifier_priv() :
		cls(struct_flow_packet_spec, struct_flow_packet_formaters,
				struct_flow_packet_names), next_rule_id(0) {
}

void pcv_classifier_init(struct pcv_classifier *cls, const uint8_t *flow_segments) {
	ovs_assert(flow_segments == nullptr && "not implemented");
	cls->priv = new pcv_classifier_priv();
	cls->publish = true;
}

void pcv_classifier_destroy(struct pcv_classifier *cls) {
	delete (pcv_classifier_priv*) cls->priv;
}

/* Set the fields for which prefix lookup should be performed. */
bool pcv_classifier_set_prefix_fields(
		struct pcv_classifier *cls __attribute__((unused)),
		const enum mf_field_id *trie_fields __attribute__((unused)),
		unsigned int n_fields __attribute__((unused))) {
	return false; /* No change. */
}

/* Inserts 'rule' into 'cls' in 'version'.  Until 'rule' is removed from 'cls',
 * the caller must not modify or free it.
 *
 * If 'cls' already contains an identical rule (including wildcards, values of
 * fixed fields, and priority) that is visible in 'version', replaces the old
 * rule by 'rule' and returns the rule that was replaced.  The caller takes
 * ownership of the returned rule and is thus responsible for destroying it
 * with cls_rule_destroy(), after RCU grace period has passed (see
 * ovsrcu_postpone()).
 *
 * Returns NULL if 'cls' does not contain a rule with an identical key, after
 * inserting the new rule.  In this case, no rules are displaced by the new
 * rule, even rules that cannot have any effect because the new rule matches a
 * superset of their flows and has higher priority.
 */
const struct cls_rule *
pcv_classifier_replace(struct pcv_classifier *cls, const struct cls_rule *rule,
		ovs_version_t version __attribute__((unused)),
		const struct cls_conjunction *conjs __attribute__((unused)),
		size_t n_conjs) {
	auto p = ((pcv_classifier_priv*) cls->priv);
	//auto a = p->to_pcv_rule.find(rule);
	PcvClassifier::rule_spec_t tmp;
	struct match m;
	minimatch_expand(&rule->match, &m);
	flow_to_array(&m.flow, &m.wc, tmp.first);
	tmp.second.rule_id = rule;
	tmp.second.priority = rule->priority;
	assert(n_conjs == 0);
	p->cls.insert(tmp);
	p->to_pcv_rule[rule] = tmp;

	return nullptr;
}

/* If 'rule' is in 'cls', removes 'rule' from 'cls' and returns true.  It is
 * the caller's responsibility to destroy 'rule' with cls_rule_destroy(),
 * freeing the memory block in which 'rule' resides, etc., as necessary.
 *
 * If 'rule' is not in any pcv_classifier, returns false without making any
 * changes.
 *
 * 'rule' must not be in some pcv_classifier other than 'cls'.
 */
bool pcv_classifier_remove(struct pcv_classifier *cls,
		const struct cls_rule *cls_rule) {
	auto p = ((pcv_classifier_priv*) cls->priv);
	auto f = p->to_pcv_rule.find(cls_rule);
	if (f != p->to_pcv_rule.find(cls_rule)) {
		p->cls.remove(f->second);
		return true;
	}
	return false;
}

void pcv_classifier_remove_assert(struct pcv_classifier *cls,
		const struct cls_rule *cls_rule) {
	ovs_assert(pcv_classifier_remove(cls, cls_rule));
}

/* Finds and returns the highest-priority rule in 'cls' that matches 'flow' and
 * that is visible in 'version'.  Returns a null pointer if no rules in 'cls'
 * match 'flow'.  If multiple rules of equal priority match 'flow', returns one
 * arbitrarily.
 *
 * If a rule is found and 'wc' is non-null, bitwise-OR's 'wc' with the
 * set of bits that were significant in the lookup.  At some point
 * earlier, 'wc' should have been initialized (e.g., by
 * flow_wildcards_init_catchall()).
 *
 * 'flow' is non-const to allow for temporary modifications during the lookup.
 * Any changes are restored before returning. */
const struct cls_rule *
pcv_classifier_lookup(const struct pcv_classifier *_cls,
		ovs_version_t version __attribute__((unused)), struct flow *flow,
		struct flow_wildcards *wc) {
	assert(wc == nullptr);
	auto p = ((pcv_classifier_priv*) _cls->priv);
	auto tmp = reinterpret_cast<const uint8_t*>(flow);
	auto res = p->cls.search<const uint8_t*>(tmp);
	return res.rule_id;
}

/* Checks if 'target' would overlap any other rule in 'cls' in 'version'.  Two
 * rules are considered to overlap if both rules have the same priority and a
 * packet could match both, and if both rules are visible in the same version.
 *
 * A trivial example of overlapping rules is two rules matching disjoint sets
 * of fields. E.g., if one rule matches only on port number, while another only
 * on dl_type, any packet from that specific port and with that specific
 * dl_type could match both, if the rules also have the same priority. */
bool pcv_classifier_rule_overlaps(
		const struct pcv_classifier *cls __attribute__((unused)),
		const struct cls_rule *target __attribute__((unused)),
		ovs_version_t version __attribute__((unused))) {
	return false;
}

/* Finds and returns a rule in 'cls' with exactly the same priority and
 * matching criteria as 'target', and that is visible in 'version'.
 * Only one such rule may ever exist.  Returns a null pointer if 'cls' doesn't
 * contain an exact match. */
const struct cls_rule *
pcv_classifier_find_rule_exactly(
		const struct pcv_classifier *cls __attribute__((unused)),
		const struct cls_rule *target __attribute__((unused)),
		ovs_version_t version __attribute__((unused))) {
	// [TODO]
	return nullptr;
}

/* Returns true if 'cls' contains no classification rules, false otherwise.
 * Checking the cmap requires no locking. */
bool pcv_classifier_is_empty(const struct pcv_classifier *_cls) {
	auto p = ((pcv_classifier_priv*) _cls->priv);
	return p->cls.rule_to_tree.empty();
}

/* Returns the number of rules in 'cls'. */
int pcv_classifier_count(const struct pcv_classifier *cls) {
	/* n_rules is an int, so in the presence of concurrent writers this will
	 * return either the old or a new value. */
	return ((PcvClassifier*) cls)->rule_to_tree.size();
}

struct pcv_cls_cursor_pos {
	std::unordered_map<const struct cls_rule*, PcvClassifier::rule_spec_t>::iterator pos;
};

struct pcv_cls_cursor pcv_cls_cursor_start(const struct pcv_classifier * cls,
		const struct cls_rule *target,
		ovs_version_t ver __attribute__((unused))) {
	pcv_cls_cursor c;
	c.cls = cls;
	auto p = reinterpret_cast<pcv_classifier_priv*>(cls->priv);
	auto it = p->to_pcv_rule.begin();
	static_assert(sizeof(it) == sizeof(c.pos));
	auto priv = new pcv_cls_cursor_pos;
	priv->pos = it;
	c.pos = reinterpret_cast<void*>(priv);
	c.rule = it->first;
	c.target = target;
	return c;
}

void pcv_cls_cursor_advance(struct pcv_cls_cursor * cur) {
	auto p = reinterpret_cast<pcv_classifier_priv*>(cur->cls->priv);
	auto it = reinterpret_cast<pcv_cls_cursor_pos *>(cur->pos);
	if (cur->rule == nullptr || cur->rule == cur->target || it == nullptr
			|| it->pos == p->to_pcv_rule.end()) {
		cur->rule = nullptr;
		delete reinterpret_cast<pcv_cls_cursor_pos *>(cur->pos);
		cur->pos = nullptr;
		return;
	} else {
		++it->pos;
		cur->rule = it->pos->first;
	}
}
