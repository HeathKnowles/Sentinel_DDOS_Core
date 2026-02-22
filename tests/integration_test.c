#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "../core/sentinel_types.h"
#include "../featureextractor/feature_extractor.h"
#include "../decisionengine/decision_engine.h"
#include "../feedback/feedback.h"
#include "../sdncontrolplane/sdn_controller.h"

static void test_feature_to_decision_path(void)
{
    fe_config_t fe_cfg = FE_CONFIG_DEFAULT;
    de_thresholds_t de_cfg = DE_THRESHOLDS_DEFAULT;

    fe_context_t *fe = fe_init(&fe_cfg);
    de_context_t *de = de_init(&de_cfg);
    assert(fe != NULL);
    assert(de != NULL);

    fe_packet_t pkt;
    memset(&pkt, 0, sizeof(pkt));
    pkt.src_ip = 0x01020304;
    pkt.dst_ip = 0x05060708;
    pkt.src_port = 0x3930; /* 12345 in network-byte-order literal */
    pkt.dst_port = 0x0050; /* 80 in network-byte-order literal */
    pkt.protocol = 6;
    pkt.payload_len = 60;
    pkt.ttl = 64;
    pkt.tcp_flags = FE_TCP_SYN;

    for (uint32_t i = 0; i < 64; i++) {
        pkt.packet_id = i + 1;
        pkt.timestamp_ns = 1000000000ULL + (uint64_t)i * 1000000ULL;
        assert(fe_ingest_packet(fe, &pkt) == 0);
    }

    sentinel_feature_vector_t fv;
    assert(fe_extract_last(fe, &fv) == 0);

    sentinel_threat_assessment_t ta;
    assert(de_classify(de, &fv, &ta) == 0);
    assert(ta.threat_score >= 0.0 && ta.threat_score <= 1.0);

    de_destroy(de);
    fe_destroy(fe);
}

static void test_feedback_adjustments(void)
{
    fb_config_t cfg = FB_CONFIG_DEFAULT;
    cfg.history_size = 256;
    cfg.evaluation_window_sec = 300;
    fb_context_t *fb = fb_init(&cfg);
    assert(fb != NULL);

    for (int i = 0; i < 32; i++) {
        assert(fb_record_action(fb, 0x0A000001, VERDICT_ALLOW, SENTINEL_ATTACK_NONE, 0.9) == 0);
        assert(fb_auto_detect_fn(fb, 0x0A000001, 0.9) >= 0);
    }

    fb_adjustments_t adj;
    assert(fb_suggest_adjustments(fb, &adj) == 0);
    assert(adj.should_adjust == 0 || adj.should_adjust == 1);

    fb_destroy(fb);
}

static void test_sdn_rule_build(void)
{
    sdn_config_t cfg = SDN_CONFIG_DEFAULT;
    sdn_context_t *sdn = sdn_init(&cfg);
    assert(sdn != NULL);

    sentinel_threat_assessment_t a;
    memset(&a, 0, sizeof(a));
    a.src_ip = 0x0A000002;
    a.dst_ip = 0x0A000003;
    a.src_port = 0x04D2; /* 1234 in network-byte-order literal */
    a.dst_port = 0x0050; /* 80 in network-byte-order literal */
    a.protocol = 6;
    a.attack_type = SENTINEL_ATTACK_SYN_FLOOD;
    a.verdict = VERDICT_DROP;
    a.threat_score = 0.95;

    sentinel_sdn_rule_t r;
    assert(sdn_build_rule_from_assessment(sdn, &a, &r) == 0);
    assert(r.action == SDN_ACTION_DROP);
    assert(r.match_src_ip == a.src_ip);
    assert(r.match_dst_ip == a.dst_ip);
    assert(r.match_protocol == a.protocol);

    sdn_destroy(sdn);
}

int main(void)
{
    printf("=== Sentinel Integration Test Suite ===\n");
    test_feature_to_decision_path();
    test_feedback_adjustments();
    test_sdn_rule_build();
    printf("=== All Tests Passed ===\n");
    return 0;
}
