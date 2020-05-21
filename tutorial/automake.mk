EXTRA_DIST += \
	tutorial/ovs-sandbox \
	tutorial/t-setup \
	tutorial/t-stage0 \
	tutorial/t-stage1 \
	tutorial/t-stage2 \
	tutorial/t-stage3 \
	tutorial/t-stage4 \
        tutorial/ovs_pcv/ovs_dpdk_pcv.sh \
        tutorial/ovs_pcv/ovs_reboot.sh \
        tutorial/ovs_pcv/ovs_test_iperf.sh

sandbox: all
	cd $(srcdir)/tutorial && MAKE=$(MAKE) HAVE_OPENSSL=$(HAVE_OPENSSL) \
		./ovs-sandbox -b $(abs_builddir) $(SANDBOXFLAGS)
