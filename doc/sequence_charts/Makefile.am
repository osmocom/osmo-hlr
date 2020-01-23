all:
	echo "built only on manual invocation, needs mscgen and dot (graphviz) programs: invoke 'make charts'"

charts: msc dot

EXTRA_DIST = \
	proxy_cache.dot \
	proxy_cache__mm_fsm.dot \
	proxy_cache__to_home_hlr_fsm.dot \
	$(NULL)

CLEANFILES = \
	proxy_cache.png \
	proxy_cache__mm_fsm.png \
	proxy_cache__to_home_hlr_fsm.png \
	$(NULL)

msc: \
	$(NULL)

dot: \
	$(builddir)/proxy_cache.png \
	$(builddir)/proxy_cache__mm_fsm.png \
	$(builddir)/proxy_cache__to_home_hlr_fsm.png \
	$(NULL)

$(builddir)/%.png: %.msc
	mscgen -T png -o $@ $<

$(builddir)/%.msc: $(srcdir)/%.ladder
	@which ladder_to_msc.py || (echo 'PLEASE POINT YOUR $$PATH AT libosmocore/contrib/ladder_to_msc.py' && false)
	ladder_to_msc.py -i $< -o $@

$(builddir)/%.png: $(srcdir)/%.dot
	dot -Tpng $< > $@

.PHONY: poll
poll:
	while true; do $(MAKE) msc dot; sleep 1; done
