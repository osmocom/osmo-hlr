all: \
	proxy_cache_attach.msc \
	proxy_cache_more_tuples.msc \
	proxy_cache_tuple_cache_dry.msc \
	proxy_cache_periodic_lu.msc \
	proxy_cache_umts_aka_resync.msc \
	$(NULL)

png: \
	proxy_cache.png \
	proxy_cache_unused.png \
	lu_attach_and_periodic.png \
	$(NULL)

%.png: %.msc
	mscgen -T png -o $@ $<

%.msc: %.ladder
	@which ladder_to_msc.py || (echo 'PLEASE POINT YOUR $$PATH AT libosmocore/contrib/ladder_to_msc.py' && false)
	ladder_to_msc.py -i $< -o $@
