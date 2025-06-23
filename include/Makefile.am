SUBDIRS = osmocom

osmocom/%/version.h: osmocom/%/version.h.tpl
	$(AM_V_GEN)$(MKDIR_P) $(dir $@)
	$(AM_V_GEN)sed \
		-e "s/{{VERSION}}/$$(echo '@VERSION@' | cut -d. -f1-3)/g" \
		-e "s/{{VERSION_MAJOR}}/$$(echo '@VERSION@' | cut -d. -f1)/g" \
		-e "s/{{VERSION_MINOR}}/$$(echo '@VERSION@' | cut -d. -f2)/g" \
		-e "s/{{VERSION_PATCH}}/$$(echo '@VERSION@' | cut -d. -f3)/g" \
		$< > $@

nobase_include_HEADERS = \
	osmocom/gsupclient/cni_peer_id.h \
	osmocom/gsupclient/gsup_client.h \
	osmocom/gsupclient/gsup_client_mux.h \
	osmocom/gsupclient/gsup_req.h \
	osmocom/gsupclient/version.h \
	osmocom/mslookup/mdns.h \
	osmocom/mslookup/mdns_sock.h \
	osmocom/mslookup/mslookup_client_fake.h \
	osmocom/mslookup/mslookup_client.h \
	osmocom/mslookup/mslookup_client_mdns.h \
	osmocom/mslookup/mslookup.h \
	osmocom/mslookup/version.h \
	$(NULL)
