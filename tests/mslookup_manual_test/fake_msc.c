#include <osmocom/core/logging.h>
#include <osmocom/core/select.h>
#include <osmocom/core/application.h>
#include <osmocom/gsupclient/gsup_client.h>

void *ctx;

int gsup_client_read_cb(struct osmo_gsup_client *gsupc, struct msgb *msg)
{
	struct osmo_gsup_message gsup;
	if (osmo_gsup_decode(msgb_l2(msg), msgb_l2len(msg), &gsup)) {
		printf("fake_msc: GSUP rx, but failed to decode\n");
		return 0;
	}
	printf("fake_msc: GSUP rx %s %s (destination_name=%s)\n",
	       gsup.imsi, osmo_gsup_message_type_name(gsup.message_type),
	       osmo_quote_str((const char*)gsup.destination_name, gsup.destination_name_len));
	return 0;
}

struct osmo_gsup_client *gsupc;
struct osmo_timer_list do_stuff_timer;

static void gsup_send(const struct osmo_gsup_message *gsup)
{
	printf("fake_msc: GSUP tx %s %s\n", gsup->imsi, osmo_gsup_message_type_name(gsup->message_type));
	osmo_gsup_client_enc_send(gsupc, gsup);
}

void do_stuff(void *data)
{
	static int i = 0;
	int seq = 0;
	if (i == seq++) {
		struct osmo_gsup_message gsup = {
			.message_type = OSMO_GSUP_MSGT_SEND_AUTH_INFO_REQUEST,
			.imsi = "222222",
			.cn_domain = OSMO_GSUP_CN_DOMAIN_CS,
		};
		gsup_send(&gsup);
	}

	seq += 3;
	if (i == seq++) {
		struct osmo_gsup_message gsup = {
			.message_type = OSMO_GSUP_MSGT_UPDATE_LOCATION_REQUEST,
			.imsi = "222222",
			.cn_domain = OSMO_GSUP_CN_DOMAIN_CS,
		};
		gsup_send(&gsup);
	}

	seq += 60;
	if (i == seq++) {
		exit(0);
	}

	i++;
	osmo_timer_schedule(&do_stuff_timer, 1, 0);
}

int main()
{
	ctx = talloc_named_const(NULL, 0, "main");
	osmo_init_logging2(ctx, NULL);

	log_set_print_filename(osmo_stderr_target, 0);
	log_set_print_level(osmo_stderr_target, 0);
	log_set_print_category(osmo_stderr_target, 0);
	log_set_print_category_hex(osmo_stderr_target, 0);
	log_set_use_color(osmo_stderr_target, 0);
	log_set_category_filter(osmo_stderr_target, DLMSLOOKUP, true, LOGL_DEBUG);

	struct ipaccess_unit gsup_client_name = {
		.unit_name = "fake-msc-1",
		.serno = "fake-msc-1",
	};
	gsupc = osmo_gsup_client_create2(ctx, &gsup_client_name, "127.0.0.1", OSMO_GSUP_PORT, gsup_client_read_cb,
					 NULL);

	osmo_timer_setup(&do_stuff_timer, do_stuff, NULL);
	osmo_timer_schedule(&do_stuff_timer, 1, 0);
	for (;;) {
		osmo_select_main_ctx(0);
	}
}
