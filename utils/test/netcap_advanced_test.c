// SPDX-License-Identifier: GPL-2.0-or-later
/* Test the real collector and renderer without depending on host sockets. */
#include "../netcap-advanced.c"

static void fail(const char *message)
{
	fprintf(stderr, "%s\n", message);
	exit(EXIT_FAILURE);
}

#ifdef HAVE_NETCAP_BLUETOOTH
static void test_bluetooth_tables(void)
{
	char path[] = "/tmp/netcap-bluetooth-XXXXXX";
	int fd = mkstemp(path);
	FILE *file;
	struct process_info owner = { .pid = 1234 };
	size_t count, i;

	if (fd < 0 || !(file = fdopen(fd, "w")))
		fail("Cannot create Bluetooth table fixture");
	fputs("sk RefCnt Rmem Wmem User Inode Parent\n"
	      "malformed\n"
	      "0 1 0 0 1000 12 0\n"
	      "0 1 0 0 1000 13 0\n", file);
	if (fclose(file))
		fail("Cannot write Bluetooth table fixture");

	/* Keep this independent of sysfs, Bluetooth hardware, and privileges. */
	bt_adapters_loaded = 1;
	strcpy(bt_adapters[0].name, "hci7");
	strcpy(bt_adapters[0].addr, "AA:BB:CC:DD:EE:FF");
	for (count = 0; count <= 2; count++) {
		struct model m = { 0 };
		const char *name = count == 1 ? "hci7" : "hci?";
		const char *addr = count == 1 ? "AA:BB:CC:DD:EE:FF" : "*";

		bt_adapters_n = count;
		if (add_inode_proc(&m, 12, &owner))
			fail("Cannot create socket ownership fixture");
		parse_bluetooth_file(&m, path, "rfcomm");
		parse_bluetooth_file(&m, path, "hci");
		parse_bluetooth_file(&m, path, "hci");
		if (m.eps_n != 2 || strcmp(m.eps[0].proto, "rfcomm") ||
		    strcmp(m.eps[1].proto, "hci"))
			fail("Bluetooth protocols were lost or duplicated");
		for (i = 0; i < m.eps_n; i++) {
			struct endpoint *e = &m.eps[i];

			if (e->plane != PLANE_BLUETOOTH || e->port != 0 ||
			    strcmp(e->ifname, name) || strcmp(e->bind, addr) ||
			    strcmp(e->ifaddr, addr) || e->procs_n != 1 ||
			    e->procs[0] != &owner)
				fail("Bluetooth ownership or adapter fallback changed");
		}
		free_model(&m);
	}
	unlink(path);
}
#endif

int main(void)
{
#ifdef HAVE_NETCAP_BLUETOOTH
	test_bluetooth_tables();
#endif
	puts("Advanced netcap tests passed");
	return 0;
}
