/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* change_id_transition_test.c -- unprivileged credential transition tests
 * Copyright 2026 Red Hat Inc.
 * All Rights Reserved.
 */

#include "config.h"
#include "../cap-ng.h"
#include <errno.h>
#include <grp.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>

static struct __user_cap_data_struct current_caps[2];
static unsigned int group_calls;

/*
 * check - require a transition invariant.
 * @condition: nonzero when the invariant holds.
 * @message: diagnostic on failure.
 *
 * Returns no value; terminates the test on failure.
 */
static void check(int condition, const char *message)
{
	if (!condition) {
		fprintf(stderr, "%s\n", message);
		exit(EXIT_FAILURE);
	}
}

/*
 * capget - provide a fixed capability ABI and simulated process state.
 * @header: requested ABI, updated during version discovery.
 * @data: destination capability words, or NULL for discovery.
 *
 * Returns 0 on a read, -1 with EINVAL for version discovery.
 */
int capget(cap_user_header_t header, const cap_user_data_t data)
{
	header->version = _LINUX_CAPABILITY_VERSION_3;
	if (!data) {
		errno = EINVAL;
		return -1;
	}
	memcpy(data, current_caps, sizeof(current_caps));
	return 0;
}

/*
 * capset - enforce the capability subset rules relevant to this test.
 * @header: capability ABI selected by the library.
 * @data: requested process capabilities.
 *
 * Returns 0 on success, -1 if effective exceeds permitted or permitted grows.
 * No kernel credentials are changed by this test executable.
 */
int capset(cap_user_header_t header, cap_user_data_t data)
{
	size_t i;

	check(header->version == _LINUX_CAPABILITY_VERSION_3,
	      "Unexpected capability ABI");
	for (i = 0; i < 2; i++) {
		if ((data[i].effective & ~data[i].permitted) ||
		    (data[i].permitted & ~current_caps[i].permitted)) {
			errno = EPERM;
			return -1;
		}
	}
	memcpy(current_caps, data, sizeof(current_caps));
	return 0;
}

/*
 * prctl - allow keepcaps without touching the running test's credentials.
 * @option: requested operation; optional arguments are unused.
 *
 * Returns 0 for keepcaps, -1 with EINVAL for unrelated feature probes.
 */
int prctl(int option, ...)
{
	if (option == PR_SET_KEEPCAPS)
		return 0;
	errno = EINVAL;
	return -1;
}

/*
 * setgroups - check transition-time SETGID without changing real groups.
 * @count: number of requested groups.
 * @groups: requested group IDs.
 *
 * Returns 0 with effective SETGID, -1 with EPERM otherwise.
 */
int setgroups(size_t count, const gid_t *groups)
{
	check(count > 0 && groups != NULL, "Missing supplementary groups");
	group_calls++;
	if (current_caps[0].effective & (1U << CAP_SETGID))
		return 0;
	errno = EPERM;
	return -1;
}

/*
 * getpwuid - resolve the synthetic target without relying on local accounts.
 * @uid: target user ID.
 *
 * Returns the test account; an unexpected lookup fails the test.
 */
struct passwd *getpwuid(uid_t uid)
{
	static struct passwd account = {
		.pw_name = "transition-test", .pw_uid = 42, .pw_gid = 7,
	};

	check(uid == account.pw_uid, "Unexpected user lookup");
	return &account;
}

/*
 * getgrouplist - supply one natural group for the synthetic account.
 * @user: account name.
 * @gid: primary group to include.
 * @groups: output group array.
 * @count: capacity on input, group count on output.
 *
 * Returns 1; the library supplies space for at least one group.
 */
int getgrouplist(const char *user, gid_t gid, gid_t *groups, int *count)
{
	check(!strcmp(user, "transition-test") && *count >= 1,
	      "Unexpected group lookup");
	groups[0] = gid;
	*count = 1;
	return 1;
}

/*
 * initgroups - exercise the same SETGID check as staged group application.
 * @user: account name.
 * @gid: natural primary group.
 *
 * Returns the simulated setgroups result.
 */
int initgroups(const char *user, gid_t gid)
{
	check(!strcmp(user, "transition-test"), "Unexpected initgroups user");
	return setgroups(1, &gid);
}

/*
 * setresuid - verify SETUID is available without changing real user IDs.
 * @real: requested real UID.
 * @effective: requested effective UID.
 * @saved: requested saved UID.
 *
 * Returns 0; unexpected IDs or missing SETUID fail the test.
 */
int setresuid(uid_t real, uid_t effective, uid_t saved)
{
	check(real == 42 && effective == 42 && saved == 42,
	      "Unexpected user transition");
	check(current_caps[0].effective & (1U << CAP_SETUID),
	      "Missing temporary SETUID");
	return 0;
}

/*
 * main - verify group-only transitions and exact final SETGID preservation.
 *
 * Returns success only when each mode works without real process privileges.
 */
int main(void)
{
	const capng_flags_t modes[] = {
		CAPNG_APPLY_STAGED_GROUPS,
		CAPNG_INIT_SUPP_GRP,
		CAPNG_INIT_SUPP_GRP | CAPNG_APPLY_STAGED_GROUPS,
	};
	gid_t group = 8;
	size_t i;
	int retain;

	for (i = 0; i < sizeof(modes) / sizeof(modes[0]); i++) {
		for (retain = 0; retain <= 1; retain++) {
			memset(current_caps, 0, sizeof(current_caps));
			current_caps[0].effective = (1U << CAP_SETGID) |
				(1U << CAP_SETUID);
			current_caps[0].permitted = current_caps[0].effective;
			group_calls = 0;
			capng_clear(CAPNG_SELECT_ALL);
			if (retain)
				check(capng_update(CAPNG_ADD, CAPNG_PERMITTED,
						   CAP_SETGID) == 0,
				      "Failed to stage permitted-only SETGID");
			if (modes[i] & CAPNG_APPLY_STAGED_GROUPS)
				check(capng_stage_additional_groups(&group, 1) == 0,
				      "Failed to stage groups");
			check(capng_change_id(i == 0 ? -1 : 42, -1, modes[i]) == 0,
			      "Group-only transition failed");
			check(group_calls == 1, "Groups were not applied once");
			check(current_caps[0].effective == 0 &&
			      current_caps[0].permitted ==
				(retain ? 1U << CAP_SETGID : 0),
			      "Temporary capabilities changed the final request");
			check(capng_change_id(-1, -1,
					     CAPNG_APPLY_STAGED_GROUPS) == -13,
			      "Staged groups were not consumed");
		}
	}
	return EXIT_SUCCESS;
}
