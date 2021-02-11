/*
 * Copyright (c) 2021 Nordic Semiconductor
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "bstests.h"
#include "mesh_test.h"
#include <signal.h>

extern struct bst_test_list *
test_transport_install(struct bst_test_list *tests);
extern struct bst_test_list *
test_friendship_install(struct bst_test_list *tests);

bst_test_install_t test_installers[] = {
	test_transport_install,
	test_friendship_install,
	NULL
};

static void sigsegv_handler(int sig)
{
	FAIL("Segmentation fault");
}

void main(void)
{
	signal(SIGSEGV, sigsegv_handler);
	bst_main();
}
