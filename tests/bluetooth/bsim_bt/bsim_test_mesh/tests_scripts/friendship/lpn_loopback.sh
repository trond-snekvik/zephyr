#!/usr/bin/env bash
# Copyright 2021 Nordic Semiconductor
# SPDX-License-Identifier: Apache-2.0

source $(dirname $0)/../../mesh_test.sh

# Test LPN sending packets to a group and virtual address it subscribes to
RunTest mesh_friend_msg_mesh \
	friendship_lpn_loopback \
	friendship_friend_est \
