#!/usr/bin/env bash
# Copyright 2021 Nordic Semiconductor
# SPDX-License-Identifier: Apache-2.0

source $(dirname $0)/../../mesh_test.sh

# Test receieves on group and virtual addresses in the LPN
RunTest mesh_friend_msg_mesh \
	friendship_lpn_group \
	friendship_other_group \
	friendship_friend_group \
