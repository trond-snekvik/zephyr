#!/usr/bin/env bash
# Copyright 2021 Nordic Semiconductor
# SPDX-License-Identifier: Apache-2.0

source $(dirname $0)/../../mesh_test.sh

# Test communication between the LPN and a third mesh device
RunTest mesh_friend_msg_mesh \
	friendship_lpn_msg_mesh \
	friendship_other_msg \
	friendship_friend_est \
