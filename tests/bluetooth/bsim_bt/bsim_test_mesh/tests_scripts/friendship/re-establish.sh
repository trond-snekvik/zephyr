#!/usr/bin/env bash
# Copyright 2021 Nordic Semiconductor
# SPDX-License-Identifier: Apache-2.0

source $(dirname $0)/../../mesh_test.sh

# Test friendship re-establishment
RunTest mesh_friend_re_establish \
	friendship_friend_est \
	friendship_lpn_re_est
