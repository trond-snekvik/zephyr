#!/usr/bin/env bash
# Copyright 2021 Nordic Semiconductor
# SPDX-License-Identifier: Apache-2.0

source $(dirname $0)/../../mesh_test.sh

# Test poll timeout
RunTest mesh_friend_poll \
	friendship_friend_est \
	friendship_lpn_poll
