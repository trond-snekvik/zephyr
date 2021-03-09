#!/usr/bin/env bash
# Copyright 2021 Nordic Semiconductor
# SPDX-License-Identifier: Apache-2.0

source $(dirname $0)/../../mesh_test.sh

# Establish a single friendship, wait for first poll timeout
RunTest mesh_friend_establish \
	friendship_friend_est \
	friendship_lpn_est
