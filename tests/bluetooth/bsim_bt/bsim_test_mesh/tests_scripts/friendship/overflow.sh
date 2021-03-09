#!/usr/bin/env bash
# Copyright 2021 Nordic Semiconductor
# SPDX-License-Identifier: Apache-2.0

source $(dirname $0)/../../mesh_test.sh

# Test friend queue overflow
RunTest mesh_friend_overflow \
	friendship_friend_overflow \
	friendship_lpn_overflow
