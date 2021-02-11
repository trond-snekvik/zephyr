#!/usr/bin/env bash
# Copyright 2021 Nordic Semiconductor
# SPDX-License-Identifier: Apache-2.0

source $(dirname $0)/../../mesh_test.sh

RunTest transport_loopback transport_tx_loopback transport_rx_none
