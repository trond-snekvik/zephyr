#!/usr/bin/env bash
# Copyright 2021 Nordic Semiconductor
# SPDX-License-Identifier: Apache-2.0

source $(dirname $0)/../../mesh_test.sh

# EXTRA_DEVS=1
# RunTest mesh_transport_loopback_group transport_rx_group
RunTest mesh_transport_loopback_group transport_tx_loopback_group transport_rx_group
