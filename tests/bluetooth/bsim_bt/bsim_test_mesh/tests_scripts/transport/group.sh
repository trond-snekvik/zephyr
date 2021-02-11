#!/usr/bin/env bash
# Copyright 2021 Nordic Semiconductor
# SPDX-License-Identifier: Apache-2.0

source $(dirname $0)/../../mesh_test.sh

RunTest mesh_transport_group transport_tx_group transport_rx_group
