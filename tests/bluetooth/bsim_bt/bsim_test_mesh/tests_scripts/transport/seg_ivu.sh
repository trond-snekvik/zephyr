#!/usr/bin/env bash
# Copyright 2021 Nordic Semiconductor
# SPDX-License-Identifier: Apache-2.0

source $(dirname $0)/../../mesh_test.sh

RunTest mesh_transport_seg_ivu transport_tx_seg_ivu transport_rx_seg_ivu
