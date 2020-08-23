/*
 * Copyright (c) 2020 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <bluetooth/mesh.h>

void bt_mesh_model_recv(struct bt_mesh_msg_ctx * ctx, struct net_buf_simple *buf);
void bt_mesh_comp_provision(uint16_t addr);
bool bt_mesh_addr_rx(uint16_t dst);
void bt_mesh_attention(uint8_t duration);
void bt_mesh_heartbeat(uint16_t src, uint16_t dst, uint8_t hops, uint16_t feat);

// events
void bt_mesh_iv_update_recv(uint32_t iv_index);
