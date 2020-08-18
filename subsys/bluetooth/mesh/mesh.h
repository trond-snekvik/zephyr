/*  Bluetooth Mesh */

/*
 * Copyright (c) 2017 Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#define BT_MESH_KEY_PRIMARY 0x0000
#define BT_MESH_KEY_ANY     0xffff

#define BT_MESH_ADDR_IS_UNICAST(addr) ((addr) && (addr) < 0x8000)
#define BT_MESH_ADDR_IS_GROUP(addr) ((addr) >= 0xc000 && (addr) <= 0xff00)
#define BT_MESH_ADDR_IS_VIRTUAL(addr) ((addr) >= 0x8000 && (addr) < 0xc000)
#define BT_MESH_ADDR_IS_RFU(addr) ((addr) >= 0xff00 && (addr) <= 0xfffb)

struct bt_mesh_net;

int bt_mesh_start(void);

void bt_mesh_cfg_init(void);

void bt_mesh_gatt_proxy_set(bool gatt_proxy);
uint8_t bt_mesh_gatt_proxy_get(void);

void bt_mesh_beacon_set(bool beacon);
bool bt_mesh_beacon_get(void);

int bt_mesh_default_ttl_set(uint8_t default_ttl);
uint8_t bt_mesh_default_ttl_get(void);

void bt_mesh_friend_set(bool friendship);
uint8_t bt_mesh_friend_get(void);

void bt_mesh_net_transmit_set(uint8_t xmit);
uint8_t bt_mesh_net_transmit_get(void);

void bt_mesh_relay_set(bool relay);
uint8_t bt_mesh_relay_get(void);

void bt_mesh_relay_retransmit_set(uint8_t xmit);
uint8_t bt_mesh_relay_retransmit_get(void);