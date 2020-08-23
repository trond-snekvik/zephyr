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

#define STATUS_SUCCESS                     0x00
#define STATUS_INVALID_ADDRESS             0x01
#define STATUS_INVALID_MODEL               0x02
#define STATUS_INVALID_APPKEY              0x03
#define STATUS_INVALID_NETKEY              0x04
#define STATUS_INSUFF_RESOURCES            0x05
#define STATUS_IDX_ALREADY_STORED          0x06
#define STATUS_NVAL_PUB_PARAM              0x07
#define STATUS_NOT_SUB_MOD                 0x08
#define STATUS_STORAGE_FAIL                0x09
#define STATUS_FEAT_NOT_SUPP               0x0a
#define STATUS_CANNOT_UPDATE               0x0b
#define STATUS_CANNOT_REMOVE               0x0c
#define STATUS_CANNOT_BIND                 0x0d
#define STATUS_TEMP_STATE_CHG_FAIL         0x0e
#define STATUS_CANNOT_SET                  0x0f
#define STATUS_UNSPECIFIED                 0x10
#define STATUS_INVALID_BINDING             0x11

typedef uint8_t bt_mesh_status_t;

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