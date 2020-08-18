/*
 * Copyright (c) 2020 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <bluetooth/mesh.h>
#include "mesh.h"
#include "net.h"
#include "beacon.h"
#include "settings.h"
#include "heartbeat.h"
#include "friend.h"

void bt_mesh_beacon_set(bool beacon)
{
	if (atomic_test_bit(bt_mesh.flags, BT_MESH_BEACON) == beacon) {
		return;
	}

	atomic_set_bit_to(bt_mesh.flags, BT_MESH_BEACON, beacon);

	if (beacon) {
		bt_mesh_beacon_enable();
	} else {
		bt_mesh_beacon_disable();
	}

	if (IS_ENABLED(CONFIG_BT_SETTINGS)) {
		bt_mesh_store_cfg();
	}
}

bool bt_mesh_beacon_get(void)
{
	return atomic_test_bit(bt_mesh.flags, BT_MESH_BEACON);
}

void bt_mesh_gatt_proxy_set(bool gatt_proxy)
{
	if (!IS_ENABLED(CONFIG_BT_MESH_GATT_PROXY)) {
		return;
	}

	atomic_set_bit_to(bt_mesh.flags, BT_MESH_GATT_PROXY, gatt_proxy);

	bt_mesh_hb_feature_changed(BT_MESH_FEAT_PROXY);

	if (IS_ENABLED(CONFIG_BT_SETTINGS)) {
		bt_mesh_store_cfg();
	}
}

uint8_t bt_mesh_gatt_proxy_get(void)
{
	if (IS_ENABLED(CONFIG_BT_MESH_GATT_PROXY)) {
		return atomic_test_bit(bt_mesh.flags, BT_MESH_GATT_PROXY);
	}

	return BT_MESH_GATT_PROXY_NOT_SUPPORTED;
}

int bt_mesh_default_ttl_set(uint8_t default_ttl)
{
	if (default_ttl == 1 || default_ttl > BT_MESH_TTL_MAX) {
		return -EINVAL;
	}

	if (default_ttl == bt_mesh.default_ttl) {
		return 0;
	}

	bt_mesh.default_ttl = default_ttl;

	if (IS_ENABLED(CONFIG_BT_SETTINGS)) {
		bt_mesh_store_cfg();
	}

	return 0;
}

uint8_t bt_mesh_default_ttl_get(void)
{
	return bt_mesh.default_ttl;
}

void bt_mesh_friend_set(bool friendship)
{
	if (!IS_ENABLED(CONFIG_BT_MESH_FRIEND) ||
	    atomic_test_bit(bt_mesh.flags, BT_MESH_FRIEND) == friendship) {
		return;
	}

	atomic_set_bit_to(bt_mesh.flags, BT_MESH_FRIEND, friendship);

	bt_mesh_hb_feature_changed(BT_MESH_FEAT_FRIEND);

	if (IS_ENABLED(CONFIG_BT_SETTINGS)) {
		bt_mesh_store_cfg();
	}

	if (!friendship) {
		bt_mesh_friend_clear_net_idx(BT_MESH_KEY_ANY);
	}
}

uint8_t bt_mesh_friend_get(void)
{
	if (IS_ENABLED(CONFIG_BT_MESH_FRIEND)) {
		return atomic_test_bit(bt_mesh.flags, BT_MESH_FRIEND);
	}

	return BT_MESH_FRIEND_NOT_SUPPORTED;
}

uint32_t bt_mesh_iv_index_get(void)
{
	return bt_mesh.iv_index;
}

void bt_mesh_net_transmit_set(uint8_t xmit)
{
	if (bt_mesh.net_xmit == xmit) {
		return;
	}

	bt_mesh.net_xmit = xmit;
	if (IS_ENABLED(CONFIG_BT_SETTINGS)) {
		bt_mesh_store_cfg();
	}
}

uint8_t bt_mesh_net_transmit_get(void)
{
	return bt_mesh.net_xmit;
}

void bt_mesh_relay_set(bool relay)
{
	if (!IS_ENABLED(CONFIG_BT_MESH_RELAY) ||
	    relay == atomic_test_bit(bt_mesh.flags, BT_MESH_RELAY)) {
		return;
	}

	atomic_set_bit_to(bt_mesh.flags, BT_MESH_RELAY, relay);

	bt_mesh_hb_feature_changed(BT_MESH_FEAT_RELAY);

	if (IS_ENABLED(CONFIG_BT_SETTINGS)) {
		bt_mesh_store_cfg();
	}

	return;
}

uint8_t bt_mesh_relay_get(void)
{
	return atomic_test_bit(bt_mesh.flags, BT_MESH_RELAY);
}

void bt_mesh_relay_retransmit_set(uint8_t xmit)
{
	if (!IS_ENABLED(CONFIG_BT_MESH_RELAY) || bt_mesh.relay_xmit == xmit) {
		return;
	}

	bt_mesh.relay_xmit = xmit;

	if (IS_ENABLED(CONFIG_BT_SETTINGS)) {
		bt_mesh_store_cfg();
	}
}

uint8_t bt_mesh_relay_retransmit_get(void)
{
	return bt_mesh.relay_xmit;
}

void bt_mesh_cfg_init(void)
{
	bt_mesh.default_ttl = CONFIG_BT_MESH_DEFAULT_TTL;
	bt_mesh.net_xmit =
		BT_MESH_TRANSMIT(CONFIG_BT_MESH_NETWORK_TRANSMIT_COUNT,
				 CONFIG_BT_MESH_NETWORK_TRANSMIT_INTERVAL);

#if defined(CONFIG_BT_MESH_RELAY)
	bt_mesh.relay_xmit =
		BT_MESH_TRANSMIT(CONFIG_BT_MESH_RELAY_RETRANSMIT_COUNT,
				 CONFIG_BT_MESH_RELAY_RETRANSMIT_INTERVAL);
#endif

	if (IS_ENABLED(CONFIG_BT_MESH_RELAY_ENABLED)) {
		atomic_set_bit(bt_mesh.flags, BT_MESH_RELAY);
	}

	if (IS_ENABLED(CONFIG_BT_MESH_BEACON_ENABLED)) {
		atomic_set_bit(bt_mesh.flags, BT_MESH_BEACON);
	}

	if (IS_ENABLED(CONFIG_BT_MESH_GATT_PROXY)) {
		atomic_set_bit(bt_mesh.flags, BT_MESH_GATT_PROXY);
	}

	if (IS_ENABLED(CONFIG_BT_MESH_FRIEND)) {
		atomic_set_bit(bt_mesh.flags, BT_MESH_FRIEND);
	}
}
