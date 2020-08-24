/*
 * Copyright (c) 2017 Intel Corporation
 * Copyright (c) 2020 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <string.h>
#include <bluetooth/mesh.h>
#include "mesh.h"
#include "net.h"
#include "settings.h"
#include "crypto.h"
#include "adv.h"
#include "proxy.h"
#include "friend.h"
#include "foundation.h"
#include "access.h"
#include "keys.h"

#define BT_DBG_ENABLED IS_ENABLED(CONFIG_BT_MESH_DEBUG_KEYS)
#define LOG_MODULE_NAME bt_mesh_keys
#include "common/log.h"

struct bt_mesh_subnet_keys {
	uint8_t net[16];       /* NetKey */
	uint8_t nid;           /* NID */
	uint8_t enc[16];       /* EncKey */
	uint8_t net_id[8];     /* Network ID */
#if defined(CONFIG_BT_MESH_GATT_PROXY)
	uint8_t identity[16];  /* IdentityKey */
#endif
	uint8_t privacy[16];   /* PrivacyKey */
	uint8_t beacon[16];    /* BeaconKey */
};

static struct subnet {
	struct bt_mesh_subnet state;
	struct bt_mesh_subnet_keys keys[2];
} subnets[CONFIG_BT_MESH_SUBNET_COUNT] = {
	[0 ... (CONFIG_BT_MESH_SUBNET_COUNT - 1)] = {
		.state.net_idx = BT_MESH_KEY_UNUSED,
	},
};

struct bt_mesh_app_keys {
	uint8_t id;
	uint8_t val[16];
};

static struct app {
	struct bt_mesh_app state;
	struct bt_mesh_app_keys keys[2];
} apps[CONFIG_BT_MESH_APP_KEY_COUNT] = {
	[0 ... (CONFIG_BT_MESH_APP_KEY_COUNT - 1)] = {
		.state.app_idx = BT_MESH_KEY_UNUSED,
		.state.net_idx = BT_MESH_KEY_UNUSED,
	}
};

static uint8_t dev_key[16];

static sys_slist_t app_key_cbs; /* AppKey event handler callbacks */
static sys_slist_t subnet_cbs; /* Subnet event handler callbacks */

static void subnet_evt(struct subnet *sub, enum bt_mesh_key_evt evt)
{
	struct bt_mesh_subnet_cb *cb;

	SYS_SLIST_FOR_EACH_CONTAINER(&subnet_cbs, cb, n) {
		cb->evt_handler(&sub->state, evt);
	}
}

static void app_key_evt(struct app *app, enum bt_mesh_key_evt evt)
{
	struct bt_mesh_app_key_cb *cb;

	SYS_SLIST_FOR_EACH_CONTAINER(&app_key_cbs, cb, n) {
		cb->evt_handler(&app->state, evt);
	}
}

static struct subnet *subnet_get(uint16_t net_idx)
{
	for (int i = 0; i < ARRAY_SIZE(subnets); i++) {
		if (net_idx == subnets[i].state.net_idx) {
			return &subnets[i];
		}
	}

	return NULL;
}

static struct app *app_get(uint16_t app_idx)
{
	for (int i = 0; i < ARRAY_SIZE(apps); i++) {
		if (apps[i].state.app_idx == app_idx) {
			return &apps[i];
		}
	}

	return NULL;
}

static struct app *app_key_alloc(uint16_t app_idx)
{
	struct app *app = NULL;

	for (int i = 0; i < ARRAY_SIZE(apps); i++) {
		/* Check for already existing app_key */
		if (apps[i].state.app_idx == app_idx) {
			return &apps[i];
		}

		if (!app && apps[i].state.app_idx == BT_MESH_KEY_UNUSED) {
			app = &apps[i];
		}
	}

	return app;
}

static struct subnet *subnet_alloc(uint16_t net_idx)
{
	struct subnet *sub = NULL;

	for (int i = 0; i < ARRAY_SIZE(subnets); i++) {
		/* Check for already existing subnet */
		if (subnets[i].state.net_idx == net_idx) {
			return &subnets[i];
		}

		if (!sub && subnets[i].state.net_idx == BT_MESH_KEY_UNUSED) {
			sub = &subnets[i];
		}
	}

	return sub;
}

static void app_key_del(struct app *app)
{
	BT_DBG("AppIdx 0x%03x", app->state.app_idx);

	if (IS_ENABLED(CONFIG_BT_SETTINGS)) {
		bt_mesh_clear_app_key(app);
	}

	app_key_evt(app, BT_MESH_KEY_DELETED);

	app->state.net_idx = BT_MESH_KEY_UNUSED;
	app->state.app_idx = BT_MESH_KEY_UNUSED;
	(void)memset(app->keys, 0, sizeof(app->keys));
}

static void subnet_del(struct subnet *sub)
{
	/* Delete any app keys bound to this NetKey index */
	for (int i = 0; i < ARRAY_SIZE(apps); i++) {
		struct app *app = &apps[i];

		if (app->state.net_idx == sub->state.net_idx) {
			app_key_del(app);
		}
	}

	if (IS_ENABLED(CONFIG_BT_MESH_FRIEND)) {
		bt_mesh_friend_clear_net_idx(sub->state.net_idx); // Callback?
	}

	if (IS_ENABLED(CONFIG_BT_SETTINGS)) {
		bt_mesh_clear_subnet(&sub->state);
	}

	subnet_evt(sub, BT_MESH_KEY_DELETED);
	(void)memset(sub, 0, sizeof(*sub));
	sub->state.net_idx = BT_MESH_KEY_UNUSED;
}

static int beacon_update(struct subnet *sub)
{
	uint8_t flags = bt_mesh_net_flags(&sub->state);
	const struct bt_mesh_subnet_keys *keys;

	if (sub->state.kr_flag) {
		BT_DBG("NetIndex %u Using new key", sub->state.net_idx);
		keys = &sub->keys[1];
	} else {
		BT_DBG("NetIndex %u Using current key", sub->state.net_idx);
		keys = &sub->keys[0];
	}

	BT_DBG("flags 0x%02x, IVI 0x%08x", flags, bt_mesh.iv_index);

	return bt_mesh_beacon_auth(keys->beacon, flags, keys->net_id,
				   bt_mesh.iv_index, sub->state.auth);
}

static int net_keys_create(struct bt_mesh_subnet_keys *keys,
			    const uint8_t key[16])
{
	uint8_t p[] = { 0 };
	uint8_t nid;
	int err;

	err = bt_mesh_k2(key, p, sizeof(p), &nid, keys->enc, keys->privacy);
	if (err) {
		BT_ERR("Unable to generate NID, EncKey & PrivacyKey");
		return err;
	}

	memcpy(keys->net, key, 16);

	keys->nid = nid;

	BT_DBG("NID 0x%02x EncKey %s", keys->nid, bt_hex(keys->enc, 16));
	BT_DBG("PrivacyKey %s", bt_hex(keys->privacy, 16));

	err = bt_mesh_k3(key, keys->net_id);
	if (err) {
		BT_ERR("Unable to generate Net ID");
		return err;
	}

	BT_DBG("NetID %s", bt_hex(keys->net_id, 8));

#if defined(CONFIG_BT_MESH_GATT_PROXY)
	err = bt_mesh_identity_key(key, keys->identity);
	if (err) {
		BT_ERR("Unable to generate IdentityKey");
		return err;
	}

	BT_DBG("IdentityKey %s", bt_hex(keys->identity, 16));
#endif /* GATT_PROXY */

	err = bt_mesh_beacon_key(key, keys->beacon);
	if (err) {
		BT_ERR("Unable to generate beacon key");
		return err;
	}

	BT_DBG("BeaconKey %s", bt_hex(keys->beacon, 16));

	return 0;
}

static void net_keys_revoke(struct subnet *sub)
{
	int i;

	BT_DBG("idx 0x%04x", sub->state.net_idx);

	memcpy(&sub->keys[0], &sub->keys[1], sizeof(sub->keys[0]));
	if (IS_ENABLED(CONFIG_BT_SETTINGS)) {
		BT_DBG("Storing Updated NetKey persistently");
		bt_mesh_store_subnet(sub);
	}

	for (i = 0; i < ARRAY_SIZE(apps); i++) {
		struct app *app = &apps[i];

		if (app->state.net_idx != sub->state.net_idx || !app->state.updated) {
			continue;
		}

		memcpy(&app->keys[0], &app->keys[1], sizeof(app->keys[0]));
		app->state.updated = false;
		if (IS_ENABLED(CONFIG_BT_SETTINGS)) {
			BT_DBG("Storing Updated AppKey persistently");
			bt_mesh_store_app_key(app);
		}
	}
}

bt_mesh_status_t bt_mesh_subnet_add(uint16_t idx, const uint8_t key[16])
{
	struct subnet *sub = NULL;
	int err;

	BT_DBG("idx 0x%04x", idx);

	sub = subnet_alloc(idx);
	if (!sub) {
		return STATUS_INSUFF_RESOURCES;
	}

	if (sub->state.net_idx == idx) {
		if (memcmp(key, sub->keys[0].net, 16)) {
			return STATUS_IDX_ALREADY_STORED;
		}

		return STATUS_SUCCESS;
	}

	err = net_keys_create(&sub->keys[0], key);
	if (err) {
		return STATUS_UNSPECIFIED;
	}

	sub->state.net_idx = idx;

	if (IS_ENABLED(CONFIG_BT_SETTINGS)) {
		BT_DBG("Storing NetKey persistently");
		bt_mesh_store_subnet(sub);
	}

	/* Make sure we have valid beacon data to be sent */
	bt_mesh_net_beacon_update(&sub->state); // TODO: Convert to callback?

	if (IS_ENABLED(CONFIG_BT_MESH_GATT_PROXY)) {
		sub->state.node_id = BT_MESH_NODE_IDENTITY_STOPPED;
		bt_mesh_proxy_beacon_send(&sub->state);
		bt_mesh_adv_update();
	} else {
		sub->state.node_id = BT_MESH_NODE_IDENTITY_NOT_SUPPORTED;
	}

	subnet_evt(sub, BT_MESH_KEY_ADDED);

	return STATUS_SUCCESS;
}

bt_mesh_status_t bt_mesh_subnet_update(uint16_t idx, const uint8_t key[16])
{
	struct subnet *sub;
	int err;

	BT_DBG("idx 0x%04x", idx);

	sub = subnet_get(idx);
	if (!sub) {
		return STATUS_INVALID_NETKEY;
	}

	/* The node shall successfully process a NetKey Update message on a
	 * valid NetKeyIndex when the NetKey value is different and the Key
	 * Refresh procedure has not been started, or when the NetKey value is
	 * the same in Phase 1. The NetKey Update message shall generate an
	 * error when the node is in Phase 2, or Phase 3.
	 */
	switch (sub->state.kr_phase) {
	case BT_MESH_KR_NORMAL:
		if (!memcmp(key, sub->keys[0].net, 16)) {
			return STATUS_IDX_ALREADY_STORED;
		}
		break;
	case BT_MESH_KR_PHASE_1:
		if (!memcmp(key, sub->keys[1].net, 16)) {
			return STATUS_SUCCESS;
		}
		/* fall through */
	case BT_MESH_KR_PHASE_2:
	case BT_MESH_KR_PHASE_3:
		return STATUS_CANNOT_UPDATE;
	}

	err = net_keys_create(&sub->keys[1], key);
	if (err) {
		return STATUS_CANNOT_UPDATE;
	}

	if (IS_ENABLED(CONFIG_BT_MESH_LOW_POWER) ||
	    IS_ENABLED(CONFIG_BT_MESH_FRIEND)) {
		err = friend_cred_update(&sub->state);
		if (err) {
			return STATUS_CANNOT_UPDATE;
		}
	}

	sub->state.kr_phase = BT_MESH_KR_PHASE_1;

	if (IS_ENABLED(CONFIG_BT_SETTINGS)) {
		BT_DBG("Storing NetKey persistently");
		bt_mesh_store_subnet(&sub->state);
	}

	bt_mesh_net_beacon_update(&sub->state); // TODO: Convert to callback? Or remove? The kr_flag state is unchanged.

	return STATUS_SUCCESS;
}

void bt_mesh_subnet_del(uint16_t idx)
{
	struct subnet *sub;

	BT_DBG("idx 0x%04x", idx);

	sub = subnet_get(idx);
	if (!sub) {
		/* This could be a retry of a previous attempt that had its
		 * response lost, so pretend that it was a success.
		 */
		return;
	}

	subnet_del(sub);
}

bt_mesh_status_t bt_mesh_subnet_kr_phase_set(uint16_t idx, uint8_t *phase)
{
	struct subnet *sub;

	BT_DBG("idx 0x%04x", idx);

	sub = subnet_get(idx);
	if (!sub) {
		return STATUS_INVALID_NETKEY;
	}

	BT_DBG("%u -> %u", sub->state.kr_phase, *phase);

	if (*phase < BT_MESH_KR_PHASE_2 || *phase > BT_MESH_KR_PHASE_3 ||
	    (sub->state.kr_phase == BT_MESH_KR_NORMAL &&
	     *phase == BT_MESH_KR_PHASE_2)) {
		BT_WARN("Prohibited transition %u -> %u", sub->state.kr_phase,
			*phase);
		return STATUS_CANNOT_UPDATE;
	}

	if (sub->state.kr_phase == BT_MESH_KR_PHASE_1 &&
	    *phase == BT_MESH_KR_PHASE_2) {
		sub->state.kr_phase = BT_MESH_KR_PHASE_2;
		sub->state.kr_flag = 1;
		bt_mesh_net_beacon_update(&sub->state); // TODO: Move to callback?
		subnet_evt(sub, BT_MESH_KEY_UPDATED);
	} else if ((sub->state.kr_phase == BT_MESH_KR_PHASE_1 ||
		    sub->state.kr_phase == BT_MESH_KR_PHASE_2) &&
		   *phase == BT_MESH_KR_PHASE_3) {
		net_keys_revoke(sub);

		if (IS_ENABLED(CONFIG_BT_MESH_LOW_POWER) ||
		    IS_ENABLED(CONFIG_BT_MESH_FRIEND)) {
			friend_cred_refresh(idx);
		}

		sub->state.kr_phase = BT_MESH_KR_NORMAL;
		sub->state.kr_flag = 0;
		bt_mesh_net_beacon_update(&sub->state);
		subnet_evt(sub, BT_MESH_KEY_UPDATED);
	}

	*phase = sub->state.kr_phase;

	return STATUS_SUCCESS;
}

bt_mesh_status_t bt_mesh_subnet_node_id_set(uint16_t idx, uint8_t node_id)
{
	struct subnet *sub;

	sub = subnet_get(idx);
	if (!sub) {
		return STATUS_INVALID_NETKEY;
	}

	if (!IS_ENABLED(CONFIG_BT_MESH_GATT_PROXY)) {
		return STATUS_FEAT_NOT_SUPP;
	}

	if (node_id) {
		bt_mesh_proxy_identity_start(&sub->state);
	} else {
		bt_mesh_proxy_identity_stop(&sub->state);
	}

	bt_mesh_adv_update();

	return STATUS_SUCCESS;
}

struct bt_mesh_subnet *bt_mesh_subnet_get(uint16_t net_idx)
{
	struct subnet *sub;

	sub = subnet_get(net_idx);
	if (sub) {
		return &sub->state;
	}

	return NULL;
}

int bt_mesh_subnet_set(uint16_t net_idx, bool kr, uint8_t krp,
		       const uint8_t old_key[16], const uint8_t new_key[16])
{
	const uint8_t *keys[] = {old_key, new_key};
	struct subnet *sub;

	sub = subnet_alloc(net_idx);
	if (!sub) {
		return -ENOMEM;
	}

	if (sub->state.net_idx == net_idx) {
		return -EALREADY;
	}

	for (int i = 0; i < ARRAY_SIZE(keys); i++) {
		if (!keys[i]) {
			continue;
		}

		if (net_keys_create(&sub->keys[i], keys[i])) {
			return -EIO;
		}
	}

	sub->state.net_idx = net_idx;
	sub->state.kr_phase = krp;
	sub->state.kr_flag = kr;

	if (IS_ENABLED(CONFIG_BT_MESH_GATT_PROXY)) {
		sub->state.node_id = BT_MESH_NODE_IDENTITY_STOPPED;
	} else {
		sub->state.node_id = BT_MESH_NODE_IDENTITY_NOT_SUPPORTED;
	}

	/* Make sure we have valid beacon data to be sent */
	bt_mesh_net_beacon_update(&sub->state);

	return 0;
}

bool bt_mesh_kr_update(struct bt_mesh_subnet *sub, uint8_t new_kr, bool new_key)
{
	if (new_kr != sub->kr_flag && sub->kr_phase == BT_MESH_KR_NORMAL) {
		BT_WARN("KR change in normal operation. Are we blacklisted?");
		return false;
	}

	sub->kr_flag = new_kr;

	if (sub->kr_flag) {
		if (sub->kr_phase == BT_MESH_KR_PHASE_1) {
			BT_DBG("Phase 1 -> Phase 2");
			sub->kr_phase = BT_MESH_KR_PHASE_2;
			return true;
		}
	} else {
		switch (sub->kr_phase) {
		case BT_MESH_KR_PHASE_1:
			if (!new_key) {
				/* Ignore */
				break;
			}
		/* Upon receiving a Secure Network beacon with the KR flag set
		 * to 0 using the new NetKey in Phase 1, the node shall
		 * immediately transition to Phase 3, which effectively skips
		 * Phase 2.
		 *
		 * Intentional fall-through.
		 */
		case BT_MESH_KR_PHASE_2:
			BT_DBG("KR Phase 0x%02x -> Normal", sub->kr_phase);
			net_keys_revoke(CONTAINER_OF(sub, struct subnet, state));
			if (IS_ENABLED(CONFIG_BT_MESH_LOW_POWER) ||
			    IS_ENABLED(CONFIG_BT_MESH_FRIEND)) {
				friend_cred_refresh(sub->net_idx);
			}
			sub->kr_phase = BT_MESH_KR_NORMAL;
			return true;
		}
	}

	return false;
}

void bt_mesh_subnet_cb_register(struct bt_mesh_subnet_cb *cb)
{
	sys_slist_append(&subnet_cbs, &cb->n);
}

static bool auth_match(struct bt_mesh_subnet_keys *keys,
		       const uint8_t net_id[8], uint8_t flags,
		       uint32_t iv_index, const uint8_t auth[8])
{
	uint8_t net_auth[8];

	if (memcmp(net_id, keys->net_id, 8)) {
		return false;
	}

	bt_mesh_beacon_auth(keys->beacon, flags, keys->net_id, iv_index,
			    net_auth);

	if (memcmp(auth, net_auth, 8)) {
		BT_WARN("Authentication Value %s", bt_hex(auth, 8));
		BT_WARN(" != %s", bt_hex(net_auth, 8));
		return false;
	}

	return true;
}

struct bt_mesh_subnet *bt_mesh_subnet_find(const uint8_t net_id[8],
					   uint8_t flags, uint32_t iv_index,
					   const uint8_t auth[8], bool *new_key)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(subnets); i++) {
		struct subnet *sub = &subnets[i];

		if (sub->state.net_idx == BT_MESH_KEY_UNUSED) {
			continue;
		}

		if (auth_match(&sub->keys[0], net_id, flags, iv_index, auth)) {
			*new_key = false;
			return &sub->state;
		}

		if (sub->state.kr_phase == BT_MESH_KR_NORMAL) {
			continue;
		}

		if (auth_match(&sub->keys[1], net_id, flags, iv_index, auth)) {
			*new_key = true;
			return &sub->state;
		}
	}

	return NULL;
}

bt_mesh_status_t bt_mesh_app_key_add(uint16_t app_idx, uint16_t net_idx,
				     const uint8_t key[16])
{
	struct app *app;

	BT_DBG("net_idx 0x%04x app_idx %04x val %s",
	       net_idx, app_idx, bt_hex(key, 16));

	if (!subnet_get(net_idx)) {
		return STATUS_INVALID_NETKEY;
	}

	app = app_key_alloc(app_idx);
	if (!app) {
		return STATUS_INSUFF_RESOURCES;
	}

	if (app->state.app_idx == app_idx) {
		if (app->state.net_idx != net_idx) {
			return STATUS_INVALID_BINDING;
		}

		if (memcmp(key, app->keys[0].val, 16)) {
			return STATUS_IDX_ALREADY_STORED;
		}

		return STATUS_SUCCESS;
	}

	if (bt_mesh_app_id(key, &app->keys[0].id)) {
		return STATUS_CANNOT_SET;
	}

	BT_DBG("AppIdx 0x%04x AID 0x%02x", app_idx, app->keys[0].id);

	app->state.net_idx = net_idx;
	app->state.app_idx = app_idx;
	app->state.updated = false;
	memcpy(app->keys[0].val, key, 16);

	if (IS_ENABLED(CONFIG_BT_SETTINGS)) {
		BT_DBG("Storing AppKey persistently");
		bt_mesh_store_app_key(app);
	}

	app_key_evt(app, BT_MESH_KEY_ADDED);

	return STATUS_SUCCESS;
}

struct bt_mesh_app *bt_mesh_app_get(uint16_t app_idx)
{
	struct app *app;

	app = app_get(app_idx);
	if (app) {
		return &app->state;
	}

	return NULL;
}

bt_mesh_status_t bt_mesh_app_key_update(uint16_t app_idx, uint16_t net_idx,
					const uint8_t key[16])
{
	struct app *app;
	struct subnet *sub;

	BT_DBG("net_idx 0x%04x app_idx %04x val %s",
	       net_idx, app_idx, bt_hex(key, 16));

	app = app_get(app_idx);
	if (!app) {
		return STATUS_INVALID_APPKEY;
	}

	if (net_idx != BT_MESH_KEY_UNUSED && app->state.net_idx != net_idx) {
		return STATUS_INVALID_BINDING;
	}

	sub = subnet_get(app->state.net_idx);
	if (!sub) {
		return STATUS_INVALID_NETKEY;
	}

	/* The AppKey Update message shall generate an error when node
	 * is in normal operation, Phase 2, or Phase 3 or in Phase 1
	 * when the AppKey Update message on a valid AppKeyIndex when
	 * the AppKey value is different.
	 */
	if (sub->state.kr_phase != BT_MESH_KR_PHASE_1) {
		return STATUS_CANNOT_UPDATE;
	}

	if (app->state.updated) {
		if (memcmp(app->keys[1].val, key, 16)) {
			return STATUS_IDX_ALREADY_STORED;
		}

		return STATUS_SUCCESS;
	}

	if (bt_mesh_app_id(key, &app->keys[1].id)) {
		return STATUS_CANNOT_UPDATE;
	}

	BT_DBG("app_idx 0x%04x AID 0x%02x", app_idx, app->keys[1].id);

	app->state.updated = true;
	memcpy(app->keys[1].val, key, 16);

	if (IS_ENABLED(CONFIG_BT_SETTINGS)) {
		BT_DBG("Storing AppKey persistently");
		bt_mesh_store_app_key(app);
	}

	app_key_evt(app, BT_MESH_KEY_UPDATED);

	return STATUS_SUCCESS;
}

bt_mesh_status_t bt_mesh_app_key_del(uint16_t app_idx, uint16_t net_idx)
{
	struct app *app;

	BT_DBG("AppIdx 0x%03x", app_idx);

	if (net_idx != BT_MESH_KEY_UNUSED && !subnet_get(net_idx)) {
		return STATUS_INVALID_NETKEY;
	}

	app = app_get(app_idx);
	if (!app) {
		/* This could be a retry of a previous attempt that had its
		 * response lost, so pretend that it was a success.
		 */
		return STATUS_SUCCESS;
	}

	if (net_idx != BT_MESH_KEY_UNUSED && net_idx != app->state.net_idx) {
		return STATUS_INVALID_BINDING;
	}

	app_key_del(app);

	return STATUS_SUCCESS;
}

int bt_mesh_app_key_set(uint16_t app_idx, uint16_t net_idx,
			const uint8_t old_key[16], const uint8_t new_key[16])
{
	struct app *app;

	app = app_key_alloc(app_idx);
	if (!app) {
		return -ENOMEM;
	}

	if (app->state.app_idx == app_idx) {
		return 0;
	}

	BT_DBG("AppIdx 0x%04x AID 0x%02x", app_idx, app->keys[0].id);

	memcpy(app->keys[0].val, old_key, 16);
	if (bt_mesh_app_id(old_key, &app->keys[0].id)) {
		return -EIO;
	}

	if (new_key) {
		memcpy(app->keys[1].val, new_key, 16);
		if (bt_mesh_app_id(new_key, &app->keys[1].id)) {
			return -EIO;
		}
	}

	app->state.net_idx = net_idx;
	app->state.app_idx = app_idx;
	app->state.updated = !!new_key;

	return 0;
}

void bt_mesh_app_key_cb_register(struct bt_mesh_app_key_cb *cb)
{
	sys_slist_append(&app_key_cbs, &cb->n);
}

int bt_mesh_keys_resolve(struct bt_mesh_msg_ctx *ctx,
			 struct bt_mesh_subnet **subnet,
			 const uint8_t *app_key[16], uint8_t *aid)
{
	struct subnet *sub = NULL;
	struct app *app = NULL;

	if (BT_MESH_IS_DEV_KEY(ctx->app_idx)) {
		/* With device keys, the application has to decide which subnet
		 * to send on.
		 */
		sub = subnet_get(ctx->net_idx);
		if (!sub) {
			BT_WARN("Unknown NetKey 0x%03x", ctx->net_idx);
			return -EINVAL;
		}

		if (ctx->app_idx == BT_MESH_KEY_DEV_REMOTE &&
		    !bt_mesh_elem_find(ctx->addr)) {
			struct bt_mesh_cdb_node *node;

			if (!IS_ENABLED(CONFIG_BT_MESH_CDB)) {
				BT_WARN("No DevKey for 0x%04x", ctx->addr);
				return -EINVAL;
			}

			node = bt_mesh_cdb_node_get(ctx->addr);
			if (!node) {
				BT_WARN("No DevKey for 0x%04x", ctx->addr);
				return -EINVAL;
			}

			*app_key = node->dev_key;
		} else {
			*app_key = dev_key;
		}

		*aid = 0;
		*subnet = &sub->state;
		return 0;
	}

	app = app_get(ctx->app_idx);
	if (!app) {
		BT_WARN("Unknown AppKey 0x%03x", ctx->app_idx);
		return -EINVAL;
	}

	sub = subnet_get(app->state.net_idx);
	if (!sub) {
		BT_WARN("Unknown NetKey 0x%03x", app->state.net_idx);
		return -EINVAL;
	}

	if (sub->state.kr_phase == BT_MESH_KR_PHASE_2 && app->state.updated) {
		*aid = app->keys[1].id;
		*app_key = app->keys[1].val;
	} else {
		*aid = app->keys[0].id;
		*app_key = app->keys[0].val;
	}

	*subnet = &sub->state;
	return 0;
}

const uint8_t *bt_mesh_app_key_next(struct bt_mesh_net_rx *rx, bool akf,
				    uint8_t aid, const uint8_t *prev)
{
	int i;

	if (!akf) {
		struct bt_mesh_cdb_node *node;

		/* Attempt remote dev key first, as that is only available for
		 * provisioner devices, which normally don't interact with nodes
		 * that know their local dev key.
		 */
		if (IS_ENABLED(CONFIG_BT_MESH_CDB) && !prev) {
			node = bt_mesh_cdb_node_get(rx->ctx.addr);
			if (node) {
				rx->ctx.app_idx = BT_MESH_KEY_DEV_REMOTE;
				return node->dev_key;
			}
		}

		if (prev == dev_key) {
			return NULL;
		}

		rx->ctx.app_idx = BT_MESH_KEY_DEV_LOCAL;
		return dev_key;
	}

	if (prev) {
		i = (CONTAINER_OF(prev, struct app, keys[0].val) - &apps[0]) +
		    1;
	} else {
		i = 0;
	}

	while (i < ARRAY_SIZE(apps)) {
		const struct app *app = &apps[i++];
		const struct bt_mesh_app_keys *keys;

		if (app->state.app_idx == BT_MESH_KEY_UNUSED) {
			continue;
		}

		if (app->state.net_idx != rx->sub->net_idx) {
			continue;
		}

		if (rx->new_key && app->state.updated) {
			keys = &app->keys[1];
		} else {
			keys = &app->keys[0];
		}

		if (keys->id == aid) {
			rx->ctx.app_idx = app->state.app_idx;
			return keys->val;
		}
	}

	return false;
}

int bt_mesh_net_beacon_update(struct bt_mesh_subnet *sub)
{
	return beacon_update(CONTAINER_OF(sub, struct subnet, state));
}

void bt_mesh_keys_reset(void)
{
	int i;

	/* Delete all net keys, which also takes care of all app keys which
	 * are associated with each net key.
	 */
	for (i = 0; i < ARRAY_SIZE(subnets); i++) {
		struct subnet *sub = &subnets[i];

		if (sub->state.net_idx != BT_MESH_KEY_UNUSED) {
			subnet_del(sub);
		}
	}
}

void bt_mesh_subnet_foreach(void (*cb)(struct bt_mesh_subnet *sub, void *cb_data), void *cb_data)
{
	for (int i = 0; i < ARRAY_SIZE(subnets); i++) {
		if (subnets[i].state.net_idx != BT_MESH_KEY_UNUSED) {
			cb(&subnets[i].state, cb_data);
		}
	}
}

void bt_mesh_app_foreach(uint16_t net_idx, void (*cb)(struct bt_mesh_app *app, void *cb_data), void *cb_data)
{
	for (int i = 0; i < ARRAY_SIZE(apps); i++) {
		if (net_idx == BT_MESH_KEY_ANY || net_idx == apps[i].state.net_idx) {
			cb(&apps[i].state, cb_data);
		}
	}
}

const uint8_t *bt_mesh_subnet_id_get(const struct bt_mesh_subnet *sub)
{
	return CONTAINER_OF(sub, struct subnet, state)->keys[sub->kr_flag].net_id;
}

struct bt_mesh_subnet *bt_mesh_subnet_next(struct bt_mesh_subnet *prev)
{
	struct subnet *sub;

	if (prev) {
		sub = (CONTAINER_OF(prev, struct subnet, state)) + 1;
	} else {
		sub = &subnets[0];
	}

	while (sub < &subnets[CONFIG_BT_MESH_SUBNET_COUNT]) {
		if (sub->state.net_idx != BT_MESH_KEY_UNUSED) {
			return &sub->state;
		}

		sub++;
	}

	return NULL;
}

struct bt_mesh_app *bt_mesh_app_next(uint16_t net_idx, struct bt_mesh_app *prev)
{
	struct app *app;

	if (prev) {
		app = (CONTAINER_OF(prev, struct app, state)) + 1;
	} else {
		app = &apps[0];
	}

	while (app < &apps[CONFIG_BT_MESH_APP_KEY_COUNT]) {
		if (app->state.net_idx != BT_MESH_KEY_UNUSED) {
			return &app->state;
		}

		app++;
	}

	return NULL;
}
