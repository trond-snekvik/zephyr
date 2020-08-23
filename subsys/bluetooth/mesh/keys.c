/*
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

static void subnet_evt(uint16_t idx, const struct bt_mesh_subnet_flags *state,
		       enum bt_mesh_key_evt evt)
{
	struct bt_mesh_subnet_cb *cb;

	SYS_SLIST_FOR_EACH_CONTAINER(&bt_mesh.subnet_cbs, cb, n) {
		cb->evt_handler(idx, state, evt);
	}
}

static void app_key_evt(uint16_t app_idx, uint16_t net_idx,
			enum bt_mesh_key_evt evt)
{
	struct bt_mesh_app_key_cb *cb;

	SYS_SLIST_FOR_EACH_CONTAINER(&bt_mesh.app_key_cbs, cb, n) {
		cb->evt_handler(app_idx, net_idx, evt);
	}
}

static struct bt_mesh_subnet *subnet_get(uint16_t net_idx)
{
	for (int i = 0; i < ARRAY_SIZE(bt_mesh.sub); i++) {
		if (net_idx == bt_mesh.sub[i].net_idx) {
			return &bt_mesh.sub[i];
		}
	}

	return NULL;
}

static struct bt_mesh_app_key *app_key_get(uint16_t app_idx)
{
	for (int i = 0; i < ARRAY_SIZE(bt_mesh.app_keys); i++) {
		if (bt_mesh.app_keys[i].app_idx == app_idx) {
			return &bt_mesh.app_keys[i];
		}
	}

	return NULL;
}

static struct bt_mesh_app_key *app_key_alloc(uint16_t app_idx)
{
	struct bt_mesh_app_key *app = NULL;

	for (int i = 0; i < ARRAY_SIZE(bt_mesh.app_keys); i++) {
		/* Check for already existing app_key */
		if (bt_mesh.app_keys[i].app_idx == app_idx) {
			return &bt_mesh.app_keys[i];
		}

		if (!app && bt_mesh.app_keys[i].app_idx == BT_MESH_KEY_UNUSED) {
			app = &bt_mesh.app_keys[i];
		}
	}

	return app;
}

static struct bt_mesh_subnet *subnet_alloc(uint16_t net_idx)
{
	struct bt_mesh_subnet *sub = NULL;

	for (int i = 0; i < ARRAY_SIZE(bt_mesh.sub); i++) {
		/* Check for already existing subnet */
		if (bt_mesh.sub[i].net_idx == net_idx) {
			return &bt_mesh.sub[i];
		}

		if (!sub && bt_mesh.sub[i].net_idx == BT_MESH_KEY_UNUSED) {
			sub = &bt_mesh.sub[i];
		}
	}

	return sub;
}

static void app_key_del(struct bt_mesh_app_key *key)
{
	uint16_t app_idx = key->app_idx;
	uint16_t net_idx = key->net_idx;

	BT_DBG("AppIdx 0x%03x", app_idx);

	if (IS_ENABLED(CONFIG_BT_SETTINGS)) {
		bt_mesh_clear_app_key(key);
	}

	key->net_idx = BT_MESH_KEY_UNUSED;
	key->app_idx = BT_MESH_KEY_UNUSED;
	(void)memset(key->keys, 0, sizeof(key->keys));

	app_key_evt(app_idx, net_idx, BT_MESH_KEY_DELETED);
}

static void subnet_del(struct bt_mesh_subnet *sub)
{
	uint16_t idx = sub->net_idx;

	/* Delete any app keys bound to this NetKey index */
	for (int i = 0; i < ARRAY_SIZE(bt_mesh.app_keys); i++) {
		struct bt_mesh_app_key *app = &bt_mesh.app_keys[i];

		if (app->net_idx == sub->net_idx) {
			app_key_del(app);
		}
	}

	if (IS_ENABLED(CONFIG_BT_MESH_FRIEND)) {
		bt_mesh_friend_clear_net_idx(sub->net_idx); // Callback?
	}

	if (IS_ENABLED(CONFIG_BT_SETTINGS)) {
		bt_mesh_clear_subnet(sub);
	}

	(void)memset(sub, 0, sizeof(*sub));
	sub->net_idx = BT_MESH_KEY_UNUSED;

	subnet_evt(idx, NULL, BT_MESH_KEY_DELETED);
}

static void subnet_flags_get(struct bt_mesh_subnet *sub,
			    struct bt_mesh_subnet_flags *flags)
{
	flags->kr_phase = sub->kr_phase;
	flags->node_id = sub->node_id;
	flags->kr_flag = sub->kr_flag;
	flags->iv_update = atomic_test_bit(bt_mesh.flags,
					   BT_MESH_IVU_IN_PROGRESS);
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

bt_mesh_status_t bt_mesh_subnet_add(uint16_t idx, const uint8_t key[16])
{
	struct bt_mesh_subnet_flags flags;
	struct bt_mesh_subnet *sub = NULL;
	int err;

	BT_DBG("idx 0x%04x", idx);

	sub = subnet_alloc(idx);
	if (!sub) {
		return STATUS_INSUFF_RESOURCES;
	}

	if (sub->net_idx == idx) {
		if (memcmp(key, sub->keys[0].net, 16)) {
			return STATUS_IDX_ALREADY_STORED;
		}

		return STATUS_SUCCESS;
	}

	err = net_keys_create(&sub->keys[0], key);
	if (err) {
		return STATUS_UNSPECIFIED;
	}

	sub->net_idx = idx;

	if (IS_ENABLED(CONFIG_BT_SETTINGS)) {
		BT_DBG("Storing NetKey persistently");
		bt_mesh_store_subnet(sub);
	}

	/* Make sure we have valid beacon data to be sent */
	bt_mesh_net_beacon_update(sub); // TODO: Convert to callback?

	if (IS_ENABLED(CONFIG_BT_MESH_GATT_PROXY)) {
		sub->node_id = BT_MESH_NODE_IDENTITY_STOPPED;
		bt_mesh_proxy_beacon_send(sub);
		bt_mesh_adv_update();
	} else {
		sub->node_id = BT_MESH_NODE_IDENTITY_NOT_SUPPORTED;
	}


	subnet_flags_get(sub, &flags);
	subnet_evt(sub->net_idx, &flags, BT_MESH_KEY_ADDED);

	return STATUS_SUCCESS;
}

bt_mesh_status_t bt_mesh_subnet_update(uint16_t idx, const uint8_t key[16])
{
	struct bt_mesh_subnet *sub;
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
	switch (sub->kr_phase) {
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
		err = friend_cred_update(sub);
		if (err) {
			return STATUS_CANNOT_UPDATE;
		}
	}

	sub->kr_phase = BT_MESH_KR_PHASE_1;

	if (IS_ENABLED(CONFIG_BT_SETTINGS)) {
		BT_DBG("Storing NetKey persistently");
		bt_mesh_store_subnet(sub);
	}

	bt_mesh_net_beacon_update(sub); // TODO: Convert to callback? Or remove? The kr_flag state is unchanged.

	return STATUS_SUCCESS;
}

void bt_mesh_subnet_del(uint16_t idx)
{
	struct bt_mesh_subnet *sub;

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

const uint16_t *bt_mesh_net_idx_next(const uint16_t *prev)
{
	const struct bt_mesh_subnet *sub;

	if (prev) {
		sub = CONTAINER_OF(prev, struct bt_mesh_subnet, net_idx) + 1;
	} else {
		sub = &bt_mesh.sub[0];
	}

	while (sub != &bt_mesh.sub[ARRAY_SIZE(bt_mesh.sub)]) {
		if (sub->net_idx != BT_MESH_KEY_UNUSED) {
			return &sub->net_idx;
		}

		sub++;
	}

	return NULL;
}

bt_mesh_status_t bt_mesh_subnet_kr_phase_set(uint16_t idx, uint8_t *phase)
{
	struct bt_mesh_subnet_flags flags;
	struct bt_mesh_subnet *sub;

	BT_DBG("idx 0x%04x", idx);

	sub = subnet_get(idx);
	if (!sub) {
		return STATUS_INVALID_NETKEY;
	}

	BT_DBG("%u -> %u", sub->kr_phase, *phase);

	if (*phase < BT_MESH_KR_PHASE_2 || *phase > BT_MESH_KR_PHASE_3 ||
	    (sub->kr_phase == BT_MESH_KR_NORMAL &&
	     *phase == BT_MESH_KR_PHASE_2)) {
		BT_WARN("Prohibited transition %u -> %u", sub->kr_phase,
			*phase);
		return STATUS_CANNOT_UPDATE;
	}

	if (sub->kr_phase == BT_MESH_KR_PHASE_1 &&
	    *phase == BT_MESH_KR_PHASE_2) {
		sub->kr_phase = BT_MESH_KR_PHASE_2;
		sub->kr_flag = 1;
		bt_mesh_net_beacon_update(sub); // TODO: Move to callback?

		subnet_flags_get(sub, &flags);
		subnet_evt(idx, &flags, BT_MESH_KEY_UPDATED);
	} else if ((sub->kr_phase == BT_MESH_KR_PHASE_1 ||
		    sub->kr_phase == BT_MESH_KR_PHASE_2) &&
		   *phase == BT_MESH_KR_PHASE_3) {
		bt_mesh_net_revoke_keys(sub);

		if (IS_ENABLED(CONFIG_BT_MESH_LOW_POWER) ||
		    IS_ENABLED(CONFIG_BT_MESH_FRIEND)) {
			friend_cred_refresh(idx);
		}

		sub->kr_phase = BT_MESH_KR_NORMAL;
		sub->kr_flag = 0;
		bt_mesh_net_beacon_update(sub);

		subnet_flags_get(sub, &flags);
		subnet_evt(idx, &flags, BT_MESH_KEY_UPDATED);
	}

	*phase = sub->kr_phase;

	return STATUS_SUCCESS;
}

bt_mesh_status_t bt_mesh_subnet_node_id_set(uint16_t idx, uint8_t node_id)
{
	struct bt_mesh_subnet *sub;

	sub = subnet_get(idx);
	if (!sub) {
		return STATUS_INVALID_NETKEY;
	}

	if (!IS_ENABLED(CONFIG_BT_MESH_GATT_PROXY)) {
		return STATUS_FEAT_NOT_SUPP;
	}

	if (node_id) {
		bt_mesh_proxy_identity_start(sub);
	} else {
		bt_mesh_proxy_identity_stop(sub);
	}

	bt_mesh_adv_update();

	return STATUS_SUCCESS;
}

int bt_mesh_subnet_flags_get(uint16_t idx, struct bt_mesh_subnet_flags *flags)
{
	struct bt_mesh_subnet *sub;

	sub = subnet_get(idx);
	if (!sub) {
		return -ENOENT;
	}

	if (flags) {
		subnet_flags_get(sub, flags);
	}

	return 0;
}

const struct bt_mesh_subnet *bt_mesh_subnet_get(uint16_t net_idx)
{
	return subnet_get(net_idx);
}

int bt_mesh_subnet_set(uint16_t net_idx, bool kr, uint8_t krp,
		       const uint8_t old_key[16], const uint8_t new_key[16])
{
	const uint8_t *keys[] = {old_key, new_key};
	struct bt_mesh_subnet *sub;

	sub = subnet_alloc(net_idx);
	if (!sub) {
		return -ENOMEM;
	}

	if (sub->net_idx == net_idx) {
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

	sub->net_idx = net_idx;
	sub->kr_phase = krp;
	sub->kr_flag = kr;

	if (IS_ENABLED(CONFIG_BT_MESH_GATT_PROXY)) {
		sub->node_id = BT_MESH_NODE_IDENTITY_STOPPED;
	} else {
		sub->node_id = BT_MESH_NODE_IDENTITY_NOT_SUPPORTED;
	}

	/* Make sure we have valid beacon data to be sent */
	bt_mesh_net_beacon_update(sub);

	return 0;
}

void bt_mesh_net_revoke_keys(struct bt_mesh_subnet *sub)
{
	int i;

	BT_DBG("idx 0x%04x", sub->net_idx);

	memcpy(&sub->keys[0], &sub->keys[1], sizeof(sub->keys[0]));
	if (IS_ENABLED(CONFIG_BT_SETTINGS)) {
		BT_DBG("Storing Updated NetKey persistently");
		bt_mesh_store_subnet(sub);
	}

	for (i = 0; i < ARRAY_SIZE(bt_mesh.app_keys); i++) {
		struct bt_mesh_app_key *key = &bt_mesh.app_keys[i];

		if (key->net_idx != sub->net_idx || !key->updated) {
			continue;
		}

		memcpy(&key->keys[0], &key->keys[1], sizeof(key->keys[0]));
		key->updated = false;
		if (IS_ENABLED(CONFIG_BT_SETTINGS)) {
			BT_DBG("Storing Updated AppKey persistently");
			bt_mesh_store_app_key(key);
		}
	}
}

void bt_mesh_subnet_cb_register(struct bt_mesh_subnet_cb *cb)
{
	sys_slist_append(&bt_mesh.subnet_cbs, &cb->n);
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

	for (i = 0; i < ARRAY_SIZE(bt_mesh.sub); i++) {
		struct bt_mesh_subnet *sub = &bt_mesh.sub[i];

		if (sub->net_idx == BT_MESH_KEY_UNUSED) {
			continue;
		}

		if (auth_match(&sub->keys[0], net_id, flags, iv_index, auth)) {
			*new_key = false;
			return sub;
		}

		if (sub->kr_phase == BT_MESH_KR_NORMAL) {
			continue;
		}

		if (auth_match(&sub->keys[1], net_id, flags, iv_index, auth)) {
			*new_key = true;
			return sub;
		}
	}

	return NULL;
}

bt_mesh_status_t bt_mesh_app_key_add(uint16_t app_idx, uint16_t net_idx,
				     const uint8_t key[16])
{
	struct bt_mesh_app_key *app;

	BT_DBG("net_idx 0x%04x app_idx %04x val %s",
	       net_idx, app_idx, bt_hex(key, 16));

	if (!subnet_get(net_idx)) {
		return STATUS_INVALID_NETKEY;
	}

	app = app_key_alloc(app_idx);
	if (!app) {
		return STATUS_INSUFF_RESOURCES;
	}

	if (app->app_idx == app_idx) {
		if (app->net_idx != net_idx) {
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

	app->net_idx = net_idx;
	app->app_idx = app_idx;
	app->updated = false;
	memcpy(app->keys[0].val, key, 16);

	if (IS_ENABLED(CONFIG_BT_SETTINGS)) {
		BT_DBG("Storing AppKey persistently");
		bt_mesh_store_app_key(app);
	}

	app_key_evt(app_idx, net_idx, BT_MESH_KEY_ADDED);

	return STATUS_SUCCESS;
}

const struct bt_mesh_app_key *bt_mesh_app_key_get(uint16_t app_idx)
{
	return app_key_get(app_idx);
}

bt_mesh_status_t bt_mesh_app_key_update(uint16_t app_idx, uint16_t net_idx,
					const uint8_t key[16])
{
	struct bt_mesh_app_key *app;
	struct bt_mesh_subnet *sub;

	BT_DBG("net_idx 0x%04x app_idx %04x val %s",
	       net_idx, app_idx, bt_hex(key, 16));

	app = app_key_get(app_idx);
	if (!app) {
		return STATUS_INVALID_APPKEY;
	}

	if (net_idx != BT_MESH_KEY_UNUSED && app->net_idx != net_idx) {
		return STATUS_INVALID_BINDING;
	}

	sub = subnet_get(app->net_idx);
	if (!sub) {
		return STATUS_INVALID_NETKEY;
	}

	/* The AppKey Update message shall generate an error when node
	 * is in normal operation, Phase 2, or Phase 3 or in Phase 1
	 * when the AppKey Update message on a valid AppKeyIndex when
	 * the AppKey value is different.
	 */
	if (sub->kr_phase != BT_MESH_KR_PHASE_1) {
		return STATUS_CANNOT_UPDATE;
	}

	if (app->updated) {
		if (memcmp(app->keys[1].val, key, 16)) {
			return STATUS_IDX_ALREADY_STORED;
		}

		return STATUS_SUCCESS;
	}

	if (bt_mesh_app_id(key, &app->keys[1].id)) {
		return STATUS_CANNOT_UPDATE;
	}

	BT_DBG("app_idx 0x%04x AID 0x%02x", app_idx, app->keys[1].id);

	app->updated = true;
	memcpy(app->keys[1].val, key, 16);

	if (IS_ENABLED(CONFIG_BT_SETTINGS)) {
		BT_DBG("Storing AppKey persistently");
		bt_mesh_store_app_key(app);
	}

	app_key_evt(app_idx, net_idx, BT_MESH_KEY_UPDATED);

	return STATUS_SUCCESS;
}

bt_mesh_status_t bt_mesh_app_key_del(uint16_t app_idx, uint16_t net_idx)
{
	struct bt_mesh_app_key *app;

	BT_DBG("AppIdx 0x%03x", app_idx);

	if (net_idx != BT_MESH_KEY_UNUSED && !subnet_get(net_idx)) {
		return STATUS_INVALID_NETKEY;
	}

	app = app_key_get(app_idx);
	if (!app) {
		/* This could be a retry of a previous attempt that had its
		 * response lost, so pretend that it was a success.
		 */
		return STATUS_SUCCESS;
	}

	if (net_idx != BT_MESH_KEY_UNUSED && net_idx != app->net_idx) {
		return STATUS_INVALID_BINDING;
	}

	app_key_del(app);

	return STATUS_SUCCESS;
}

const uint16_t *bt_mesh_app_idx_next(uint16_t net_idx, const uint16_t *prev)
{
	const struct bt_mesh_app_key *app;

	if (prev) {
		app = CONTAINER_OF(prev, struct bt_mesh_app_key, app_idx) + 1;
	} else {
		app = &bt_mesh.app_keys[0];
	}

	while (app != &bt_mesh.app_keys[ARRAY_SIZE(bt_mesh.app_keys)]) {
		if (app->app_idx != BT_MESH_KEY_UNUSED &&
		    (net_idx == BT_MESH_KEY_ANY || net_idx == app->net_idx)) {
			return &app->app_idx;
		}

		app++;
	}

	return NULL;
}

int bt_mesh_app_key_set(uint16_t app_idx, uint16_t net_idx,
			const uint8_t old_key[16], const uint8_t new_key[16])
{
	struct bt_mesh_app_key *app;

	app = app_key_alloc(app_idx);
	if (!app) {
		return -ENOMEM;
	}

	if (app->app_idx == app_idx) {
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

	app->net_idx = net_idx;
	app->app_idx = app_idx;
	app->updated = !!new_key;

	return 0;
}

void bt_mesh_app_key_cb_register(struct bt_mesh_app_key_cb *cb)
{
	sys_slist_append(&bt_mesh.app_key_cbs, &cb->n);
}

int bt_mesh_keys_resolve(struct bt_mesh_msg_ctx *ctx,
			 const struct bt_mesh_subnet **sub,
			 const uint8_t *app_key[16], uint8_t *aid)
{
	const struct bt_mesh_app_key *app = NULL;

	if (BT_MESH_IS_DEV_KEY(ctx->app_idx)) {
		/* With device keys, the application has to decide which subnet
		 * to send on.
		 */
		*sub = subnet_get(ctx->net_idx);
		if (!*sub) {
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
			*app_key = bt_mesh.dev_key;
		}

		*aid = 0;
		return 0;
	}

	app = app_key_get(ctx->app_idx);
	if (!app) {
		BT_WARN("Unknown AppKey 0x%03x", ctx->app_idx);
		return -EINVAL;
	}

	*sub = subnet_get(app->net_idx);
	if (!*sub) {
		BT_WARN("Unknown NetKey 0x%03x", app->net_idx);
		return -EINVAL;
	}

	if ((*sub)->kr_phase == BT_MESH_KR_PHASE_2 && app->updated) {
		*aid = app->keys[1].id;
		*app_key = app->keys[1].val;
	} else {
		*aid = app->keys[0].id;
		*app_key = app->keys[0].val;
	}

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

		if (prev == bt_mesh.dev_key) {
			return NULL;
		}

		rx->ctx.app_idx = BT_MESH_KEY_DEV_LOCAL;
		return bt_mesh.dev_key;
	}

	if (prev) {
		i = (CONTAINER_OF(prev, struct bt_mesh_app_key, keys[0].val) -
		     &bt_mesh.app_keys[0]) + 1;
	} else {
		i = 0;
	}

	while (i < ARRAY_SIZE(bt_mesh.app_keys)) {
		const struct bt_mesh_app_key *app = &bt_mesh.app_keys[i++];
		const struct bt_mesh_app_keys *keys;

		if (app->app_idx == BT_MESH_KEY_UNUSED) {
			continue;
		}

		if (app->net_idx != rx->sub->net_idx) {
			continue;
		}

		if (rx->new_key && app->updated) {
			keys = &app->keys[1];
		} else {
			keys = &app->keys[0];
		}

		if (keys->id == aid) {
			rx->ctx.app_idx = app->app_idx;
			return keys->val;
		}
	}

	return false;
}

void bt_mesh_keys_reset(void)
{
	int i;

	/* Delete all net keys, which also takes care of all app keys which
	 * are associated with each net key.
	 */
	for (i = 0; i < ARRAY_SIZE(bt_mesh.sub); i++) {
		struct bt_mesh_subnet *sub = &bt_mesh.sub[i];

		if (sub->net_idx != BT_MESH_KEY_UNUSED) {
			subnet_del(sub);
		}
	}
}
