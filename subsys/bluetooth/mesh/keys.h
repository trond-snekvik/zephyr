/*
 * Copyright (c) 2020 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: Apache-2.0
 */

enum bt_mesh_key_evt {
	BT_MESH_KEY_ADDED,
	BT_MESH_KEY_DELETED,
	BT_MESH_KEY_UPDATED,
};

struct bt_mesh_subnet {
	uint32_t beacon_sent;        /* Timestamp of last sent beacon */
	uint8_t  beacons_last;       /* Number of beacons during last
				      * observation window
				      */
	uint8_t  beacons_cur;        /* Number of beaconds observed during
				      * currently ongoing window.
				      */

	uint8_t  beacon_cache[21];   /* Cached last authenticated beacon */

	uint16_t net_idx;            /* NetKeyIndex */

	bool     kr_flag;            /* Key Refresh Flag */
	uint8_t  kr_phase;           /* Key Refresh Phase */

	uint8_t  node_id;            /* Node Identity State */
	uint32_t node_id_start;      /* Node Identity started timestamp */

	uint8_t  auth[8];            /* Beacon Authentication Value */
};

struct bt_mesh_app {
	uint16_t net_idx;
	uint16_t app_idx;
	bool     updated;
};

struct bt_mesh_subnet_cb {
	void (*evt_handler)(struct bt_mesh_subnet *subnet,
			    enum bt_mesh_key_evt evt);
	sys_snode_t n;
};

struct bt_mesh_app_key_cb {
	void (*evt_handler)(struct bt_mesh_app *app, enum bt_mesh_key_evt evt);
	sys_snode_t n;
};

void bt_mesh_keys_reset(void);

bt_mesh_status_t bt_mesh_subnet_add(uint16_t idx, const uint8_t key[16]);
bt_mesh_status_t bt_mesh_subnet_update(uint16_t idx, const uint8_t key[16]);
void bt_mesh_subnet_del(uint16_t idx);

bt_mesh_status_t bt_mesh_subnet_kr_phase_set(uint16_t idx, uint8_t *phase);
bt_mesh_status_t bt_mesh_subnet_node_id_set(uint16_t idx, uint8_t node_id);

int bt_mesh_subnet_flags_get(uint16_t idx, struct bt_mesh_subnet_flags *flags);
bool bt_mesh_kr_update(struct bt_mesh_subnet *sub, uint8_t new_kr,
		       bool new_key);

struct bt_mesh_subnet *bt_mesh_subnet_find(const uint8_t net_id[8],
					   uint8_t flags, uint32_t iv_index,
					   const uint8_t auth[8],
					   bool *new_key);

bt_mesh_status_t bt_mesh_app_key_add(uint16_t app_idx, uint16_t net_idx,
				     const uint8_t key[16]);
bt_mesh_status_t bt_mesh_app_key_update(uint16_t app_idx, uint16_t net_idx,
					const uint8_t key[16]);
bt_mesh_status_t bt_mesh_app_key_del(uint16_t app_idx, uint16_t net_idx);

void bt_mesh_subnet_cb_register(struct bt_mesh_subnet_cb *cb);
void bt_mesh_app_key_cb_register(struct bt_mesh_app_key_cb *cb);

struct bt_mesh_subnet *bt_mesh_subnet_get(uint16_t net_idx);
struct bt_mesh_app *bt_mesh_app_get(uint16_t app_idx);

int bt_mesh_subnet_set(uint16_t net_idx, bool kr, uint8_t krp,
		       const uint8_t old_key[16], const uint8_t new_key[16]);

int bt_mesh_keys_resolve(struct bt_mesh_msg_ctx *ctx,
			 struct bt_mesh_subnet **sub,
			 const uint8_t *app_key[16], uint8_t *aid);
const uint8_t *bt_mesh_app_key_next(struct bt_mesh_net_rx *rx, bool akf,
				    uint8_t aid, const uint8_t *prev);

const uint16_t *bt_mesh_app_idx_next(uint16_t net_idx, const uint16_t *prev);
const uint16_t *bt_mesh_net_idx_next(const uint16_t *prev);
int bt_mesh_net_beacon_update(struct bt_mesh_subnet *sub);

void bt_mesh_subnet_foreach(void (*cb)(struct bt_mesh_subnet *sub,
				       void *cb_data),
			    void *cb_data);
void bt_mesh_app_foreach(uint16_t net_idx,
			 void (*cb)(struct bt_mesh_app *app, void *cb_data),
			 void *cb_data);
const uint8_t *bt_mesh_subnet_id_get(const struct bt_mesh_subnet *sub);

struct bt_mesh_subnet *bt_mesh_subnet_next(struct bt_mesh_subnet *prev);
struct bt_mesh_app *bt_mesh_app_next(uint16_t net_idx,
				     struct bt_mesh_app *prev);

int bt_mesh_subnet_load(uint16_t net_idx, size_t len_rd,
			settings_read_cb read_cb, void *cb_arg);
int bt_mesh_app_load(uint16_t app_idx, size_t len_rd, settings_read_cb read_cb,
		     void *cb_arg);

int bt_mesh_subnet_store(uint16_t net_idx, const char *path);
int bt_mesh_app_store(uint16_t app_idx, const char *path);