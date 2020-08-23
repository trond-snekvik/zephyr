/*
 * Copyright (c) 2020 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: Apache-2.0
 */

struct bt_mesh_subnet_flags {
	bool iv_update;
	bool kr_flag;
	uint8_t kr_phase;
	uint8_t node_id;
};

enum bt_mesh_key_evt {
	BT_MESH_KEY_ADDED,
	BT_MESH_KEY_DELETED,
	BT_MESH_KEY_UPDATED,
};

struct bt_mesh_subnet_cb {
	void (*evt_handler)(uint16_t net_idx,
			    const struct bt_mesh_subnet_flags *flags,
			    enum bt_mesh_key_evt evt);
	sys_snode_t n;
};

struct bt_mesh_app_key_cb {
	void (*evt_handler)(uint16_t app_idx, uint16_t net_idx,
			    enum bt_mesh_key_evt evt);
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

const struct bt_mesh_subnet *bt_mesh_subnet_get(uint16_t net_idx);
const struct bt_mesh_app_key *bt_mesh_app_key_get(uint16_t app_idx);

int bt_mesh_subnet_set(uint16_t net_idx, bool kr, uint8_t krp,
		       const uint8_t old_key[16], const uint8_t new_key[16]);
int bt_mesh_app_key_set(uint16_t app_idx, uint16_t net_idx,
			const uint8_t old_key[16], const uint8_t new_key[16]);

int bt_mesh_keys_resolve(struct bt_mesh_msg_ctx *ctx,
			 const struct bt_mesh_subnet **sub,
			 const uint8_t *app_key[16], uint8_t *aid);
const uint8_t *bt_mesh_app_key_next(struct bt_mesh_net_rx *rx, bool akf,
				    uint8_t aid, const uint8_t *prev);

const uint16_t *bt_mesh_app_idx_next(uint16_t net_idx, const uint16_t *prev);
const uint16_t *bt_mesh_net_idx_next(const uint16_t *prev);
