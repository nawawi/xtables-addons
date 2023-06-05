#pragma once
#define IPP2P_VERSION "0.10"

enum {
	IPP2N_EDK,
	IPP2N_DATA_KAZAA,
	IPP2N_DATA_EDK,
	IPP2N_DATA_DC,
	IPP2N_DC,
	IPP2N_DATA_GNU,
	IPP2N_GNU,
	IPP2N_KAZAA,
	IPP2N_BIT,
	IPP2N_APPLE,
	IPP2N_SOUL,
	IPP2N_WINMX,
	IPP2N_ARES,
	IPP2N_MUTE,
	IPP2N_WASTE,
	IPP2N_XDCC,

	IPP2P_EDK        = 1 << IPP2N_EDK,
	IPP2P_DATA_KAZAA = 1 << IPP2N_DATA_KAZAA,
	IPP2P_DATA_EDK   = 1 << IPP2N_DATA_EDK,
	IPP2P_DATA_DC    = 1 << IPP2N_DATA_DC,
	IPP2P_DC         = 1 << IPP2N_DC,
	IPP2P_DATA_GNU   = 1 << IPP2N_DATA_GNU,
	IPP2P_GNU        = 1 << IPP2N_GNU,
	IPP2P_KAZAA      = 1 << IPP2N_KAZAA,
	IPP2P_BIT        = 1 << IPP2N_BIT,
	IPP2P_APPLE      = 1 << IPP2N_APPLE,
	IPP2P_SOUL       = 1 << IPP2N_SOUL,
	IPP2P_WINMX      = 1 << IPP2N_WINMX,
	IPP2P_ARES       = 1 << IPP2N_ARES,
	IPP2P_MUTE       = 1 << IPP2N_MUTE,
	IPP2P_WASTE      = 1 << IPP2N_WASTE,
	IPP2P_XDCC       = 1 << IPP2N_XDCC,
};

struct ipt_p2p_info {
	int32_t cmd, debug;

	struct ts_config *ts_conf_winmx;
	struct ts_config *ts_conf_bt_info_hash;
	struct ts_config *ts_conf_bt_peer_id;
	struct ts_config *ts_conf_bt_passkey;
	struct ts_config *ts_conf_gnu_x_gnutella;
	struct ts_config *ts_conf_gnu_x_queue;
	struct ts_config *ts_conf_kz_x_kazaa_username;
	struct ts_config *ts_conf_kz_user_agent;
	struct ts_config *ts_conf_xdcc;
};
