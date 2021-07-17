#pragma once
enum xt_chaos_target_variant {
	XTCHAOS_NORMAL,
	XTCHAOS_TARPIT,
	XTCHAOS_DELUDE,
};

struct xt_chaos_tginfo {
	uint8_t variant;
};
