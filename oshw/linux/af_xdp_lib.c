/* SPDX-License-Identifier: GPL-2.0 */

#include <assert.h>
#include <errno.h>
#include <locale.h>
#include <poll.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/resource.h>

#include <bpf/bpf.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <linux/if_link.h>
#include <linux/if_ether.h>
#include <linux/ipv6.h>
#include <linux/icmpv6.h>

#include "af_xdp_lib.h"
#include "../common/common_user_bpf_xdp.h"
#include "../common/common_libbpf.h"

#define NANOSEC_PER_SEC 1000000000 /* 10^9 */

/* Initialize AF_XDP context */
struct af_xdp_context *af_xdp_init(void)
{
	struct af_xdp_context *ctx;
	
	ctx = calloc(1, sizeof(*ctx));
	if (!ctx)
		return NULL;
		
	ctx->cfg.ifindex = -1;
	ctx->custom_xsk = false;
	ctx->global_exit = false;
	ctx->xsk_map_fd = -1;
	
	printf("[INFO] %s: AF_XDP context initialized successfully (ctx=%p)\n", __func__, ctx);
	return ctx;
}

/* Clean up AF_XDP context */
void af_xdp_cleanup(struct af_xdp_context *ctx)
{
	if (!ctx)
		return;

	ctx->global_exit = true;

	if (ctx->xsk_socket) {
		printf("[INFO] %s: deleting xsk_socket (xsk=%p)\n", __func__, ctx->xsk_socket->xsk);
		xsk_socket__delete(ctx->xsk_socket->xsk);
		free(ctx->xsk_socket);
	}

	if (ctx->umem) {
		printf("[INFO] %s: deleting umem (umem=%p buffer=%p)\n", __func__, ctx->umem->umem, ctx->umem->buffer);
		xsk_umem__delete(ctx->umem->umem);
		free(ctx->umem->buffer);  // Free packet buffer
		free(ctx->umem);
	}

	if (ctx->prog) {
		printf("[INFO] %s: detaching and closing xdp program (prog=%p)\n", __func__, ctx->prog);
		xdp_program__detach(ctx->prog, ctx->cfg.ifindex, XDP_MODE_UNSPEC, 0);
		xdp_program__close(ctx->prog);
	}

	free(ctx);
}

/* Configure UMEM */
struct xsk_umem_info *af_xdp_configure_umem(void *buffer, uint64_t size)
{
	struct xsk_umem_info *umem;
	int ret;

	umem = calloc(1, sizeof(*umem));
	if (!umem)
		return NULL;

	printf("[INFO] %s: creating umem size=%lu buffer=%p\n", __func__, (unsigned long)size, buffer);
	ret = xsk_umem__create(&umem->umem, buffer, size, &umem->fq, &umem->cq, NULL);
	if (ret) {
		errno = -ret;
		printf("[ERROR] %s: xsk_umem__create failed ret=%d errno=%d\n", __func__, ret, errno);
		free(umem);
		return NULL;
	}

	umem->buffer = buffer;
	printf("[INFO] %s: umem configured umem=%p fq=%p cq=%p\n", __func__, umem->umem, &umem->fq, &umem->cq);
	return umem;
}

/* Frame allocation functions */
uint64_t af_xdp_alloc_umem_frame(struct xsk_socket_info *xsk)
{
	uint64_t frame;
	if (xsk->umem_frame_free == 0)
		return INVALID_UMEM_FRAME;

	frame = xsk->umem_frame_addr[--xsk->umem_frame_free];
	xsk->umem_frame_addr[xsk->umem_frame_free] = INVALID_UMEM_FRAME;
	return frame;
}

void af_xdp_free_umem_frame(struct xsk_socket_info *xsk, uint64_t frame)
{
	// printf("DEBUG: Freeing frame. Current free count: %u\n", xsk->umem_frame_free);
	assert(xsk->umem_frame_free < NUM_FRAMES);
	xsk->umem_frame_addr[xsk->umem_frame_free++] = frame;
}

uint64_t af_xdp_umem_free_frames(struct xsk_socket_info *xsk)
{
	return xsk->umem_frame_free;
}

/* Configure XSK socket */
struct xsk_socket_info *af_xdp_configure_socket(struct config *cfg,
													struct xsk_umem_info *umem,
													int xsk_map_fd,
													bool custom_xsk)
{
	struct xsk_socket_config xsk_cfg;
	struct xsk_socket_info *xsk_info;
	uint32_t idx;
	int i;
	int ret;
	uint32_t prog_id;

	xsk_info = calloc(1, sizeof(*xsk_info));
	if (!xsk_info)
		return NULL;

	xsk_info->umem = umem;
	xsk_cfg.rx_size = XSK_RING_CONS__DEFAULT_NUM_DESCS;
	xsk_cfg.tx_size = XSK_RING_PROD__DEFAULT_NUM_DESCS;
	xsk_cfg.xdp_flags = cfg->xdp_flags;
	xsk_cfg.bind_flags = cfg->xsk_bind_flags;
	xsk_cfg.libbpf_flags = (custom_xsk) ? XSK_LIBBPF_FLAGS__INHIBIT_PROG_LOAD: 0;
	
    printf("[INFO] %s: Creating XSK socket with interface %s, queue %d cfg=%p umem=%p\n",
	    __func__, cfg->ifname, cfg->xsk_if_queue, cfg, umem);
	ret = xsk_socket__create(&xsk_info->xsk, cfg->ifname,
				 cfg->xsk_if_queue, umem->umem, &xsk_info->rx,
				 &xsk_info->tx, &xsk_cfg);
	if (ret)
		goto error_exit;
    printf("[INFO] %s: XSK socket created successfully (xsk=%p)\n", __func__, xsk_info->xsk);

	if (custom_xsk) {
		ret = xsk_socket__update_xskmap(xsk_info->xsk, xsk_map_fd);
		if (ret)
			goto error_exit;
	} else {
		/* Getting the program ID must be after the xdp_socket__create() call */
		if (bpf_xdp_query_id(cfg->ifindex, cfg->xdp_flags, &prog_id))
			goto error_exit;
	}

	/* Initialize umem frame allocation */
	for (i = 0; i < NUM_FRAMES; i++)
		xsk_info->umem_frame_addr[i] = i * FRAME_SIZE;

	xsk_info->umem_frame_free = NUM_FRAMES;

	/* Stuff the receive path with buffers, we assume we have enough */
	printf("[INFO] %s: Reserving fill queue space for %d frames\n",
		   __func__, XSK_RING_PROD__DEFAULT_NUM_DESCS);
	ret = xsk_ring_prod__reserve(&xsk_info->umem->fq,
					 XSK_RING_PROD__DEFAULT_NUM_DESCS,
					 &idx);

	if (ret != XSK_RING_PROD__DEFAULT_NUM_DESCS)
		goto error_exit;

	for (i = 0; i < XSK_RING_PROD__DEFAULT_NUM_DESCS; i ++)
		*xsk_ring_prod__fill_addr(&xsk_info->umem->fq, idx++) =
			af_xdp_alloc_umem_frame(xsk_info);

    printf("[INFO] %s: Reserving fill queue space completed, submitting %d frames\n",
	    __func__, XSK_RING_PROD__DEFAULT_NUM_DESCS);
	xsk_ring_prod__submit(&xsk_info->umem->fq,
			  XSK_RING_PROD__DEFAULT_NUM_DESCS);

	return xsk_info;

error_exit:
	errno = -ret;
    printf("[ERROR] %s: error_exit ret=%d errno=%d\n", __func__, ret, errno);
	free(xsk_info);
	return NULL;
}

/* Complete TX operations */
void af_xdp_complete_tx(struct xsk_socket_info *xsk)
{
	unsigned int completed;
	uint32_t idx_cq;

	if (!xsk->outstanding_tx)
		return;

	// printf("[af_xdp_lib] %s: attempting sendto to kick completion (fd=%d) outstanding_tx=%u\n", __func__, xsk_socket__fd(xsk->xsk), xsk->outstanding_tx);
	sendto(xsk_socket__fd(xsk->xsk), NULL, 0, MSG_DONTWAIT, NULL, 0);

	/* Collect/free completed TX buffers */
	completed = xsk_ring_cons__peek(&xsk->umem->cq,
					XSK_RING_CONS__DEFAULT_NUM_DESCS,
					&idx_cq);

	if (completed > 0) {
		// printf("[af_xdp_lib] %s: completed=%u (cq idx=%u)\n", __func__, completed, idx_cq);
		for (unsigned int i = 0; i < completed; i++)
			af_xdp_free_umem_frame(xsk,
						*xsk_ring_cons__comp_addr(&xsk->umem->cq,
									  idx_cq++));

		xsk_ring_cons__release(&xsk->umem->cq, completed);
		xsk->outstanding_tx -= completed < xsk->outstanding_tx ?
			completed : xsk->outstanding_tx;
	}
}

/* New API: send a packet (reserve TX descriptor, submit, update stats) */
int af_xdp_ready_send(struct xsk_socket_info *xsk, uint64_t addr, uint32_t len)
{
	uint32_t tx_idx = 0;
	int ret;

	/* Reserve one TX descriptor slot */
	ret = xsk_ring_prod__reserve(&xsk->tx, 1, &tx_idx);
	if (ret != 1) {
		printf("[ERROR] %s: xsk_ring_prod__reserve failed ret=%d\n", __func__, ret);
		return -1;
	}

	/* Setup TX descriptor */
	xsk_ring_prod__tx_desc(&xsk->tx, tx_idx)->addr = addr;
	xsk_ring_prod__tx_desc(&xsk->tx, tx_idx)->len  = len;
	xsk_ring_prod__submit(&xsk->tx, 1);

	/* Update outstanding and stats */
	xsk->outstanding_tx++;
	// printf("[af_xdp_lib] %s: queued TX addr=%llu len=%u outstanding_tx=%u\n", __func__, (unsigned long long)addr, len, xsk->outstanding_tx);
	return 0;
}

/* Receive batch: peek RX ring, refill fill-ring, and copy addr/len into user arrays */
int af_xdp_receive(struct af_xdp_context *ctx, 
				   unsigned char *buf, 
				   unsigned int buf_len, 
				   unsigned int max_entries,
				   int (*func)(unsigned char *buf, unsigned int buf_len, unsigned int ret_len))
{
	uint32_t idx_rx = 0;
	uint32_t idx_fq = 0;
	uint64_t addr;
	uint32_t len;
	int ret_len = 0; // Buf return size

	if (!ctx || !ctx->xsk_socket || !buf)
		return -EINVAL;

	unsigned int rcvd; // = xsk_ring_cons__peek(&ctx->xsk_socket->rx, max_entries, &idx_rx);;
	for (int i = 0; i < 100; i++) {
		rcvd = xsk_ring_cons__peek(&ctx->xsk_socket->rx, max_entries, &idx_rx);
		if (rcvd)
			break;
	}
	if (!rcvd) {
		return -EAGAIN;
	}

	// Reserve space in the fill ring for the received packets
	unsigned int ret = xsk_ring_prod__reserve(&ctx->xsk_socket->umem->fq, rcvd, &idx_fq);
	if (ret != rcvd) {
		printf("[ERROR] %s: xsk_ring_prod__reserve failed ret=%d rcvd=%u\n", __func__, ret, rcvd);
		xsk_ring_cons__release(&ctx->xsk_socket->rx, rcvd);
		return -EAGAIN;
	}

	/* Copy out packet data to caller-provided bounce buffers and record addrs */
	for (unsigned int i = 0; i < rcvd; i++) {
		const struct xdp_desc *desc = xsk_ring_cons__rx_desc(&ctx->xsk_socket->rx, idx_rx++);
		addr = desc->addr;
		len  = desc->len;
		void* src = xsk_umem__get_data(ctx->xsk_socket->umem->buffer, addr);

		if (func == NULL || func(buf, buf_len, ret_len) == 1) {
			/* Ensure caller provided buffer is large enough */
			if (buf_len - ret_len < len) {
				/* If not enough space, copy as much as fits and set reported length to shrinked size */
				memcpy(buf + ret_len, src, buf_len - ret_len);
				ret_len = buf_len;
			} else {
				memcpy(buf + ret_len, src, len);
				ret_len += len;
			}
		}
		*xsk_ring_prod__fill_addr(&ctx->xsk_socket->umem->fq, idx_fq++) = addr;
	}

	xsk_ring_prod__submit(&ctx->xsk_socket->umem->fq, rcvd);
	xsk_ring_cons__release(&ctx->xsk_socket->rx, rcvd);

	return (int)ret_len;
}



/* Setup XDP program */
int af_xdp_setup_program(struct af_xdp_context *ctx, const char *filename,
						const char *progname)
{
	DECLARE_LIBBPF_OPTS(bpf_object_open_opts, opts);
	DECLARE_LIBXDP_OPTS(xdp_program_opts, xdp_opts, 0);
	struct bpf_map *map;
	int err;
	char errmsg[1024];

	if (!filename || filename[0] == 0)
		return 0; /* No custom program */

	ctx->custom_xsk = true;
	xdp_opts.open_filename = filename;
	xdp_opts.prog_name = progname;
	xdp_opts.opts = &opts;

	if (progname && progname[0] != 0) {
		ctx->prog = xdp_program__create(&xdp_opts);
	} else {
		ctx->prog = xdp_program__open_file(filename, NULL, &opts);
	}

	err = libxdp_get_error(ctx->prog);
	if (err) {
		libxdp_strerror(err, errmsg, sizeof(errmsg));
		fprintf(stderr, "ERR: loading program: %s\n", errmsg);
		return err;
	}

	err = xdp_program__attach(ctx->prog, ctx->cfg.ifindex, ctx->cfg.attach_mode, 0);
	if (err) {
		libxdp_strerror(err, errmsg, sizeof(errmsg));
		fprintf(stderr, "Couldn't attach XDP program on iface '%s' : %s (%d)\n",
			ctx->cfg.ifname, errmsg, err);
		return err;
	}

	/* We also need to load the xsks_map */
	map = bpf_object__find_map_by_name(xdp_program__bpf_obj(ctx->prog), "xsks_map");
	ctx->xsk_map_fd = bpf_map__fd(map);
	if (ctx->xsk_map_fd < 0) {
		fprintf(stderr, "ERROR: no xsks map found: %s\n",
			strerror(ctx->xsk_map_fd));
		return -1;
	}

	return 0;
}

/* Setup socket */
int af_xdp_setup_socket(struct af_xdp_context *ctx)
{
	void *packet_buffer;
	uint64_t packet_buffer_size;
	struct rlimit rlim = {RLIM_INFINITY, RLIM_INFINITY};

	printf("DEBUG: Starting af_xdp_setup_socket\n");
	
	/* Allow unlimited locking of memory */
	if (setrlimit(RLIMIT_MEMLOCK, &rlim)) {
		fprintf(stderr, "ERROR: setrlimit(RLIMIT_MEMLOCK) \"%s\"\n",
			strerror(errno));
		return -1;
	}
	printf("DEBUG: Memory limit set successfully\n");

	/* Allocate memory for NUM_FRAMES of the default XDP frame size */
	packet_buffer_size = NUM_FRAMES * FRAME_SIZE;
	printf("DEBUG: Allocating %lu bytes for packet buffer\n", packet_buffer_size);
	if (posix_memalign(&packet_buffer,
			   getpagesize(), /* PAGE_SIZE aligned */
			   packet_buffer_size)) {
		fprintf(stderr, "ERROR: Can't allocate buffer memory \"%s\"\n", strerror(errno));
		return -1;
	}
	printf("DEBUG: Packet buffer allocated successfully\n");

	/* Initialize shared packet_buffer for umem usage */
	printf("DEBUG: Configuring UMEM\n");
	ctx->umem = af_xdp_configure_umem(packet_buffer, packet_buffer_size);
	if (ctx->umem == NULL) {
		fprintf(stderr, "ERROR: Can't create umem \"%s\"\n", strerror(errno));
		free(packet_buffer);
		return -1;
	}
	printf("DEBUG: UMEM configured successfully\n");

	/* Open and configure the AF_XDP (xsk) socket */
	printf("DEBUG: Configuring XSK socket\n");
	ctx->xsk_socket = af_xdp_configure_socket(&ctx->cfg, ctx->umem,
											 ctx->xsk_map_fd, ctx->custom_xsk);
	if (ctx->xsk_socket == NULL) {
		fprintf(stderr, "ERROR: Can't setup AF_XDP socket \"%s\"\n", strerror(errno));
		return -1;
	}
	printf("DEBUG: XSK socket configured successfully\n");

	return 0;
}

/* Utility functions */
void af_xdp_set_global_exit(struct af_xdp_context *ctx, bool exit_flag)
{
	ctx->global_exit = exit_flag;
}

bool af_xdp_should_exit(struct af_xdp_context *ctx)
{
	return ctx->global_exit;
}

/* 新增: 高階封裝送出函式 */
int af_xdp_send(struct xsk_socket_info *xsk, const void *data, size_t len, uint32_t flags)
{
	uint64_t frame;
	uint8_t *dst;
	int ret;
	int retry = 0;

	if (!xsk || !data)
		return -EINVAL;
	if (len == 0 || len > FRAME_SIZE)
		return -EMSGSIZE;

retry_alloc:
	frame = af_xdp_alloc_umem_frame(xsk);
	if (frame == INVALID_UMEM_FRAME) {
		/* Try to reclaim completed TX, then retry once (or a few times) */
		af_xdp_complete_tx(xsk);
		if (retry++ < 2) /* Simply retry up to two more times */
			goto retry_alloc;
		return -EAGAIN; /* Caller can retry later */
	}

	dst = xsk_umem__get_data(xsk->umem->buffer, frame);
	memcpy(dst, data, len);

	ret = af_xdp_ready_send(xsk, frame, (uint32_t)len);
	if (ret) {
		/* TX queue full, reclaim and try again */
		af_xdp_complete_tx(xsk);
		ret = af_xdp_ready_send(xsk, frame, (uint32_t)len);
		if (ret) {
			/* Still failed, return the frame */
			af_xdp_free_umem_frame(xsk, frame);
			return -EAGAIN;
		}
	}

	/* Depending on the flag or ring usage, decide whether to reclaim immediately */
	if (flags & AF_XDP_SEND_F_FLUSH) {
		af_xdp_complete_tx(xsk);
	} else {
		/* If outstanding reaches more than half, reclaim early to avoid exhaustion */
		if (xsk->outstanding_tx > (XSK_RING_PROD__DEFAULT_NUM_DESCS / 2))
			af_xdp_complete_tx(xsk);
	}

	return 0;
}






