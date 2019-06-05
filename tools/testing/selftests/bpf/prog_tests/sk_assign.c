// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2018 Facebook
// Copyright (c) 2019 Cloudflare
// Copyright (c) 2020 Isovalent, Inc.
/*
 * Test that the socket assign program is able to redirect traffic towards a
 * socket, regardless of whether the port or address destination of the traffic
 * matches the port.
 */

#define _GNU_SOURCE
#include <fcntl.h>
#include <signal.h>
#include <stdlib.h>
#include <unistd.h>

#include "test_progs.h"

#define TEST_DPORT 4321
#define TEST_DADDR (0xC0A80203)
#define NS_SELF "/proc/self/ns/net"

static __u32 duration;

static bool configure_stack(int self_net)
{
	/* Move to a new networking namespace */
	if (CHECK_FAIL(unshare(CLONE_NEWNET)))
		return false;

	/* Configure necessary links, routes */
	if (CHECK_FAIL(system("ip link set dev lo up")))
		return false;
	if (CHECK_FAIL(system("ip route add local default dev lo")))
		return false;
	if (CHECK_FAIL(system("ip -6 route add local default dev lo")))
		return false;

	/* Load qdisc, BPF program */
	if (CHECK_FAIL(system("tc qdisc add dev lo clsact")))
		return false;
	if (CHECK_FAIL(system("tc filter add dev lo ingress bpf direct-action "
		     "object-file ./test_sk_assign.o section sk_assign_test")))
		return false;

	return true;
}

static int start_server(const struct sockaddr *addr, socklen_t len)
{
	int fd;

	fd = socket(addr->sa_family, SOCK_STREAM, 0);
	if (CHECK_FAIL(fd == -1))
		goto out;
	if (CHECK_FAIL(bind(fd, addr, len) == -1))
		goto close_out;
	if (CHECK_FAIL(listen(fd, 128) == -1))
		goto close_out;

	goto out;

close_out:
	close(fd);
	fd = -1;
out:
	return fd;
}

static void handle_timeout(int signum)
{
	if (signum == SIGALRM)
		fprintf(stderr, "Timed out while connecting to server\n");
	kill(0, SIGKILL);
}

static struct sigaction timeout_action = {
	.sa_handler = handle_timeout,
};

static int connect_to_server(const struct sockaddr *addr, socklen_t len)
{
	int fd = -1;

	fd = socket(addr->sa_family, SOCK_STREAM, 0);
	if (CHECK_FAIL(fd == -1))
		goto out;
	if (CHECK_FAIL(sigaction(SIGALRM, &timeout_action, NULL)))
		goto out;
	alarm(3);
	if (CHECK_FAIL(connect(fd, addr, len) == -1))
		goto close_out;

	goto out;

close_out:
	close(fd);
	fd = -1;
out:
	return fd;
}

static in_port_t get_port(int fd)
{
	struct sockaddr_storage name;
	socklen_t len;
	in_port_t port = 0;

	len = sizeof(name);
	if (CHECK_FAIL(getsockname(fd, (struct sockaddr *)&name, &len)))
		return port;

	switch (name.ss_family) {
	case AF_INET:
		port = ((struct sockaddr_in *)&name)->sin_port;
		break;
	case AF_INET6:
		port = ((struct sockaddr_in6 *)&name)->sin6_port;
		break;
	default:
		CHECK(1, "Invalid address family", "%d\n", name.ss_family);
	}
	return port;
}

static int run_test(int server_fd, const struct sockaddr *addr, socklen_t len)
{
	int client = -1, srv_client = -1;
	char buf[] = "testing";
	in_port_t port;
	int ret = 1;

	client = connect_to_server(addr, len);
	if (client == -1) {
		perror("Cannot connect to server");
		goto out;
	}

	srv_client = accept(server_fd, NULL, NULL);
	if (CHECK_FAIL(srv_client == -1)) {
		perror("Can't accept connection");
		goto out;
	}
	if (CHECK_FAIL(write(client, buf, sizeof(buf)) != sizeof(buf))) {
		perror("Can't write on client");
		goto out;
	}
	if (CHECK_FAIL(read(srv_client, buf, sizeof(buf)) != sizeof(buf))) {
		perror("Can't read on server");
		goto out;
	}

	port = get_port(srv_client);
	if (CHECK_FAIL(!port))
		goto out;
	if (CHECK(port != htons(TEST_DPORT), "Expected", "port %u but got %u",
		  TEST_DPORT, ntohs(port)))
		goto out;

	ret = 0;
out:
	close(client);
	close(srv_client);
	return ret;
}

static int do_sk_assign(void)
{
	struct sockaddr_in addr4;
	struct sockaddr_in6 addr6;
	int server = -1;
	int server_v6 = -1;
	int err = 1;

	memset(&addr4, 0, sizeof(addr4));
	addr4.sin_family = AF_INET;
	addr4.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	addr4.sin_port = htons(1234);

	memset(&addr6, 0, sizeof(addr6));
	addr6.sin6_family = AF_INET6;
	addr6.sin6_addr = in6addr_loopback;
	addr6.sin6_port = htons(1234);

	server = start_server((const struct sockaddr *)&addr4, sizeof(addr4));
	if (server == -1)
		goto out;

	server_v6 = start_server((const struct sockaddr *)&addr6,
				 sizeof(addr6));
	if (server_v6 == -1)
		goto out;

	/* Connect to unbound ports */
	addr4.sin_port = htons(TEST_DPORT);
	addr6.sin6_port = htons(TEST_DPORT);

	test__start_subtest("ipv4 port redir");
	if (run_test(server, (const struct sockaddr *)&addr4, sizeof(addr4)))
		goto out;

	test__start_subtest("ipv6 port redir");
	if (run_test(server_v6, (const struct sockaddr *)&addr6, sizeof(addr6)))
		goto out;

	/* Connect to unbound addresses */
	addr4.sin_addr.s_addr = htonl(TEST_DADDR);
	addr6.sin6_addr.s6_addr32[3] = htonl(TEST_DADDR);

	test__start_subtest("ipv4 addr redir");
	if (run_test(server, (const struct sockaddr *)&addr4, sizeof(addr4)))
		goto out;

	test__start_subtest("ipv6 addr redir");
	if (run_test(server_v6, (const struct sockaddr *)&addr6, sizeof(addr6)))
		goto out;

	err = 0;
out:
	close(server);
	close(server_v6);
	return err;
}

void test_sk_assign(void)
{
	int self_net;

	self_net = open(NS_SELF, O_RDONLY);
	if (CHECK_FAIL(self_net < 0)) {
		perror("Unable to open "NS_SELF);
		return;
	}

	if (!configure_stack(self_net)) {
		perror("configure_stack");
		goto cleanup;
	}

	do_sk_assign();

cleanup:
	close(self_net);
}
