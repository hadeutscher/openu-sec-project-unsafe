#pragma once

#include <WinSock2.h>
#include <WS2tcpip.h>
#include <vector>

#include "sockaddr.h"

class Socket {
public:
	Socket(int af, int type, int protocol);
	Socket(const Socket&) = delete;
	Socket(Socket&& other) noexcept : s(std::exchange(other.s, INVALID_SOCKET)) {}
	Socket& operator=(const Socket&) = delete;
	Socket& operator=(Socket&& other) noexcept;
	virtual ~Socket();
	SOCKET get() { return s; }
	void connect(const Sockaddr& addr);
	void send(std::vector<byte> data);
	std::vector<byte> recv(int len);
protected:
	Socket(SOCKET s) : s(s) {}
	SOCKET s;
};
