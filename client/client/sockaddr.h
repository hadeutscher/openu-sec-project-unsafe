#pragma once

#include <WinSock2.h>
#include <WS2tcpip.h>
#include <string>

class Sockaddr {
public:
	Sockaddr(std::string addr, std::string port);
	sockaddr* get() { return reinterpret_cast<sockaddr*>(&_addr); }
	const sockaddr* get() const { return reinterpret_cast<const sockaddr*>(&_addr); }
	size_t len() const { return _len; }
protected:
	SOCKADDR_STORAGE _addr;
	size_t _len;
};
