#include "socket.h"

#include <stdexcept>

Socket::Socket(int af, int type, int protocol) :
	s(socket(af, type, protocol)) {
	if (s == INVALID_SOCKET) {
		throw std::runtime_error("socket error");
	}
}

Socket& Socket::operator=(Socket&& other) noexcept {
	SOCKET old = std::exchange(s, INVALID_SOCKET);
	if (old != INVALID_SOCKET) {
		closesocket(s);
	}
	s = std::exchange(other.s, INVALID_SOCKET);
	return *this;
}

Socket::~Socket() {
	if (s != INVALID_SOCKET) {
		closesocket(s);
	}
}

void Socket::connect(const Sockaddr& addr) {
	if (::connect(s, addr.get(), addr.len())) {
		throw std::runtime_error("connect error");
	}
}

void Socket::send(std::vector<byte> data) {
	size_t sent = 0;
	while (sent < data.size()) {
		int result = ::send(s, reinterpret_cast<char*>(data.data() + sent), data.size() - sent, 0);
		if (result == SOCKET_ERROR) {
			throw std::runtime_error("send error");
		}
		sent += result;
	}
}

std::vector<byte> Socket::recv(int len) {
	std::vector<byte> result;
	result.resize(len);
	char* data = reinterpret_cast<char*>(result.data());
	int err = ::recv(s, data, len, MSG_WAITALL);
	if (err == 0) {
		throw SocketClosed();
	}
	else if (err == SOCKET_ERROR || err != len) {
		throw std::runtime_error("recv error");
	}
	return std::move(result);
}
