#include "sockaddr.h"

#include <memory>
#include <stdexcept>

Sockaddr::Sockaddr(std::string addr, std::string port) {
	ADDRINFO hints{};
	ADDRINFO* result_raw;
	if (getaddrinfo(addr.c_str(), port.c_str(), &hints, &result_raw)) {
		throw std::runtime_error("getaddrinfo failed");
	}
	auto deleter = [](ADDRINFO* ptr) { freeaddrinfo(ptr); };
	std::unique_ptr<ADDRINFO, decltype(deleter)> result(result_raw, deleter);
	for (ADDRINFO* curr = result.get(); curr; curr = curr->ai_next) {
		switch (result->ai_family) {
		case AF_INET:
		case AF_INET6:
			_len = curr->ai_addrlen;
			memcpy(&_addr, curr->ai_addr, _len);
			return;
		default:
			continue;
		}
	}
	throw std::runtime_error("unsupported address type");
}
