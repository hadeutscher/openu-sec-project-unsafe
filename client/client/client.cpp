#include <iostream>
#include <cassert>
#include <WinSock2.h>
#include <WS2tcpip.h>
#include <vector>
#include <sstream>

#include "sockaddr.h"
#include "socket.h"

#pragma comment (lib, "Ws2_32.lib")

void* startup() {
	WSADATA wsadata;
	int error = WSAStartup(0x0202, &wsadata);
	if (error) {
		throw std::runtime_error("WSAStartup error");
	}
	return nullptr;
}

void cleanup() {
	WSACleanup();
}

enum class Operation {
	AUTH_DATA = 1,
	AUTH_RESULT = 2,
	CODE_DATA = 3,
	CODE_RESULT = 4,
};

void tlv_send(Socket& s, std::string value, Operation type) {
	std::vector<byte> header;
	header.resize(8);
	*reinterpret_cast<uint32_t*>(header.data()) = htonl(static_cast<int>(type));
	*reinterpret_cast<uint32_t*>(header.data() + 4) = htonl(value.length());
	s.send(header);
	std::vector<byte> data(value.begin(), value.end());
	s.send(data);
}

std::string tlv_recv(Socket& s, Operation req_type) {
	std::vector<byte> header = s.recv(8);
	Operation type = static_cast<Operation>(ntohl(*reinterpret_cast<uint32_t*>(header.data())));
	if (type != req_type) {
		std::cerr << "Expected: " << static_cast<int>(req_type) << ", Got: " << static_cast<int>(type) << std::endl;
		throw std::runtime_error("incorrect packet type");
	}
	size_t len = ntohl(*reinterpret_cast<uint32_t*>(header.data() + 4));
	std::vector<byte> data = s.recv(len);
	return std::string(data.begin(), data.end());
}

std::string read_code()
{
	std::string code;
	std::getline(std::cin, code);
	return code;
}

void operate(std::string addr, std::string password) {
	Sockaddr saddr(addr, "1337");
	Socket s(saddr.get()->sa_family, SOCK_STREAM, IPPROTO_TCP);
	s.connect(saddr);
	tlv_send(s, password, Operation::AUTH_DATA);
	if (tlv_recv(s, Operation::AUTH_RESULT) != "Success") {
		std::cerr << "Bad password" << std::endl;
		return;
	}
	std::cerr << "Type code to evaluate: " << std::endl;
	tlv_send(s, read_code(), Operation::CODE_DATA);
	std::cout << "Result: " << tlv_recv(s, Operation::CODE_RESULT) << std::endl;
}

int main(int argc, const char* argv[])
{
	if (argc != 3) {
		std::cerr << "Usage: client <address> <password>" << std::endl;
		return -1;
	}
	auto deleter = [](void*) { cleanup(); };
	std::unique_ptr<void, decltype(deleter)> wsa(startup(), deleter);
	std::string addr(argv[1]);
	std::string password(argv[2]);
	try {
		operate(std::move(addr), std::move(password));
	}
	catch (const std::exception& e) {
		std::cerr << "Failed: " << e.what() << std::endl;
		return -1;
	}
	return 0;
}
