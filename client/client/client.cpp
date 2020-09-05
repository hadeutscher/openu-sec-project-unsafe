#include <iostream>
#include <cassert>
#include <WinSock2.h>
#include <WS2tcpip.h>
#include <vector>
#include <sstream>
#include <tuple>
#include <functional>

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

decltype(auto) tlv_recv(Socket& s) {
	std::vector<byte> header = s.recv(8);
	Operation type = static_cast<Operation>(ntohl(*reinterpret_cast<uint32_t*>(header.data())));
	size_t len = ntohl(*reinterpret_cast<uint32_t*>(header.data() + 4));
	std::vector<byte> data = s.recv(len);
	std::string str = std::string(data.begin(), data.end());
	return std::make_tuple(str, type);
}

void read_single_line(char* buf, size_t len)
{
	std::cin.getline(buf, len);
}

void read_multi_line(char* buf, size_t len)
{
	std::cin.read(buf, len);
}

class UserCodeFetcher {
public:
	using Callback = void (*)(char*, size_t);
	UserCodeFetcher(Callback&& read_cb) : buf{}, read_cb(read_cb) {}
	std::string fetch() {
		read_cb(buf, sizeof(buf));
		return std::string(buf);
	}
private:
	char buf[1060];
	Callback read_cb;
};

class PasswordError : std::exception {};

UserCodeFetcher* fetcher = nullptr;
char auth_result[1024] = {};

void operate(std::string addr, std::string password) {
	Sockaddr saddr(addr, "1337");
	Socket s(saddr.get()->sa_family, SOCK_STREAM, IPPROTO_TCP);
	s.connect(saddr);
	tlv_send(s, password, Operation::AUTH_DATA);
	std::string data;
	Operation op;
	try {
		while (true) {
			std::tie(data, op) = tlv_recv(s);
			switch (op) {
			case Operation::AUTH_RESULT:
				// Save auth result for main
				strncpy_s(auth_result, data.c_str(), sizeof(auth_result));
				if (auth_result[0] != 'S') {
					throw PasswordError();
				}
				std::cerr << "Type code to evaluate: " << std::endl;
				tlv_send(s, fetcher->fetch(), Operation::CODE_DATA);
				delete fetcher;
				break;
			case Operation::CODE_RESULT:
				std::cout << "Result: " << data << std::endl;
				break;
			}
		}
	}
	catch (const SocketClosed&) {
		// Graceful close, do nothing and exit
	}
}

int main(int argc, const char* argv[])
{
	if (argc < 3) {
		std::cerr << "Usage: client <address> <password> [-m]" << std::endl;
		return -1;
	}
	auto deleter = [](void*) { cleanup(); };
	std::unique_ptr<void, decltype(deleter)> wsa(startup(), deleter);
	std::string addr(argv[1]);
	std::string password(argv[2]);
	bool multiline = argc > 3 && !strcmp(argv[3], "-m");
	fetcher = new UserCodeFetcher(multiline ? read_multi_line : read_single_line);
	try {
		operate(std::move(addr), std::move(password));
	}
	catch (const PasswordError&) {
		std::cerr << "Server auth failed: " << auth_result << std::endl;
		return -1;
	}
	catch (const std::exception& e) {
		// Hard close
		std::cerr << "Failed: " << e.what() << std::endl;
		return -1;
	}
	return 0;
}
