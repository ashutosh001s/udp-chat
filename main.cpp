#include <iostream>
#include <string>
#include <vector>
#include <unordered_map>
#include <thread>
#include <chrono>
#include <mutex>
#include <atomic>
#include <cstring>
#include <algorithm>

// Cross-platform socket includes
#ifdef _WIN32
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
typedef int socklen_t;
#define CLOSE_SOCKET closesocket
#define GET_SOCKET_ERROR() WSAGetLastError()
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#define SOCKET int
#define INVALID_SOCKET -1
#define SOCKET_ERROR -1
#define CLOSE_SOCKET close
#define GET_SOCKET_ERROR() errno
#endif

// Simplified protocol constants
const size_t MAX_MESSAGE_SIZE = 1400; // Just under MTU to avoid fragmentation
const size_t HEADER_SIZE = 8;
const uint32_t HEARTBEAT_INTERVAL_MS = 10000; // Less frequent heartbeats
const uint32_t CONNECTION_TIMEOUT_MS = 30000; // Longer timeout

// Simplified message types
enum class MessageType : uint8_t {
	CHAT = 1,
	PING = 2,
	PONG = 3,
	CONNECT = 4
};

// Minimal packet header - no reliability overhead
#ifdef _WIN32
#pragma pack(push, 1)
struct PacketHeader {
	uint32_t magic;          // Magic number for validation
	uint8_t msg_type;        // Message type
	uint8_t reserved[3];     // Padding for alignment
};
#pragma pack(pop)
#else
struct PacketHeader {
	uint32_t magic;          // Magic number for validation
	uint8_t msg_type;        // Message type
	uint8_t reserved[3];     // Padding for alignment
} __attribute__((packed));
#endif

const uint32_t MAGIC_NUMBER = 0xDEADC0DE;

// Simplified peer state
struct PeerState {
	sockaddr_in address;
	std::chrono::steady_clock::time_point last_activity;
	bool connected;

	PeerState() : last_activity(std::chrono::steady_clock::now()), connected(false) {
		memset(&address, 0, sizeof(address));
	}
};

class FastUDPChat {
private:
	SOCKET socket_fd;
	std::atomic<bool> running;
	std::unordered_map<std::string, PeerState> peers;
	std::mutex peers_mutex;
	std::thread receive_thread;
	std::thread maintenance_thread;

	// Fast packet serialization
	std::vector<uint8_t> create_packet(MessageType type, const std::string& payload) {
		std::vector<uint8_t> packet(HEADER_SIZE + payload.size());
		PacketHeader* header = reinterpret_cast<PacketHeader*>(packet.data());

		header->magic = htonl(MAGIC_NUMBER);
		header->msg_type = static_cast<uint8_t>(type);
		memset(header->reserved, 0, sizeof(header->reserved));

		if (!payload.empty()) {
			memcpy(packet.data() + HEADER_SIZE, payload.data(), payload.size());
		}

		return packet;
	}

	// Fast packet parsing
	bool parse_packet(const uint8_t* data, size_t len, PacketHeader& header, std::string& payload) {
		if (len < HEADER_SIZE) return false;

		memcpy(&header, data, HEADER_SIZE);
		header.magic = ntohl(header.magic);

		if (header.magic != MAGIC_NUMBER) return false;

		size_t payload_len = len - HEADER_SIZE;
		if (payload_len > 0) {
			payload.assign(reinterpret_cast<const char*>(data + HEADER_SIZE), payload_len);
		}
		else {
			payload.clear();
		}

		return true;
	}

	std::string get_peer_key(const sockaddr_in& addr) {
		return std::string(inet_ntoa(addr.sin_addr)) + ":" + std::to_string(ntohs(addr.sin_port));
	}

	// Direct send - no reliability overhead
	void send_packet(const sockaddr_in& dest_addr, MessageType type, const std::string& payload = "") {
		auto packet = create_packet(type, payload);
		sendto(socket_fd, reinterpret_cast<const char*>(packet.data()),
			static_cast<int>(packet.size()), 0,
			reinterpret_cast<const sockaddr*>(&dest_addr), sizeof(dest_addr));
	}

	void handle_packet(const sockaddr_in& sender_addr, const PacketHeader& header, const std::string& payload) {
		std::string peer_key = get_peer_key(sender_addr);
		MessageType msg_type = static_cast<MessageType>(header.msg_type);

		// Update peer activity
		{
			std::lock_guard<std::mutex> lock(peers_mutex);
			PeerState& peer = peers[peer_key];
			peer.address = sender_addr;
			peer.last_activity = std::chrono::steady_clock::now();

			if (!peer.connected && msg_type == MessageType::CONNECT) {
				peer.connected = true;
				std::cout << "User " << peer_key << " connected\n";
			}
		}

		// Handle message types
		switch (msg_type) {
		case MessageType::CHAT:
			std::cout << "[" << peer_key << "]: " << payload << std::endl;
			break;

		case MessageType::PING:
			send_packet(sender_addr, MessageType::PONG);
			break;

		case MessageType::PONG:
			// Just updates last_activity above
			break;

		case MessageType::CONNECT:
			// Connection handled above
			break;
		}
	}

	void receive_loop() {
		uint8_t buffer[MAX_MESSAGE_SIZE];
		sockaddr_in sender_addr;
		socklen_t addr_len;

		while (running) {
			addr_len = sizeof(sender_addr);
			int bytes_received = recvfrom(socket_fd, reinterpret_cast<char*>(buffer),
				MAX_MESSAGE_SIZE, 0,
				reinterpret_cast<sockaddr*>(&sender_addr), &addr_len);

			if (bytes_received > 0) {
				PacketHeader header;
				std::string payload;

				if (parse_packet(buffer, bytes_received, header, payload)) {
					handle_packet(sender_addr, header, payload);
				}
			}
			else if (bytes_received == SOCKET_ERROR) {
#ifdef _WIN32
				int error = WSAGetLastError();
				if (error != WSAEWOULDBLOCK && error != WSAETIMEDOUT && running) {
#else
				if (errno != EAGAIN && errno != EWOULDBLOCK && running) {
#endif
					std::cerr << "Receive error: " << GET_SOCKET_ERROR() << std::endl;
					break;
				}
				std::this_thread::sleep_for(std::chrono::milliseconds(1));
				}
			}
		}

	void maintenance_loop() {
		auto last_heartbeat = std::chrono::steady_clock::now();

		while (running) {
			auto now = std::chrono::steady_clock::now();

			// Send heartbeats less frequently
			if (now - last_heartbeat >= std::chrono::milliseconds(HEARTBEAT_INTERVAL_MS)) {
				std::lock_guard<std::mutex> lock(peers_mutex);
				for (auto& [peer_key, peer] : peers) {
					if (peer.connected) {
						send_packet(peer.address, MessageType::PING);
					}
				}
				last_heartbeat = now;
			}

			// Clean up timed-out connections
			{
				std::lock_guard<std::mutex> lock(peers_mutex);
				for (auto it = peers.begin(); it != peers.end();) {
					if (now - it->second.last_activity >= std::chrono::milliseconds(CONNECTION_TIMEOUT_MS)) {
						if (it->second.connected) {
							std::cout << "Connection timeout for " << it->first << std::endl;
						}
						it = peers.erase(it);
					}
					else {
						++it;
					}
				}
			}

			// Sleep longer to reduce CPU usage
			std::this_thread::sleep_for(std::chrono::milliseconds(1000));
		}
	}

public:
	FastUDPChat() : socket_fd(INVALID_SOCKET), running(false) {
#ifdef _WIN32
		WSADATA wsaData;
		if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
			throw std::runtime_error("Failed to initialize Winsock");
		}
#endif
	}

	~FastUDPChat() {
		stop();
#ifdef _WIN32
		WSACleanup();
#endif
	}

	bool start(int port) {
		socket_fd = socket(AF_INET, SOCK_DGRAM, 0);
		if (socket_fd == INVALID_SOCKET) {
			std::cerr << "Failed to create socket: " << GET_SOCKET_ERROR() << std::endl;
			return false;
		}

		// Increase socket buffer sizes for better performance
		int buffer_size = 65536;
		setsockopt(socket_fd, SOL_SOCKET, SO_RCVBUF, reinterpret_cast<const char*>(&buffer_size), sizeof(buffer_size));
		setsockopt(socket_fd, SOL_SOCKET, SO_SNDBUF, reinterpret_cast<const char*>(&buffer_size), sizeof(buffer_size));

		// Set socket to non-blocking
#ifdef _WIN32
		u_long mode = 1;
		ioctlsocket(socket_fd, FIONBIO, &mode);
#else
		int flags = fcntl(socket_fd, F_GETFL, 0);
		fcntl(socket_fd, F_SETFL, flags | O_NONBLOCK);
#endif

		sockaddr_in local_addr{};
		local_addr.sin_family = AF_INET;
		local_addr.sin_addr.s_addr = INADDR_ANY;
		local_addr.sin_port = htons(static_cast<uint16_t>(port));

		if (bind(socket_fd, reinterpret_cast<sockaddr*>(&local_addr), sizeof(local_addr)) == SOCKET_ERROR) {
			std::cerr << "Failed to bind socket to port " << port << ": " << GET_SOCKET_ERROR() << std::endl;
			CLOSE_SOCKET(socket_fd);
			return false;
		}

		running = true;
		receive_thread = std::thread(&FastUDPChat::receive_loop, this);
		maintenance_thread = std::thread(&FastUDPChat::maintenance_loop, this);

		std::cout << "Fast UDP chat started on port " << port << std::endl;
		return true;
	}

	void stop() {
		if (running) {
			running = false;

			if (receive_thread.joinable()) receive_thread.join();
			if (maintenance_thread.joinable()) maintenance_thread.join();

			if (socket_fd != INVALID_SOCKET) {
				CLOSE_SOCKET(socket_fd);
				socket_fd = INVALID_SOCKET;
			}
		}
	}

	bool connect_to_peer(const std::string & ip, int port) {
		sockaddr_in peer_addr{};
		peer_addr.sin_family = AF_INET;
		peer_addr.sin_port = htons(static_cast<uint16_t>(port));

#ifdef _WIN32
		if (inet_pton(AF_INET, ip.c_str(), &peer_addr.sin_addr) <= 0) {
#else
		if (inet_aton(ip.c_str(), &peer_addr.sin_addr) == 0) {
#endif
			std::cerr << "Invalid IP address: " << ip << std::endl;
			return false;
		}

		std::string peer_key = get_peer_key(peer_addr);

		{
			std::lock_guard<std::mutex> lock(peers_mutex);
			PeerState& peer = peers[peer_key];
			peer.address = peer_addr;
			peer.connected = true;
			peer.last_activity = std::chrono::steady_clock::now();
		}

		// Send connection packet multiple times for reliability
		for (int i = 0; i < 3; ++i) {
			send_packet(peer_addr, MessageType::CONNECT);
			std::this_thread::sleep_for(std::chrono::milliseconds(100));
		}

		std::cout << "Connected to " << peer_key << std::endl;
		return true;
		}

	void send_chat_message(const std::string & message) {
		if (message.size() > MAX_MESSAGE_SIZE - HEADER_SIZE) {
			std::cerr << "Message too long, truncating..." << std::endl;
			std::string truncated = message.substr(0, MAX_MESSAGE_SIZE - HEADER_SIZE);
			send_chat_message(truncated);
			return;
		}

		std::lock_guard<std::mutex> lock(peers_mutex);
		for (const auto& [peer_key, peer] : peers) {
			if (peer.connected) {
				send_packet(peer.address, MessageType::CHAT, message);
			}
		}
	}

	std::vector<std::string> get_connected_peers() {
		std::vector<std::string> connected;
		std::lock_guard<std::mutex> lock(peers_mutex);
		for (const auto& [peer_key, peer] : peers) {
			if (peer.connected) {
				connected.push_back(peer_key);
			}
		}
		return connected;
	}
	};

// Simplified client
class FastChatClient {
private:
	FastUDPChat chat;

public:
	void run(const std::string& server_ip, int server_port, int local_port) {
		if (!chat.start(local_port)) {
			std::cerr << "Failed to start client on port " << local_port << std::endl;
			return;
		}

		std::cout << "Connecting to " << server_ip << ":" << server_port << std::endl;
		if (!chat.connect_to_peer(server_ip, server_port)) {
			std::cerr << "Failed to connect to server" << std::endl;
			return;
		}

		std::cout << "Connected! Type messages to chat (type 'quit' to exit):\n";

		std::string input;
		while (std::getline(std::cin, input)) {
			if (input == "quit" || input == "exit") break;
			if (!input.empty()) {
				chat.send_chat_message(input);
			}
		}
	}
};

// Simplified server
class FastChatServer {
private:
	FastUDPChat chat;

public:
	void run(int port) {
		if (!chat.start(port)) {
			std::cerr << "Failed to start server on port " << port << std::endl;
			return;
		}

		std::cout << "Fast chat server running on port " << port << std::endl;
		std::cout << "Type messages to broadcast (type 'quit' to exit, 'status' for info):\n";

		std::string input;
		while (std::getline(std::cin, input)) {
			if (input == "quit" || input == "exit") break;

			if (input == "status") {
				auto peers = chat.get_connected_peers();
				std::cout << "Connected clients: " << peers.size() << std::endl;
				for (const auto& peer : peers) {
					std::cout << "  - " << peer << std::endl;
				}
				continue;
			}

			if (!input.empty()) {
				chat.send_chat_message("[Server]: " + input);
			}
		}
	}
};

int main(int argc, char* argv[]) {
	if (argc < 2) {
		std::cout << "Usage:\n";
		std::cout << "  Server: " << argv[0] << " server <port>\n";
		std::cout << "  Client: " << argv[0] << " client <server_ip> <server_port> <local_port>\n";
		return 1;
	}

	std::string mode = argv[1];

	try {
		if (mode == "server") {
			if (argc != 3) {
				std::cerr << "Server usage: " << argv[0] << " server <port>\n";
				return 1;
			}

			int port = std::stoi(argv[2]);
			FastChatServer server;
			server.run(port);

		}
		else if (mode == "client") {
			if (argc != 5) {
				std::cerr << "Client usage: " << argv[0] << " client <server_ip> <server_port> <local_port>\n";
				return 1;
			}

			std::string server_ip = argv[2];
			int server_port = std::stoi(argv[3]);
			int local_port = std::stoi(argv[4]);

			FastChatClient client;
			client.run(server_ip, server_port, local_port);

		}
		else {
			std::cerr << "Invalid mode. Use 'server' or 'client'\n";
			return 1;
		}
	}
	catch (const std::exception& e) {
		std::cerr << "Error: " << e.what() << std::endl;
		return 1;
	}

	return 0;
}
