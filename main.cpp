#include <iostream>
#include <string>
#include <thread>
#include <atomic>
#include <chrono>
#include <cstring>
#include <vector>
#include <set>
#include <unordered_set>
#include <unordered_map>
#include <mutex>
#include <random>

#ifdef _WIN32
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "winmm.lib")
typedef int socklen_t;
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <cstdlib>
#include <ifaddrs.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>
#define SOCKET int
#define INVALID_SOCKET -1
#define SOCKET_ERROR -1
#define closesocket close
#endif

struct DeviceInfo {
    std::string username;
    std::string deviceId;
    std::chrono::steady_clock::time_point lastSeen;

    DeviceInfo(const std::string& user, const std::string& id)
        : username(user), deviceId(id), lastSeen(std::chrono::steady_clock::now()) {
    }
};

class UDPChatApp {
private:
    SOCKET sendSock;
    SOCKET recvSock;
    struct sockaddr_in broadcastAddr;
    struct sockaddr_in listenAddr;
    std::atomic<bool> running;
    std::atomic<bool> socketsHealthy;
    std::string username;
    std::string deviceId;
    std::unordered_set<std::string> recentMessages;
    std::unordered_map<std::string, DeviceInfo> activeDevices;
    std::chrono::steady_clock::time_point lastCleanup;
    std::chrono::steady_clock::time_point lastMessageTime;
    std::chrono::steady_clock::time_point lastHealthCheck;
    std::chrono::steady_clock::time_point lastPingTime;
    std::chrono::steady_clock::time_point lastDeviceCleanup;
    std::mutex socketMutex;
    std::mutex deviceMutex;
    std::atomic<int> consecutiveErrors;

    static const int PORT = 12345;
    static const int BUFFER_SIZE = 1024;
    static const int MAX_RECENT_MESSAGES = 50;
    static const int MAX_CONSECUTIVE_ERRORS = 5;
    static const int HEALTH_CHECK_INTERVAL = 30; // seconds
    static const int SOCKET_TIMEOUT = 5; // seconds
    static const int PING_INTERVAL = 60; // seconds - send ping every minute
    static const int DEVICE_TIMEOUT = 180; // seconds - device considered offline after 3 minutes

    std::string generateDeviceId() {
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> dis(100000, 999999);
        return std::to_string(dis(gen));
    }

#ifdef _WIN32
    void logError(const std::string& message) {
        auto now = std::chrono::system_clock::now();
        time_t time = std::chrono::system_clock::to_time_t(now);

        char timeStr[26]; // ctime_s requires a buffer of at least 26 bytes
        ctime_s(timeStr, sizeof(timeStr), &time);

        // Remove newline added by ctime_s
        timeStr[24] = '\0';

        std::cout << "\n[ERROR " << timeStr << "] " << message << std::endl;
        std::cout << "You: " << std::flush;
    }

    void logInfo(const std::string& message) {
        auto now = std::chrono::system_clock::now();
        time_t time = std::chrono::system_clock::to_time_t(now);

        char timeStr[26];
        ctime_s(timeStr, sizeof(timeStr), &time);
        timeStr[24] = '\0';

        std::cout << "\n[INFO " << timeStr << "] " << message << std::endl;
        std::cout << "You: " << std::flush;
    }

#else

    void logError(const std::string& message) {
        auto now = std::chrono::system_clock::now();
        auto time_t = std::chrono::system_clock::to_time_t(now);
        std::cout << "\n[ERROR " << std::ctime(&time_t) << "] " << message << std::endl;
        std::cout << "You: " << std::flush;
    }

    void logInfo(const std::string& message) {
        auto now = std::chrono::system_clock::now();
        auto time_t = std::chrono::system_clock::to_time_t(now);
        std::cout << "\n[INFO " << std::ctime(&time_t) << "] " << message << std::endl;
        std::cout << "You: " << std::flush;
    }

#endif // _WIN32

    bool testSocketHealth() {
        // Simple health check - try to send a small packet to ourselves
        std::string testMessage = "HEALTH_CHECK_" + username;
        struct sockaddr_in testAddr;
        memset(&testAddr, 0, sizeof(testAddr));
        testAddr.sin_family = AF_INET;
        testAddr.sin_port = htons(PORT);
        testAddr.sin_addr.s_addr = inet_addr("127.0.0.1");

        int result = sendto(sendSock, testMessage.c_str(), (int)testMessage.length(), 0,
            reinterpret_cast<struct sockaddr*>(&testAddr), sizeof(testAddr));

        return result != SOCKET_ERROR;
    }

    void resetSockets() {
        std::lock_guard<std::mutex> lock(socketMutex);

        logInfo("Resetting sockets due to health issues...");

        // Close existing sockets
        if (sendSock != INVALID_SOCKET) {
            closesocket(sendSock);
        }
        if (recvSock != INVALID_SOCKET) {
            closesocket(recvSock);
        }

        // Small delay before recreating
        std::this_thread::sleep_for(std::chrono::milliseconds(500));

        // Recreate sockets
        try {
            initializeSockets();
            consecutiveErrors = 0;
            socketsHealthy = true;
            logInfo("Sockets reset successfully");
        }
        catch (...) {
            logError("Failed to reset sockets");
            socketsHealthy = false;
        }
    }

    std::vector<std::string> getAllBroadcastAddresses() {
        std::vector<std::string> addresses;

#ifdef _WIN32
        addresses.push_back("255.255.255.255");
        addresses.push_back("192.168.1.255");
        addresses.push_back("192.168.0.255");
#else
        struct ifaddrs* ifap, * ifa;

        if (getifaddrs(&ifap) == 0) {
            for (ifa = ifap; ifa != nullptr; ifa = ifa->ifa_next) {
                if (ifa->ifa_addr && ifa->ifa_addr->sa_family == AF_INET &&
                    (ifa->ifa_flags & IFF_BROADCAST) && (ifa->ifa_flags & IFF_UP) &&
                    !(ifa->ifa_flags & IFF_LOOPBACK)) {

                    if (ifa->ifa_broadaddr) {
                        struct sockaddr_in* bsin = (struct sockaddr_in*)ifa->ifa_broadaddr;
                        std::string broadcastAddr = inet_ntoa(bsin->sin_addr);
                        addresses.push_back(broadcastAddr);
                    }
                }
            }
            freeifaddrs(ifap);
        }

        // Add common addresses as fallback
        if (addresses.empty()) {
            addresses.push_back("255.255.255.255");
            addresses.push_back("192.168.1.255");
            addresses.push_back("192.168.0.255");
            addresses.push_back("10.0.0.255");
        }
#endif
        return addresses;
    }

    std::string createMessageHash(const std::string& message) {
        std::hash<std::string> hasher;
        return std::to_string(hasher(message));
    }

    bool isDuplicateMessage(const std::string& message) {
        // Skip health check messages
        if (message.find("HEALTH_CHECK_") == 0) {
            return true;
        }

        auto now = std::chrono::steady_clock::now();

        // Clean up old messages every 30 seconds
        if (now - lastCleanup > std::chrono::seconds(30)) {
            recentMessages.clear();
            lastCleanup = now;
        }

        std::string messageHash = createMessageHash(message);

        if (recentMessages.find(messageHash) != recentMessages.end()) {
            return true;
        }

        recentMessages.insert(messageHash);

        if (recentMessages.size() > MAX_RECENT_MESSAGES) {
            recentMessages.clear();
        }

        return false;
    }

    void sendPing() {
        if (!socketsHealthy) {
            return;
        }

        std::string pingMessage = "PING:" + deviceId + ":" + username;
        std::lock_guard<std::mutex> lock(socketMutex);

        std::vector<std::string> broadcastAddresses = getAllBroadcastAddresses();

        for (const auto& addr : broadcastAddresses) {
            struct sockaddr_in tempAddr;
            memset(&tempAddr, 0, sizeof(tempAddr));
            tempAddr.sin_family = AF_INET;
            tempAddr.sin_port = htons(PORT);

            if (inet_pton(AF_INET, addr.c_str(), &tempAddr.sin_addr) == 1) {
                sendto(sendSock, pingMessage.c_str(), (int)pingMessage.length(), 0,
                    reinterpret_cast<struct sockaddr*>(&tempAddr), sizeof(tempAddr));
                std::this_thread::sleep_for(std::chrono::milliseconds(2));
            }
        }
    }

    void sendPong(const std::string& targetDeviceId) {
        if (!socketsHealthy) {
            return;
        }

        std::string pongMessage = "PONG:" + deviceId + ":" + username + ":" + targetDeviceId;
        std::lock_guard<std::mutex> lock(socketMutex);

        std::vector<std::string> broadcastAddresses = getAllBroadcastAddresses();

        for (const auto& addr : broadcastAddresses) {
            struct sockaddr_in tempAddr;
            memset(&tempAddr, 0, sizeof(tempAddr));
            tempAddr.sin_family = AF_INET;
            tempAddr.sin_port = htons(PORT);

            if (inet_pton(AF_INET, addr.c_str(), &tempAddr.sin_addr) == 1) {
                sendto(sendSock, pongMessage.c_str(), (int)pongMessage.length(), 0,
                    reinterpret_cast<struct sockaddr*>(&tempAddr), sizeof(tempAddr));
                std::this_thread::sleep_for(std::chrono::milliseconds(2));
            }
        }
    }

    void handlePingMessage(const std::string& senderDeviceId, const std::string& senderUsername) {
        // Don't respond to our own ping
        if (senderDeviceId == deviceId) {
            return;
        }

        // Update device list
        {
            std::lock_guard<std::mutex> lock(deviceMutex);
            auto it = activeDevices.find(senderDeviceId);
            if (it != activeDevices.end()) {
                it->second.lastSeen = std::chrono::steady_clock::now();
                it->second.username = senderUsername; // Update username in case it changed
            }
            else {
                activeDevices.emplace(senderDeviceId, DeviceInfo(senderUsername, senderDeviceId));
            }
        }

        // Send pong response
        sendPong(senderDeviceId);
    }

    void handlePongMessage(const std::string& senderDeviceId, const std::string& senderUsername, const std::string& targetDeviceId) {
        // Check if this pong is for us
        if (targetDeviceId != deviceId) {
            return;
        }

        // Don't process our own pong
        if (senderDeviceId == deviceId) {
            return;
        }

        // Update device list
        std::lock_guard<std::mutex> lock(deviceMutex);
        auto it = activeDevices.find(senderDeviceId);
        if (it != activeDevices.end()) {
            it->second.lastSeen = std::chrono::steady_clock::now();
            it->second.username = senderUsername;
        }
        else {
            activeDevices.emplace(senderDeviceId, DeviceInfo(senderUsername, senderDeviceId));
        }
    }

    void cleanupOldDevices() {
        std::lock_guard<std::mutex> lock(deviceMutex);
        auto now = std::chrono::steady_clock::now();

        auto it = activeDevices.begin();
        while (it != activeDevices.end()) {
            auto timeSinceLastSeen = std::chrono::duration_cast<std::chrono::seconds>(now - it->second.lastSeen).count();
            if (timeSinceLastSeen > DEVICE_TIMEOUT) {
                it = activeDevices.erase(it);
            }
            else {
                ++it;
            }
        }
    }

    std::vector<std::string> parseMessage(const std::string& message, char delimiter) {
        std::vector<std::string> parts;
        std::string current;

        for (char c : message) {
            if (c == delimiter) {
                parts.push_back(current);
                current.clear();
            }
            else {
                current += c;
            }
        }
        if (!current.empty()) {
            parts.push_back(current);
        }

        return parts;
    }

public:
    UDPChatApp(const std::string& user) : username(user), running(true), socketsHealthy(true),
        sendSock(INVALID_SOCKET), recvSock(INVALID_SOCKET), consecutiveErrors(0) {
        deviceId = generateDeviceId();
        lastCleanup = std::chrono::steady_clock::now();
        lastMessageTime = std::chrono::steady_clock::now();
        lastHealthCheck = std::chrono::steady_clock::now();
        lastPingTime = std::chrono::steady_clock::now();
        lastDeviceCleanup = std::chrono::steady_clock::now();

#ifndef _WIN32
        // Ignore SIGPIPE to prevent crashes on broken connections
        signal(SIGPIPE, SIG_IGN);
#endif

        initializeSockets();
    }

    ~UDPChatApp() {
        cleanup();
    }

    void initializeSockets() {
#ifdef _WIN32
        WSADATA wsaData;
        if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
            throw std::runtime_error("WSAStartup failed");
        }
#endif

        // Create sockets
        sendSock = socket(AF_INET, SOCK_DGRAM, 0);
        recvSock = socket(AF_INET, SOCK_DGRAM, 0);

        if (sendSock == INVALID_SOCKET || recvSock == INVALID_SOCKET) {
            throw std::runtime_error("Socket creation failed");
        }

        // Set socket timeouts
#ifdef _WIN32
        DWORD timeout = SOCKET_TIMEOUT * 1000; // milliseconds
        setsockopt(sendSock, SOL_SOCKET, SO_SNDTIMEO, (char*)&timeout, sizeof(timeout));
        setsockopt(recvSock, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(timeout));
#else
        struct timeval tv;
        tv.tv_sec = SOCKET_TIMEOUT;
        tv.tv_usec = 0;
        setsockopt(sendSock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
        setsockopt(recvSock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
#endif

        // Configure send socket
        int broadcast = 1;
        if (setsockopt(sendSock, SOL_SOCKET, SO_BROADCAST,
            reinterpret_cast<const char*>(&broadcast), sizeof(broadcast)) < 0) {
            throw std::runtime_error("Error enabling broadcast on send socket");
        }

        // Configure receive socket
        int reuse = 1;
        setsockopt(recvSock, SOL_SOCKET, SO_REUSEADDR,
            reinterpret_cast<const char*>(&reuse), sizeof(reuse));

#ifndef _WIN32
        int reusePort = 1;
        setsockopt(recvSock, SOL_SOCKET, SO_REUSEPORT, &reusePort, sizeof(reusePort));

        setsockopt(recvSock, SOL_SOCKET, SO_BROADCAST,
            reinterpret_cast<const char*>(&broadcast), sizeof(broadcast));
#endif

        // Set buffer sizes
        int bufSize = 65536;
        setsockopt(sendSock, SOL_SOCKET, SO_SNDBUF, reinterpret_cast<const char*>(&bufSize), sizeof(bufSize));
        setsockopt(recvSock, SOL_SOCKET, SO_RCVBUF, reinterpret_cast<const char*>(&bufSize), sizeof(bufSize));

        // Setup addresses
        memset(&broadcastAddr, 0, sizeof(broadcastAddr));
        broadcastAddr.sin_family = AF_INET;
        broadcastAddr.sin_port = htons(PORT);
        broadcastAddr.sin_addr.s_addr = INADDR_BROADCAST;

        memset(&listenAddr, 0, sizeof(listenAddr));
        listenAddr.sin_family = AF_INET;
        listenAddr.sin_port = htons(PORT);
        listenAddr.sin_addr.s_addr = INADDR_ANY;

        // Bind receive socket
        if (bind(recvSock, reinterpret_cast<struct sockaddr*>(&listenAddr), sizeof(listenAddr)) < 0) {
#ifdef _WIN32
            throw std::runtime_error("Bind failed. Error: " + std::to_string(WSAGetLastError()));
#else
            throw std::runtime_error("Bind failed: " + std::string(strerror(errno)));
#endif
        }

        std::cout << "Sockets initialized successfully on port " << PORT << std::endl;
    }

    void playNotificationSound() {
#ifdef _WIN32
        PlaySound(TEXT("SystemAsterisk"), NULL, SND_ALIAS | SND_ASYNC);
#else
        // Try PulseAudio first, fallback to terminal bell
        if (system("pactl play-sample bell-terminal 2>/dev/null") != 0) {
            std::cout << '\a' << std::flush;
        }
#endif
    }

    void showNotification(const std::string& message) {
#ifdef _WIN32
        std::string title = "UDP Chat";
        // Suppress only the assembly loading output, keep PowerShell running normally
        std::string command = "powershell -Command \"[System.Reflection.Assembly]::LoadWithPartialName('System.Windows.Forms') | Out-Null; $notify = New-Object System.Windows.Forms.NotifyIcon; $notify.Icon = [System.Drawing.SystemIcons]::Information; $notify.Visible = $true; $notify.ShowBalloonTip(3000, '" + title + "', '" + message + "', 'Info')\" 2>nul";
        system(command.c_str());
#else
        std::string escapedMsg = message;
        size_t pos = 0;
        while ((pos = escapedMsg.find("'", pos)) != std::string::npos) {
            escapedMsg.replace(pos, 1, "'\"'\"'");
            pos += 5;
        }
        system(("notify-send 'UDP Chat' '" + escapedMsg + "' 2>/dev/null").c_str());
#endif
    }

    void listenForMessages() {
        char buffer[BUFFER_SIZE];
        struct sockaddr_in senderAddr;
        socklen_t senderLen = sizeof(senderAddr);
        int consecutiveTimeouts = 0;

        std::cout << "Listening for messages...\n" << std::endl;

        while (running) {
            if (!socketsHealthy) {
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
                continue;
            }

            memset(buffer, 0, BUFFER_SIZE);

            int bytesReceived = recvfrom(recvSock, buffer, BUFFER_SIZE - 1, 0,
                reinterpret_cast<struct sockaddr*>(&senderAddr), &senderLen);

            if (bytesReceived > 0) {
                buffer[bytesReceived] = '\0';
                std::string message(buffer);

                // Handle ping/pong messages
                if (message.find("PING:") == 0) {
                    auto parts = parseMessage(message, ':');
                    if (parts.size() >= 3) {
                        std::string senderDeviceId = parts[1];
                        std::string senderUsername = parts[2];
                        handlePingMessage(senderDeviceId, senderUsername);
                    }
                    continue;
                }

                if (message.find("PONG:") == 0) {
                    auto parts = parseMessage(message, ':');
                    if (parts.size() >= 4) {
                        std::string senderDeviceId = parts[1];
                        std::string senderUsername = parts[2];
                        std::string targetDeviceId = parts[3];
                        handlePongMessage(senderDeviceId, senderUsername, targetDeviceId);
                    }
                    continue;
                }

                // Handle regular messages
                if (message.find(username + ":") != 0 && !isDuplicateMessage(message)) {
                    std::cout << "\r" << message << std::endl;
                    std::cout << "You: " << std::flush;

                    playNotificationSound();
                    showNotification(message);

                    lastMessageTime = std::chrono::steady_clock::now();
                    consecutiveTimeouts = 0;
                    consecutiveErrors = 0;
                }
            }
            else {
#ifdef _WIN32
                int error = WSAGetLastError();
                if (error == WSAETIMEDOUT) {
                    consecutiveTimeouts++;
                }
                else if (error != WSAEWOULDBLOCK) {
                    consecutiveErrors++;
                    logError("Receive error: " + std::to_string(error));
                }
#else
                if (errno == EAGAIN || errno == EWOULDBLOCK) {
                    consecutiveTimeouts++;
                }
                else {
                    consecutiveErrors++;
                    logError("Receive error: " + std::string(strerror(errno)));
                }
#endif

                // If too many errors, try to reset sockets
                if (consecutiveErrors >= MAX_CONSECUTIVE_ERRORS) {
                    socketsHealthy = false;
                    resetSockets();
                    consecutiveTimeouts = 0;
                }
            }

            auto now = std::chrono::steady_clock::now();

            // Periodic health check
            if (now - lastHealthCheck > std::chrono::seconds(HEALTH_CHECK_INTERVAL)) {
                if (!testSocketHealth()) {
                    logError("Socket health check failed");
                    socketsHealthy = false;
                    resetSockets();
                }
                lastHealthCheck = now;
            }

            // Send periodic ping
            if (now - lastPingTime > std::chrono::seconds(PING_INTERVAL)) {
                sendPing();
                lastPingTime = now;
            }

            // Clean up old devices
            if (now - lastDeviceCleanup > std::chrono::seconds(30)) {
                cleanupOldDevices();
                lastDeviceCleanup = now;
            }

            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
    }

    void sendMessage(const std::string& message) {
        if (!socketsHealthy) {
            logError("Sockets unhealthy, cannot send message");
            return;
        }

        std::lock_guard<std::mutex> lock(socketMutex);

        std::string fullMessage = username + ": " + message;
        std::vector<std::string> broadcastAddresses = getAllBroadcastAddresses();

        bool messageSent = false;

        for (const auto& addr : broadcastAddresses) {
            struct sockaddr_in tempAddr;
            memset(&tempAddr, 0, sizeof(tempAddr));
            tempAddr.sin_family = AF_INET;
            tempAddr.sin_port = htons(PORT);

            if (inet_pton(AF_INET, addr.c_str(), &tempAddr.sin_addr) == 1) {
                int bytesSent = sendto(sendSock, fullMessage.c_str(), (int)fullMessage.length(), 0,
                    reinterpret_cast<struct sockaddr*>(&tempAddr), sizeof(tempAddr));

                if (bytesSent != SOCKET_ERROR) {
                    messageSent = true;
                    consecutiveErrors = 0;
                }
                else {
                    consecutiveErrors++;
#ifdef _WIN32
                    logError("Send failed to " + addr + ": " + std::to_string(WSAGetLastError()));
#else
                    logError("Send failed to " + addr + ": " + std::string(strerror(errno)));
#endif
                }

                std::this_thread::sleep_for(std::chrono::milliseconds(2));
            }
        }

        if (!messageSent) {
            logError("Failed to send message to any address");
            if (consecutiveErrors >= MAX_CONSECUTIVE_ERRORS) {
                socketsHealthy = false;
                std::thread([this]() { resetSockets(); }).detach();
            }
        }
    }

    void showDeviceList() {
        std::lock_guard<std::mutex> lock(deviceMutex);
        auto now = std::chrono::steady_clock::now();

        std::cout << "\n=== Active Devices (" << activeDevices.size() << ") ===" << std::endl;
        std::cout << "Your Device ID: " << deviceId << std::endl;
        std::cout << "Your Username: " << username << std::endl;
        std::cout << "-------------------" << std::endl;

        if (activeDevices.empty()) {
            std::cout << "No other devices detected" << std::endl;
        }
        else {
            for (const auto& pair : activeDevices) {
                const auto& device = pair.second;
                auto secondsAgo = std::chrono::duration_cast<std::chrono::seconds>(now - device.lastSeen).count();
                std::cout << "Device: " << device.deviceId
                    << " | User: " << device.username
                    << " | Last seen: " << secondsAgo << "s ago" << std::endl;
            }
        }
        std::cout << "===================\n" << std::endl;
    }

    void run() {
        std::cout << "=== Badminton chat ===" << std::endl;
        std::cout << "Username: " << username << std::endl;
        std::cout << "Device ID: " << deviceId << std::endl;
        std::cout << "Port: " << PORT << std::endl;
        std::cout << "Type 'quit' to exit, 'status' for diagnostics, 'devices' to see active devices\n" << std::endl;

        std::thread listenerThread(&UDPChatApp::listenForMessages, this);

        // Send initial ping to announce presence
        sendPing();

        std::string input;
        while (running) {
            std::cout << "You: ";
            std::getline(std::cin, input);

            if (input == "quit" || input == "exit") {
                running = false;
                break;
            }

            if (input == "status") {
                auto now = std::chrono::steady_clock::now();
                auto timeSinceLastMsg = std::chrono::duration_cast<std::chrono::seconds>(now - lastMessageTime).count();

                std::cout << "\n=== Status ===" << std::endl;
                std::cout << "Device ID: " << deviceId << std::endl;
                std::cout << "Sockets healthy: " << (socketsHealthy ? "Yes" : "No") << std::endl;
                std::cout << "Consecutive errors: " << consecutiveErrors.load() << std::endl;
                std::cout << "Time since last message: " << timeSinceLastMsg << "s" << std::endl;
                std::cout << "Active devices: " << activeDevices.size() << std::endl;
                std::cout << "===============\n" << std::endl;
                continue;
            }

            if (input == "devices") {
                showDeviceList();
                continue;
            }

            if (input == "ping") {
                sendPing();
                std::cout << "Ping sent to discover devices...\n" << std::endl;
                continue;
            }

            if (!input.empty()) {
                sendMessage(input);
            }
        }

        if (listenerThread.joinable()) {
            listenerThread.join();
        }
    }

    void cleanup() {
        running = false;

        if (sendSock != INVALID_SOCKET) {
            closesocket(sendSock);
        }
        if (recvSock != INVALID_SOCKET) {
            closesocket(recvSock);
        }

#ifdef _WIN32
        WSACleanup();
#endif
    }
};

// Static member definitions
const int UDPChatApp::PORT;
const int UDPChatApp::BUFFER_SIZE;
const int UDPChatApp::MAX_RECENT_MESSAGES;
const int UDPChatApp::MAX_CONSECUTIVE_ERRORS;
const int UDPChatApp::HEALTH_CHECK_INTERVAL;
const int UDPChatApp::SOCKET_TIMEOUT;
const int UDPChatApp::PING_INTERVAL;
const int UDPChatApp::DEVICE_TIMEOUT;

int main(int argc, char* argv[]) {
    std::string username;

    if (argc > 1) {
        username = argv[1];
    }
    else {
        std::cout << "Enter your username: ";
        std::getline(std::cin, username);

        if (username.empty()) {
            username = "Anonymous";
        }
    }

    try {
        UDPChatApp chat(username);
        chat.run();
    }
    catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}
