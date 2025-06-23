#define _CRT_SECURE_NO_WARNINGS

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
#include <deque>
#include <algorithm>

// OpenGL and GLFW
#include <glad/glad.h>
#include <GLFW/glfw3.h>

// Dear ImGui
#include <imgui/imgui.h>
#include <imgui/imgui_impl_glfw.h>
#include <imgui/imgui_impl_opengl3.h>


#ifdef _WIN32
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "winmm.lib")
#pragma comment(lib, "opengl32.lib")
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

struct ChatMessage {
    std::string username;
    std::string content;
    std::chrono::system_clock::time_point timestamp;
    bool isSystemMessage = false;

    ChatMessage(const std::string& user, const std::string& msg, bool system = false)
        : username(user), content(msg), timestamp(std::chrono::system_clock::now()), isSystemMessage(system) {
    }
};

struct DeviceInfo {
    std::string username;
    std::string deviceId;
    std::chrono::steady_clock::time_point lastSeen;

    DeviceInfo(const std::string& user, const std::string& id)
        : username(user), deviceId(id), lastSeen(std::chrono::steady_clock::now()) {
    }
};

class UDPChatGUI {
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
    std::mutex chatMutex;
    std::atomic<int> consecutiveErrors;

    // GUI specific members
    std::deque<ChatMessage> chatMessages;
    char inputBuffer[512] = "";
    bool autoScroll = true;
    bool showDevicesWindow = false;
    bool showStatusWindow = false;
    bool showSettingsWindow = false;
    bool scrollToBottom = false;
    float chatWindowAlpha = 0.95f;
    ImVec4 userMessageColor = ImVec4(0.8f, 0.9f, 1.0f, 1.0f);
    ImVec4 otherMessageColor = ImVec4(1.0f, 1.0f, 1.0f, 1.0f);
    ImVec4 systemMessageColor = ImVec4(0.7f, 0.7f, 0.7f, 1.0f);

    static const int PORT = 12345;
    static const int BUFFER_SIZE = 1024;
    static const int MAX_RECENT_MESSAGES = 50;
    static const int MAX_CONSECUTIVE_ERRORS = 5;
    static const int HEALTH_CHECK_INTERVAL = 30;
    static const int SOCKET_TIMEOUT = 5;
    static const int PING_INTERVAL = 60;
    static const int DEVICE_TIMEOUT = 180;
    static const int MAX_CHAT_MESSAGES = 1000;

    std::string generateDeviceId() {
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> dis(100000, 999999);
        return std::to_string(dis(gen));
    }

    void addChatMessage(const std::string& user, const std::string& message, bool isSystem = false) {
        std::lock_guard<std::mutex> lock(chatMutex);
        chatMessages.emplace_back(user, message, isSystem);

        if (chatMessages.size() > MAX_CHAT_MESSAGES) {
            chatMessages.pop_front();
        }

        scrollToBottom = true;
    }

    void logError(const std::string& message) {
        addChatMessage("SYSTEM", "ERROR: " + message, true);
    }

    void logInfo(const std::string& message) {
        addChatMessage("SYSTEM", "INFO: " + message, true);
    }

    bool testSocketHealth() {
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

        if (sendSock != INVALID_SOCKET) {
            closesocket(sendSock);
        }
        if (recvSock != INVALID_SOCKET) {
            closesocket(recvSock);
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(500));

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
        if (message.find("HEALTH_CHECK_") == 0) {
            return true;
        }

        auto now = std::chrono::steady_clock::now();

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
        if (!socketsHealthy) return;

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
        if (!socketsHealthy) return;

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
        if (senderDeviceId == deviceId) return;

        {
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

        sendPong(senderDeviceId);
    }

    void handlePongMessage(const std::string& senderDeviceId, const std::string& senderUsername, const std::string& targetDeviceId) {
        if (targetDeviceId != deviceId || senderDeviceId == deviceId) return;

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
    UDPChatGUI(const std::string& user) : username(user), running(true), socketsHealthy(true),
        sendSock(INVALID_SOCKET), recvSock(INVALID_SOCKET), consecutiveErrors(0) {
        deviceId = generateDeviceId();
        lastCleanup = std::chrono::steady_clock::now();
        lastMessageTime = std::chrono::steady_clock::now();
        lastHealthCheck = std::chrono::steady_clock::now();
        lastPingTime = std::chrono::steady_clock::now();
        lastDeviceCleanup = std::chrono::steady_clock::now();

#ifndef _WIN32
        signal(SIGPIPE, SIG_IGN);
#endif

        initializeSockets();
        addChatMessage("SYSTEM", "Chat initialized. Welcome " + username + "!", true);
    }

    ~UDPChatGUI() {
        cleanup();
    }

    void initializeSockets() {
#ifdef _WIN32
        WSADATA wsaData;
        if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
            throw std::runtime_error("WSAStartup failed");
        }
#endif

        sendSock = socket(AF_INET, SOCK_DGRAM, 0);
        recvSock = socket(AF_INET, SOCK_DGRAM, 0);

        if (sendSock == INVALID_SOCKET || recvSock == INVALID_SOCKET) {
            throw std::runtime_error("Socket creation failed");
        }

#ifdef _WIN32
        DWORD timeout = SOCKET_TIMEOUT * 1000;
        setsockopt(sendSock, SOL_SOCKET, SO_SNDTIMEO, (char*)&timeout, sizeof(timeout));
        setsockopt(recvSock, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(timeout));
#else
        struct timeval tv;
        tv.tv_sec = SOCKET_TIMEOUT;
        tv.tv_usec = 0;
        setsockopt(sendSock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
        setsockopt(recvSock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
#endif

        int broadcast = 1;
        if (setsockopt(sendSock, SOL_SOCKET, SO_BROADCAST,
            reinterpret_cast<const char*>(&broadcast), sizeof(broadcast)) < 0) {
            throw std::runtime_error("Error enabling broadcast on send socket");
        }

        int reuse = 1;
        setsockopt(recvSock, SOL_SOCKET, SO_REUSEADDR,
            reinterpret_cast<const char*>(&reuse), sizeof(reuse));

#ifndef _WIN32
        int reusePort = 1;
        setsockopt(recvSock, SOL_SOCKET, SO_REUSEPORT, &reusePort, sizeof(reusePort));
        setsockopt(recvSock, SOL_SOCKET, SO_BROADCAST,
            reinterpret_cast<const char*>(&broadcast), sizeof(broadcast));
#endif

        int bufSize = 65536;
        setsockopt(sendSock, SOL_SOCKET, SO_SNDBUF, reinterpret_cast<const char*>(&bufSize), sizeof(bufSize));
        setsockopt(recvSock, SOL_SOCKET, SO_RCVBUF, reinterpret_cast<const char*>(&bufSize), sizeof(bufSize));

        memset(&broadcastAddr, 0, sizeof(broadcastAddr));
        broadcastAddr.sin_family = AF_INET;
        broadcastAddr.sin_port = htons(PORT);
        broadcastAddr.sin_addr.s_addr = INADDR_BROADCAST;

        memset(&listenAddr, 0, sizeof(listenAddr));
        listenAddr.sin_family = AF_INET;
        listenAddr.sin_port = htons(PORT);
        listenAddr.sin_addr.s_addr = INADDR_ANY;

        if (bind(recvSock, reinterpret_cast<struct sockaddr*>(&listenAddr), sizeof(listenAddr)) < 0) {
#ifdef _WIN32
            throw std::runtime_error("Bind failed. Error: " + std::to_string(WSAGetLastError()));
#else
            throw std::runtime_error("Bind failed: " + std::string(strerror(errno)));
#endif
        }
    }

    void listenForMessages() {
        char buffer[BUFFER_SIZE];
        struct sockaddr_in senderAddr;
        socklen_t senderLen = sizeof(senderAddr);

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

                if (message.find("PING:") == 0) {
                    auto parts = parseMessage(message, ':');
                    if (parts.size() >= 3) {
                        handlePingMessage(parts[1], parts[2]);
                    }
                    continue;
                }

                if (message.find("PONG:") == 0) {
                    auto parts = parseMessage(message, ':');
                    if (parts.size() >= 4) {
                        handlePongMessage(parts[1], parts[2], parts[3]);
                    }
                    continue;
                }

                if (message.find(username + ":") != 0 && !isDuplicateMessage(message)) {
                    size_t colonPos = message.find(": ");
                    if (colonPos != std::string::npos) {
                        std::string msgUsername = message.substr(0, colonPos);
                        std::string msgContent = message.substr(colonPos + 2);
                        addChatMessage(msgUsername, msgContent);
                    }
                    else {
                        addChatMessage("Unknown", message);
                    }

                    lastMessageTime = std::chrono::steady_clock::now();
                    consecutiveErrors = 0;
                }
            }

            auto now = std::chrono::steady_clock::now();

            if (now - lastHealthCheck > std::chrono::seconds(HEALTH_CHECK_INTERVAL)) {
                if (!testSocketHealth()) {
                    socketsHealthy = false;
                    resetSockets();
                }
                lastHealthCheck = now;
            }

            if (now - lastPingTime > std::chrono::seconds(PING_INTERVAL)) {
                sendPing();
                lastPingTime = now;
            }

            if (now - lastDeviceCleanup > std::chrono::seconds(30)) {
                cleanupOldDevices();
                lastDeviceCleanup = now;
            }

            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
    }

    void sendMessage(const std::string& message) {
        if (!socketsHealthy || message.empty()) return;

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

                std::this_thread::sleep_for(std::chrono::milliseconds(2));
            }
        }

        if (messageSent) {
            addChatMessage(username, message);
        }
        else {
            logError("Failed to send message");
        }
    }

    void renderChatWindow() {
        // Get the main viewport
        ImGuiViewport* viewport = ImGui::GetMainViewport();

        // Set window to cover the entire viewport
        ImGui::SetNextWindowPos(viewport->WorkPos);
        ImGui::SetNextWindowSize(viewport->WorkSize);
        ImGui::SetNextWindowBgAlpha(chatWindowAlpha);

        // Window flags to make it fullscreen and non-movable
        ImGuiWindowFlags window_flags = ImGuiWindowFlags_NoTitleBar |
            ImGuiWindowFlags_NoResize |
            ImGuiWindowFlags_NoMove |
            ImGuiWindowFlags_NoCollapse |
            ImGuiWindowFlags_MenuBar;  // Keep menu bar

        if (ImGui::Begin("UDP Chat", nullptr, window_flags)) {
            // Render menu bar first
            renderMenuBar();

            // Chat messages area - leave space for input at bottom
            float input_height = ImGui::GetFrameHeightWithSpacing() * 2;
            ImGui::BeginChild("ChatMessages", ImVec2(0, -input_height), true);

            {
                std::lock_guard<std::mutex> lock(chatMutex);
                for (const auto& msg : chatMessages) {
                    ImVec4 color = otherMessageColor;
                    if (msg.username == username) {
                        color = userMessageColor;
                    }
                    else if (msg.isSystemMessage) {
                        color = systemMessageColor;
                    }

                    ImGui::PushStyleColor(ImGuiCol_Text, color);

                    auto time = std::chrono::system_clock::to_time_t(msg.timestamp);
                    struct tm* timeinfo = localtime(&time);
                    char timeStr[20];
                    strftime(timeStr, sizeof(timeStr), "%H:%M:%S", timeinfo);

                    if (msg.isSystemMessage) {
                        ImGui::Text("[%s] %s", timeStr, msg.content.c_str());
                    }
                    else {
                        ImGui::Text("[%s] %s: %s", timeStr, msg.username.c_str(), msg.content.c_str());
                    }

                    ImGui::PopStyleColor();
                }
            }

            if (scrollToBottom) {
                ImGui::SetScrollHereY(1.0f);
                scrollToBottom = false;
            }

            ImGui::EndChild();

            // Input area
            ImGui::Separator();

            // Make input field take most of the width, leaving space for Send button
            float send_button_width = 60.0f;
            float input_width = ImGui::GetContentRegionAvail().x - send_button_width - ImGui::GetStyle().ItemSpacing.x;

            ImGui::SetNextItemWidth(input_width);
            if (ImGui::InputTextWithHint("##input", "Type your message...", inputBuffer, sizeof(inputBuffer),
                ImGuiInputTextFlags_EnterReturnsTrue)) {
                sendMessage(std::string(inputBuffer));
                memset(inputBuffer, 0, sizeof(inputBuffer));
                ImGui::SetKeyboardFocusHere(-1);
            }

            ImGui::SameLine();
            if (ImGui::Button("Send", ImVec2(send_button_width, 0))) {
                sendMessage(std::string(inputBuffer));
                memset(inputBuffer, 0, sizeof(inputBuffer));
            }
        }
        ImGui::End();
    }

    void renderDevicesWindow() {
        if (!showDevicesWindow) return;

        if (ImGui::Begin("Active Devices", &showDevicesWindow)) {
            ImGui::Text("Your Device ID: %s", deviceId.c_str());
            ImGui::Text("Your Username: %s", username.c_str());
            ImGui::Separator();

            std::lock_guard<std::mutex> lock(deviceMutex);
            auto now = std::chrono::steady_clock::now();

            if (activeDevices.empty()) {
                ImGui::Text("No other devices detected");
            }
            else {
                if (ImGui::BeginTable("DevicesTable", 3, ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg)) {
                    ImGui::TableSetupColumn("Device ID");
                    ImGui::TableSetupColumn("Username");
                    ImGui::TableSetupColumn("Last Seen");
                    ImGui::TableHeadersRow();

                    for (const auto& pair : activeDevices) {
                        const auto& device = pair.second;
                        auto secondsAgo = std::chrono::duration_cast<std::chrono::seconds>(now - device.lastSeen).count();

                        ImGui::TableNextRow();
                        ImGui::TableNextColumn();
                        ImGui::Text("%s", device.deviceId.c_str());
                        ImGui::TableNextColumn();
                        ImGui::Text("%s", device.username.c_str());
                        ImGui::TableNextColumn();
                        ImGui::Text("%llds ago", secondsAgo);
                    }
                    ImGui::EndTable();
                }
            }

            if (ImGui::Button("Send Ping")) {
                sendPing();
            }
        }
        ImGui::End();
    }

    void renderStatusWindow() {
        if (!showStatusWindow) return;

        if (ImGui::Begin("Status", &showStatusWindow)) {
            auto now = std::chrono::steady_clock::now();
            auto timeSinceLastMsg = std::chrono::duration_cast<std::chrono::seconds>(now - lastMessageTime).count();

            ImGui::Text("Device ID: %s", deviceId.c_str());
            ImGui::Text("Username: %s", username.c_str());
            ImGui::Text("Port: %d", PORT);
            ImGui::Text("Sockets Healthy: %s", socketsHealthy ? "Yes" : "No");
            ImGui::Text("Consecutive Errors: %d", consecutiveErrors.load());
            ImGui::Text("Time Since Last Message: %llds", timeSinceLastMsg);

            {
                std::lock_guard<std::mutex> lock(deviceMutex);
                ImGui::Text("Active Devices: %zu", activeDevices.size());
            }

            {
                std::lock_guard<std::mutex> lock(chatMutex);
                ImGui::Text("Chat Messages: %zu", chatMessages.size());
            }

            if (ImGui::Button("Reset Sockets")) {
                socketsHealthy = false;
                std::thread([this]() { resetSockets(); }).detach();
            }
        }
        ImGui::End();
    }

    void renderSettingsWindow() {
        if (!showSettingsWindow) return;

        if (ImGui::Begin("Settings", &showSettingsWindow)) {
            ImGui::SliderFloat("Window Transparency", &chatWindowAlpha, 0.3f, 1.0f);

            ImGui::ColorEdit3("Your Messages", (float*)&userMessageColor);
            ImGui::ColorEdit3("Other Messages", (float*)&otherMessageColor);
            ImGui::ColorEdit3("System Messages", (float*)&systemMessageColor);

            ImGui::Checkbox("Auto Scroll", &autoScroll);

            if (ImGui::Button("Clear Chat")) {
                std::lock_guard<std::mutex> lock(chatMutex);
                chatMessages.clear();
            }
        }
        ImGui::End();
    }

    void renderMenuBar() {
        if (ImGui::BeginMenuBar()) {
            if (ImGui::BeginMenu("View")) {
                ImGui::MenuItem("Devices", nullptr, &showDevicesWindow);
                ImGui::MenuItem("Status", nullptr, &showStatusWindow);
                ImGui::MenuItem("Settings", nullptr, &showSettingsWindow);
                ImGui::EndMenu();
            }

            if (ImGui::BeginMenu("Actions")) {
                if (ImGui::MenuItem("Send Ping")) {
                    sendPing();
                }
                if (ImGui::MenuItem("Clear Chat")) {
                    std::lock_guard<std::mutex> lock(chatMutex);
                    chatMessages.clear();
                }
                ImGui::EndMenu();
            }

            ImGui::EndMenuBar();
        }
    }

    void render() {
        /*if (ImGui::BeginMainMenuBar()) {
            renderMenuBar();
            ImGui::EndMainMenuBar();
        }*/

        renderChatWindow();
        renderDevicesWindow();
        renderStatusWindow();
        renderSettingsWindow();
    }

    bool isRunning() const { return running; }
    void stop() { running = false; }

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

// Global variables for GLFW callbacks
static UDPChatGUI* g_chatInstance = nullptr;

void glfw_error_callback(int error, const char* description) {
    fprintf(stderr, "GLFW Error %d: %s\n", error, description);
}

int main(int argc, char* argv[]) {
    std::string username = "User";

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

    // Setup GLFW
    glfwSetErrorCallback(glfw_error_callback);
    if (!glfwInit()) {
        return -1;
    }

    // GL 3.0 + GLSL 130
    const char* glsl_version = "#version 130";
    glfwWindowHint(GLFW_CONTEXT_VERSION_MAJOR, 3);
    glfwWindowHint(GLFW_CONTEXT_VERSION_MINOR, 0);

    // Create window with graphics context
    GLFWwindow* window = glfwCreateWindow(800, 600, "UDP Chat GUI", nullptr, nullptr);
    if (window == nullptr) {
        glfwTerminate();
        return -1;
    }

    glfwMakeContextCurrent(window);
    glfwSwapInterval(1); // Enable vsync

    if (!gladLoadGLLoader((GLADloadproc)glfwGetProcAddress))
    {
        fprintf(stderr, "Failed to initialize OpenGL loader!\n");
        glfwTerminate();
        return -1;
    }

    // Setup Dear ImGui context
    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImGuiIO& io = ImGui::GetIO(); (void)io;
    io.ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard;
    //io.ConfigFlags |= ImGuiConfigFlags_DockingEnable;

    // Setup Dear ImGui style
    ImGui::StyleColorsDark();

    // Setup Platform/Renderer backends
    ImGui_ImplGlfw_InitForOpenGL(window, true);
    ImGui_ImplOpenGL3_Init(glsl_version);

    // Initialize chat system
    try {
        UDPChatGUI chat(username);
        g_chatInstance = &chat;

        // Start message listening thread
        std::thread listenThread(&UDPChatGUI::listenForMessages, &chat);

        // Main loop
        while (!glfwWindowShouldClose(window) && chat.isRunning()) {
            glfwPollEvents();

            // Start the Dear ImGui frame
            ImGui_ImplOpenGL3_NewFrame();
            ImGui_ImplGlfw_NewFrame();
            ImGui::NewFrame();

            // Render chat interface
            chat.render();

            // Rendering
            ImGui::Render();
            int display_w, display_h;
            glfwGetFramebufferSize(window, &display_w, &display_h);
            glViewport(0, 0, display_w, display_h);
            glClearColor(0.45f, 0.55f, 0.60f, 1.00f);
            glClear(GL_COLOR_BUFFER_BIT);
            ImGui_ImplOpenGL3_RenderDrawData(ImGui::GetDrawData());

            glfwSwapBuffers(window);
        }

        // Cleanup
        chat.stop();
        if (listenThread.joinable()) {
            listenThread.join();
        }

    }
    catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;

        // Show error in a simple GUI
        while (!glfwWindowShouldClose(window)) {
            glfwPollEvents();

            ImGui_ImplOpenGL3_NewFrame();
            ImGui_ImplGlfw_NewFrame();
            ImGui::NewFrame();

            ImGui::SetNextWindowSize(ImVec2(400, 200), ImGuiCond_Always);
            ImGui::SetNextWindowPos(ImVec2(200, 200), ImGuiCond_Always);

            if (ImGui::Begin("Error", nullptr, ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoMove)) {
                ImGui::Text("Failed to initialize UDP Chat:");
                ImGui::TextWrapped("%s", e.what());
                ImGui::Separator();
                ImGui::Text("This might be due to:");
                ImGui::BulletText("Port %d already in use", 12345);
                ImGui::BulletText("Network permissions required");
                ImGui::BulletText("Firewall blocking UDP traffic");
                ImGui::Separator();
                if (ImGui::Button("Close")) {
                    glfwSetWindowShouldClose(window, true);
                }
            }
            ImGui::End();

            ImGui::Render();
            int display_w, display_h;
            glfwGetFramebufferSize(window, &display_w, &display_h);
            glViewport(0, 0, display_w, display_h);
            glClearColor(0.45f, 0.55f, 0.60f, 1.00f);
            glClear(GL_COLOR_BUFFER_BIT);
            ImGui_ImplOpenGL3_RenderDrawData(ImGui::GetDrawData());

            glfwSwapBuffers(window);
        }
    }

    // Cleanup ImGui
    ImGui_ImplOpenGL3_Shutdown();
    ImGui_ImplGlfw_Shutdown();
    ImGui::DestroyContext();

    // Cleanup GLFW
    glfwDestroyWindow(window);
    glfwTerminate();

    return 0;
}
