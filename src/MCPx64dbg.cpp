#define _WINSOCK_DEPRECATED_NO_WARNINGS
#define WIN32_LEAN_AND_MEAN

#include <Windows.h>
#include "bridgemain.h"
#include "_plugins.h"
#include "_scriptapi_module.h"
#include "_scriptapi_memory.h"
#include "_scriptapi_register.h"
#include "_scriptapi_debug.h"
#include "_scriptapi_assembler.h"
#include "_scriptapi_comment.h"
#include "_scriptapi_label.h"
#include "_scriptapi_bookmark.h"
#include "_scriptapi_function.h"
#include "_scriptapi_argument.h"
#include "_scriptapi_symbol.h"
#include "_scriptapi_stack.h"
#include "_scriptapi_pattern.h"
#include "_scriptapi_flag.h"
#include "_scriptapi_gui.h"
#include "_scriptapi_misc.h"
#include <iomanip>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <string>
#include <vector>
#include <unordered_map>
#include <sstream>
#include <mutex>
#include <algorithm>
#include <cctype>
#include <cstdarg>
#include <cstdio>
#include <cstring>
#include <deque>

#pragma comment(lib, "ws2_32.lib")

#ifdef _WIN64
#define FMT_DUINT_HEX "0x%llx"
#define FMT_DUINT_DEC "%llu"
#define DUINT_CAST_PRINTF(v) (unsigned long long)(v)
#define DUSIZE_CAST_PRINTF(v) (unsigned long long)(v)
#define REG_IP Script::Register::RIP
#else
#define FMT_DUINT_HEX "0x%08X"
#define FMT_DUINT_DEC "%u"
#define DUINT_CAST_PRINTF(v) (unsigned int)(v)
#define DUSIZE_CAST_PRINTF(v) (unsigned int)(v)
#define REG_IP Script::Register::EIP
#endif

#define PLUGIN_NAME "x64dbg HTTP Server"
#define PLUGIN_VERSION 1
#define DEFAULT_PORT 8888
#define MAX_REQUEST_SIZE 8192

int g_pluginHandle;
HANDLE g_httpServerThread = NULL;
bool g_httpServerRunning = false;
int g_httpPort = DEFAULT_PORT;
std::string g_httpHost = "127.0.0.1";
std::mutex g_httpMutex;
SOCKET g_serverSocket = INVALID_SOCKET;
std::mutex g_eventLogMutex;

struct EventLogEntry {
    unsigned long long seq;
    unsigned long long tickMs;
    std::string kind;
    std::string text;
};

std::deque<EventLogEntry> g_eventLog;
unsigned long long g_eventLogSeq = 0;
const size_t MAX_EVENT_LOG_ENTRIES = 4096;
std::mutex g_breakpointContextMutex;

struct BreakpointContextExpression {
    std::string label;
    std::string expression;
};

std::vector<BreakpointContextExpression> g_breakpointContextExpressions;

enum class DebugAction {
    Run,
    Pause,
    Stop,
    StepIn,
    StepOver,
    StepOut
};

HANDLE g_debugActionThread = NULL;
HANDLE g_debugActionEvent = NULL;
bool g_debugActionRunning = false;
std::mutex g_debugActionMutex;
std::deque<DebugAction> g_debugActionQueue;

bool startHttpServer();
void stopHttpServer();
bool startDebugActionWorker();
void stopDebugActionWorker();
bool queueDebugAction(DebugAction action);
bool registerPluginCallbacks();
void unregisterPluginCallbacks();
DWORD WINAPI DebugActionThread(LPVOID lpParam);
DWORD WINAPI HttpServerThread(LPVOID lpParam);
std::string readHttpRequest(SOCKET clientSocket);
void sendHttpResponse(SOCKET clientSocket, int statusCode, const std::string& contentType, const std::string& responseBody);
void parseHttpRequest(const std::string& request, std::string& method, std::string& path, std::string& query, std::string& body);
std::unordered_map<std::string, std::string> parseQueryParams(const std::string& query);
std::string urlDecode(const std::string& str);
std::string escapeJsonString(const char* str);
static void trimParam(std::string& s);
bool resolveListenAddress(const std::string& host, sockaddr_in& serverAddr);
std::string debugActionName(DebugAction action);
std::string breakpointTypeName(BPXTYPE type);
bool tryParseHexAddress(const std::string& value, duint& addr);
bool tryParseExpressionValue(const char* expression, duint& value);
void appendExpressionIfAvailable(std::ostringstream& ss, const char* label, const char* expression);
std::vector<BreakpointContextExpression> getBreakpointContextExpressions();
void setBreakpointContextExpressions(const std::vector<BreakpointContextExpression>& expressions);
std::vector<BreakpointContextExpression> parseBreakpointContextSpec(const std::string& spec);
bool getBreakpointByAddress(duint addr, BRIDGEBP& outBp);
std::string formatBreakpointAddress(duint addr);
bool applyBreakpointSilentFlag(duint addr, bool silent, std::string& attemptsSummary, bool& finalSilent);
void appendEventLog(const std::string& kind, const std::string& text);
std::string trimForLog(const std::string& text);
void clearEventLog();
size_t eventLogSize();
std::string readOutputDebugString(const OUTPUT_DEBUG_STRING_INFO* info);
void cbBreakpointEvent(CBTYPE bType, void* callbackInfo);
void cbOutputDebugStringEvent(CBTYPE bType, void* callbackInfo);

bool cbEnableHttpServer(int argc, char* argv[]);
bool cbSetHttpPort(int argc, char* argv[]);
bool cbSetHttpHost(int argc, char* argv[]);
void registerCommands();

bool pluginInit(PLUG_INITSTRUCT* initStruct) {
    initStruct->pluginVersion = PLUGIN_VERSION;
    initStruct->sdkVersion = PLUG_SDKVERSION;
    strncpy_s(initStruct->pluginName, PLUGIN_NAME, _TRUNCATE);
    g_pluginHandle = initStruct->pluginHandle;
    
    _plugin_logputs("x64dbg HTTP Server plugin loading...");
    registerCommands();
    registerPluginCallbacks();
    if (!startDebugActionWorker()) {
        _plugin_logputs("Failed to start debug action worker!");
    }
    if (startHttpServer()) {
        _plugin_logprintf("x64dbg HTTP Server started on %s:%d\n", g_httpHost.c_str(), g_httpPort);
    } else {
        _plugin_logputs("Failed to start HTTP server!");
    }
    
    _plugin_logputs("x64dbg HTTP Server plugin loaded!");
    return true;
}

void pluginStop() {
    _plugin_logputs("Stopping x64dbg HTTP Server...");
    unregisterPluginCallbacks();
    stopHttpServer();
    stopDebugActionWorker();
    _plugin_logputs("x64dbg HTTP Server stopped.");
}

bool pluginSetup() {
    return true;
}

extern "C" __declspec(dllexport) bool pluginit(PLUG_INITSTRUCT* initStruct) {
    return pluginInit(initStruct);
}

extern "C" __declspec(dllexport) void plugstop() {
    pluginStop();
}

extern "C" __declspec(dllexport) void plugsetup(PLUG_SETUPSTRUCT* setupStruct) {
    pluginSetup();
}

bool startHttpServer() {
    {
        std::lock_guard<std::mutex> lock(g_httpMutex);
        if (g_httpServerRunning) {
            return true;
        }
        g_httpServerRunning = true;
    }
    g_httpServerThread = CreateThread(NULL, 0, HttpServerThread, NULL, 0, NULL);
    if (g_httpServerThread == NULL) {
        _plugin_logputs("Failed to create HTTP server thread");
        std::lock_guard<std::mutex> lock(g_httpMutex);
        g_httpServerRunning = false;
        return false;
    }
    return true;
}

void stopHttpServer() {
    HANDLE thread = NULL;
    {
        std::lock_guard<std::mutex> lock(g_httpMutex);
        g_httpServerRunning = false;
        if (g_serverSocket != INVALID_SOCKET) {
            closesocket(g_serverSocket);
            g_serverSocket = INVALID_SOCKET;
        }
        thread = g_httpServerThread;
        g_httpServerThread = NULL;
    }
    if (thread != NULL) {
        WaitForSingleObject(thread, 1000);
        CloseHandle(thread);
    }
}

std::string debugActionName(DebugAction action) {
    switch (action) {
        case DebugAction::Run: return "Run";
        case DebugAction::Pause: return "Pause";
        case DebugAction::Stop: return "Stop";
        case DebugAction::StepIn: return "StepIn";
        case DebugAction::StepOver: return "StepOver";
        case DebugAction::StepOut: return "StepOut";
    }
    return "Unknown";
}

std::string breakpointTypeName(BPXTYPE type) {
    switch (type) {
        case bp_normal: return "normal";
        case bp_hardware: return "hardware";
        case bp_memory: return "memory";
        case bp_dll: return "dll";
        case bp_exception: return "exception";
        default: return "unknown";
    }
}

bool tryParseHexAddress(const std::string& value, duint& addr) {
    try {
        if (value.size() > 2 && value[0] == '0' && (value[1] == 'x' || value[1] == 'X')) {
            addr = std::stoull(value.substr(2), nullptr, 16);
        } else {
            addr = std::stoull(value, nullptr, 16);
        }
        return true;
    } catch (const std::exception&) {
        addr = 0;
        return false;
    }
}

bool tryParseExpressionValue(const char* expression, duint& value) {
    if (!expression || !*expression) {
        value = 0;
        return false;
    }
    return Script::Misc::ParseExpression(expression, &value);
}

void appendExpressionIfAvailable(std::ostringstream& ss, const char* label, const char* expression) {
    duint value = 0;
    if (!tryParseExpressionValue(expression, value)) {
        return;
    }
    ss << " " << label << "=" << formatBreakpointAddress(value);
}

std::vector<BreakpointContextExpression> getBreakpointContextExpressions() {
    std::lock_guard<std::mutex> lock(g_breakpointContextMutex);
    return g_breakpointContextExpressions;
}

void setBreakpointContextExpressions(const std::vector<BreakpointContextExpression>& expressions) {
    std::lock_guard<std::mutex> lock(g_breakpointContextMutex);
    g_breakpointContextExpressions = expressions;
}

std::vector<BreakpointContextExpression> parseBreakpointContextSpec(const std::string& spec) {
    std::vector<BreakpointContextExpression> expressions;
    std::string normalized = spec;
    std::replace(normalized.begin(), normalized.end(), ';', '\n');

    std::istringstream input(normalized);
    std::string line;
    while (std::getline(input, line)) {
        trimParam(line);
        if (line.empty()) {
            continue;
        }
        size_t equalPos = line.find('=');
        if (equalPos == std::string::npos) {
            continue;
        }
        std::string label = line.substr(0, equalPos);
        std::string expression = line.substr(equalPos + 1);
        trimParam(label);
        trimParam(expression);
        if (label.empty() || expression.empty()) {
            continue;
        }
        expressions.push_back({label, expression});
    }
    return expressions;
}

bool getBreakpointByAddress(duint addr, BRIDGEBP& outBp) {
    BPMAP bpmap;
    memset(&bpmap, 0, sizeof(bpmap));
    int count = DbgGetBpList(bp_normal, &bpmap);
    bool found = false;

    if (count > 0 && bpmap.bp != nullptr) {
        for (int i = 0; i < bpmap.count; i++) {
            if (bpmap.bp[i].addr == addr) {
                outBp = bpmap.bp[i];
                found = true;
                break;
            }
        }
        BridgeFree(bpmap.bp);
    }
    return found;
}

std::string formatBreakpointAddress(duint addr) {
    std::ostringstream ss;
    ss << "0x" << std::hex << std::uppercase << DUINT_CAST_PRINTF(addr);
    return ss.str();
}

bool applyBreakpointSilentFlag(duint addr, bool silent, std::string& attemptsSummary, bool& finalSilent) {
    std::vector<std::string> commands;
    const std::string addrText = formatBreakpointAddress(addr);
    if (silent) {
        commands.push_back("SetBreakpointSilent " + addrText + ",1");
        commands.push_back("bpsilent " + addrText + ",1");
    } else {
        commands.push_back("SetBreakpointSilent " + addrText + ",0");
        commands.push_back("SetBreakpointSilent " + addrText);
        commands.push_back("bpsilent " + addrText + ",0");
    }

    std::ostringstream attempts;
    bool applied = false;
    finalSilent = false;

    for (size_t i = 0; i < commands.size(); i++) {
        const bool execOk = DbgCmdExecDirect(commands[i].c_str());
        BRIDGEBP bp;
        bool found = getBreakpointByAddress(addr, bp);
        bool currentSilent = found ? bp.silent : false;
        if (i > 0) {
            attempts << " | ";
        }
        attempts << commands[i] << " -> exec=" << (execOk ? "1" : "0");
        if (found) {
            attempts << ",silent=" << (currentSilent ? "1" : "0");
            finalSilent = currentSilent;
        } else {
            attempts << ",missing=1";
        }
        if (execOk && found && currentSilent == silent) {
            applied = true;
            break;
        }
    }

    attemptsSummary = attempts.str();
    return applied;
}

std::string trimForLog(const std::string& text) {
    size_t start = 0;
    while (start < text.size() && (text[start] == '\r' || text[start] == '\n')) {
        start++;
    }
    size_t end = text.size();
    while (end > start && (text[end - 1] == '\r' || text[end - 1] == '\n')) {
        end--;
    }
    std::string trimmed = text.substr(start, end - start);
    if (trimmed.size() > 1024) {
        trimmed.resize(1024);
        trimmed += "...";
    }
    return trimmed;
}

void appendEventLog(const std::string& kind, const std::string& text) {
    std::lock_guard<std::mutex> lock(g_eventLogMutex);
    EventLogEntry entry;
    entry.seq = ++g_eventLogSeq;
    entry.tickMs = GetTickCount64();
    entry.kind = kind;
    entry.text = trimForLog(text);
    g_eventLog.push_back(entry);
    while (g_eventLog.size() > MAX_EVENT_LOG_ENTRIES) {
        g_eventLog.pop_front();
    }
}

void clearEventLog() {
    std::lock_guard<std::mutex> lock(g_eventLogMutex);
    g_eventLog.clear();
}

size_t eventLogSize() {
    std::lock_guard<std::mutex> lock(g_eventLogMutex);
    return g_eventLog.size();
}

std::string readOutputDebugString(const OUTPUT_DEBUG_STRING_INFO* info) {
    if (!info || !info->lpDebugStringData || info->nDebugStringLength == 0) {
        return "";
    }

    duint addr = (duint)info->lpDebugStringData;
    duint sizeRead = 0;
    size_t charCount = static_cast<size_t>(info->nDebugStringLength);
    if (charCount > 4096) {
        charCount = 4096;
    }

    if (info->fUnicode) {
        std::vector<wchar_t> buffer(charCount + 1, L'\0');
        if (!Script::Memory::Read(addr, buffer.data(), charCount * sizeof(wchar_t), &sizeRead) || sizeRead == 0) {
            return "";
        }
        buffer[sizeRead / sizeof(wchar_t)] = L'\0';
        int utf8Len = WideCharToMultiByte(CP_UTF8, 0, buffer.data(), -1, NULL, 0, NULL, NULL);
        if (utf8Len <= 1) {
            return "";
        }
        std::string utf8(static_cast<size_t>(utf8Len), '\0');
        WideCharToMultiByte(CP_UTF8, 0, buffer.data(), -1, &utf8[0], utf8Len, NULL, NULL);
        if (!utf8.empty() && utf8.back() == '\0') {
            utf8.pop_back();
        }
        return utf8;
    }

    std::vector<char> buffer(charCount + 1, '\0');
    if (!Script::Memory::Read(addr, buffer.data(), charCount, &sizeRead) || sizeRead == 0) {
        return "";
    }
    buffer[sizeRead] = '\0';
    return std::string(buffer.data());
}

void cbBreakpointEvent(CBTYPE bType, void* callbackInfo) {
    auto* info = static_cast<PLUG_CB_BREAKPOINT*>(callbackInfo);
    if (!info || !info->breakpoint) {
        appendEventLog("breakpoint", "callback received without breakpoint metadata");
        return;
    }

    const BRIDGEBP& bp = *info->breakpoint;
    std::ostringstream ss;
    ss << "addr=0x" << std::hex << bp.addr
       << " type=" << breakpointTypeName(bp.type)
       << " enabled=" << (bp.enabled ? "1" : "0")
       << " singleshoot=" << (bp.singleshoot ? "1" : "0")
       << " active=" << (bp.active ? "1" : "0")
       << " silent=" << (bp.silent ? "1" : "0")
       << " fastResume=" << (bp.fastResume ? "1" : "0")
       << " hitCount=" << std::dec << bp.hitCount;
    if (bp.mod[0] != '\0') {
        ss << " module=" << bp.mod;
    }
    if (bp.name[0] != '\0') {
        ss << " name=" << bp.name;
    }
    if (bp.breakCondition[0] != '\0') {
        ss << " breakCondition=" << bp.breakCondition;
    }
    if (bp.logText[0] != '\0') {
        ss << " logText=" << bp.logText;
    }
    if (bp.commandText[0] != '\0') {
        ss << " commandText=" << bp.commandText;
    }
    const auto expressions = getBreakpointContextExpressions();
    for (const auto& item : expressions) {
        appendExpressionIfAvailable(ss, item.label.c_str(), item.expression.c_str());
    }
    appendEventLog("breakpoint", ss.str());
}

void cbOutputDebugStringEvent(CBTYPE bType, void* callbackInfo) {
    auto* info = static_cast<PLUG_CB_OUTPUTDEBUGSTRING*>(callbackInfo);
    if (!info || !info->DebugString) {
        appendEventLog("output_debug_string", "callback received without debug-string metadata");
        return;
    }

    std::string text = readOutputDebugString(info->DebugString);
    if (text.empty()) {
        appendEventLog("output_debug_string", "received empty debug string");
        return;
    }
    appendEventLog("output_debug_string", text);
}

bool registerPluginCallbacks() {
    bool ok = true;
    _plugin_registercallback(g_pluginHandle, CB_BREAKPOINT, cbBreakpointEvent);
    _plugin_registercallback(g_pluginHandle, CB_OUTPUTDEBUGSTRING, cbOutputDebugStringEvent);
    appendEventLog("plugin", "registered CB_BREAKPOINT and CB_OUTPUTDEBUGSTRING callbacks");
    return ok;
}

void unregisterPluginCallbacks() {
    _plugin_unregistercallback(g_pluginHandle, CB_BREAKPOINT);
    _plugin_unregistercallback(g_pluginHandle, CB_OUTPUTDEBUGSTRING);
    appendEventLog("plugin", "unregistered CB_BREAKPOINT and CB_OUTPUTDEBUGSTRING callbacks");
}

bool startDebugActionWorker() {
    std::lock_guard<std::mutex> lock(g_debugActionMutex);
    if (g_debugActionRunning) {
        return true;
    }
    g_debugActionEvent = CreateEvent(NULL, FALSE, FALSE, NULL);
    if (g_debugActionEvent == NULL) {
        _plugin_logputs("Failed to create debug action event");
        return false;
    }
    g_debugActionRunning = true;
    g_debugActionThread = CreateThread(NULL, 0, DebugActionThread, NULL, 0, NULL);
    if (g_debugActionThread == NULL) {
        _plugin_logputs("Failed to create debug action thread");
        CloseHandle(g_debugActionEvent);
        g_debugActionEvent = NULL;
        g_debugActionRunning = false;
        return false;
    }
    return true;
}

void stopDebugActionWorker() {
    HANDLE thread = NULL;
    HANDLE event = NULL;
    {
        std::lock_guard<std::mutex> lock(g_debugActionMutex);
        g_debugActionRunning = false;
        thread = g_debugActionThread;
        event = g_debugActionEvent;
        if (event != NULL) {
            SetEvent(event);
        }
    }
    if (thread != NULL) {
        WaitForSingleObject(thread, 1000);
        CloseHandle(thread);
    }
    if (event != NULL) {
        CloseHandle(event);
    }
    {
        std::lock_guard<std::mutex> lock(g_debugActionMutex);
        g_debugActionThread = NULL;
        g_debugActionEvent = NULL;
        g_debugActionQueue.clear();
    }
}

bool queueDebugAction(DebugAction action) {
    std::lock_guard<std::mutex> lock(g_debugActionMutex);
    if (!g_debugActionRunning || g_debugActionEvent == NULL) {
        return false;
    }
    g_debugActionQueue.push_back(action);
    SetEvent(g_debugActionEvent);
    return true;
}

DWORD WINAPI DebugActionThread(LPVOID lpParam) {
    while (true) {
        HANDLE event = NULL;
        {
            std::lock_guard<std::mutex> lock(g_debugActionMutex);
            event = g_debugActionEvent;
            if (!g_debugActionRunning && g_debugActionQueue.empty()) {
                break;
            }
        }
        if (event != NULL) {
            WaitForSingleObject(event, 100);
        } else {
            Sleep(100);
        }

        while (true) {
            DebugAction action;
            {
                std::lock_guard<std::mutex> lock(g_debugActionMutex);
                if (g_debugActionQueue.empty()) {
                    break;
                }
                action = g_debugActionQueue.front();
                g_debugActionQueue.pop_front();
            }

            _plugin_logprintf("Executing async debug action: %s\n", debugActionName(action).c_str());
            switch (action) {
                case DebugAction::Run:
                    Script::Debug::Run();
                    break;
                case DebugAction::Pause:
                    Script::Debug::Pause();
                    break;
                case DebugAction::Stop:
                    Script::Debug::Stop();
                    break;
                case DebugAction::StepIn:
                    Script::Debug::StepIn();
                    break;
                case DebugAction::StepOver:
                    Script::Debug::StepOver();
                    break;
                case DebugAction::StepOut:
                    Script::Debug::StepOut();
                    break;
            }
        }
    }
    return 0;
}

std::string urlDecode(const std::string& str) {
    std::string decoded;
    for (size_t i = 0; i < str.length(); ++i) {
        if (str[i] == '%' && i + 2 < str.length()) {
            int value;
            std::istringstream is(str.substr(i + 1, 2));
            if (is >> std::hex >> value) {
                decoded += static_cast<char>(value);
                i += 2;
            } else {
                decoded += str[i];
            }
        } else if (str[i] == '+') {
            decoded += ' ';
        } else {
            decoded += str[i];
        }
    }
    return decoded;
}

static void trimParam(std::string& s) {
    const char* ws = " \t\r\n\v\f";
    const auto first = s.find_first_not_of(ws);
    if (first == std::string::npos) {
        s.clear();
        return;
    }
    const auto last = s.find_last_not_of(ws);
    s = s.substr(first, last - first + 1u);
}

std::string escapeJsonString(const char* str) {
    std::string result;
    if (!str) return result;
    while (*str) {
        switch (*str) {
            case '\\': result += "\\\\"; break;
            case '"':  result += "\\\""; break;
            case '\b': result += "\\b"; break;
            case '\f': result += "\\f"; break;
            case '\n': result += "\\n"; break;
            case '\r': result += "\\r"; break;
            case '\t': result += "\\t"; break;
            default:
                if (static_cast<unsigned char>(*str) < 0x20) {
                    char buf[8];
                    snprintf(buf, sizeof(buf), "\\u%04x", static_cast<unsigned char>(*str));
                    result += buf;
                } else {
                    result += *str;
                }
                break;
        }
        str++;
    }
    return result;
}

bool resolveListenAddress(const std::string& host, sockaddr_in& serverAddr) {
    if (host == "0.0.0.0" || host == "*" || host == "any") {
        serverAddr.sin_addr.s_addr = htonl(INADDR_ANY);
        return true;
    }
    if (host == "127.0.0.1" || host == "localhost") {
        serverAddr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        return true;
    }
    return inet_pton(AF_INET, host.c_str(), &serverAddr.sin_addr) == 1;
}

void markHttpServerStopped() {
    std::lock_guard<std::mutex> lock(g_httpMutex);
    g_httpServerRunning = false;
    g_serverSocket = INVALID_SOCKET;
}

DWORD WINAPI HttpServerThread(LPVOID lpParam) {
    WSADATA wsaData;
    int result = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (result != 0) {
        _plugin_logprintf("WSAStartup failed with error: %d\n", result);
        markHttpServerStopped();
        return 1;
    }
    g_serverSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (g_serverSocket == INVALID_SOCKET) {
        _plugin_logprintf("Failed to create socket, error: %d\n", WSAGetLastError());
        WSACleanup();
        markHttpServerStopped();
        return 1;
    }
    sockaddr_in serverAddr;
    memset(&serverAddr, 0, sizeof(serverAddr));
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons((u_short)g_httpPort);
    if (!resolveListenAddress(g_httpHost, serverAddr)) {
        _plugin_logprintf("Invalid HTTP listen host: %s\n", g_httpHost.c_str());
        closesocket(g_serverSocket);
        WSACleanup();
        markHttpServerStopped();
        return 1;
    }
    if (bind(g_serverSocket, (sockaddr*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR) {
        _plugin_logprintf("Bind failed with error: %d\n", WSAGetLastError());
        closesocket(g_serverSocket);
        WSACleanup();
        markHttpServerStopped();
        return 1;
    }
    if (listen(g_serverSocket, SOMAXCONN) == SOCKET_ERROR) {
        _plugin_logprintf("Listen failed with error: %d\n", WSAGetLastError());
        closesocket(g_serverSocket);
        WSACleanup();
        markHttpServerStopped();
        return 1;
    }
    
    _plugin_logprintf("HTTP server started at http://%s:%d/\n", g_httpHost.c_str(), g_httpPort);
    u_long mode = 1;
    ioctlsocket(g_serverSocket, FIONBIO, &mode);
    while (g_httpServerRunning) {
        sockaddr_in clientAddr;
        int clientAddrSize = sizeof(clientAddr);
        SOCKET clientSocket = accept(g_serverSocket, (sockaddr*)&clientAddr, &clientAddrSize);
        
        if (clientSocket == INVALID_SOCKET) {
            if (!g_httpServerRunning) {
                break;
            }
            if (WSAGetLastError() != WSAEWOULDBLOCK) {
                _plugin_logprintf("Accept failed with error: %d\n", WSAGetLastError());
            }
            Sleep(100);
            continue;
        }
        std::string requestData = readHttpRequest(clientSocket);
        if (!requestData.empty()) {
            std::string method, path, query, body;
            parseHttpRequest(requestData, method, path, query, body);
            std::unordered_map<std::string, std::string> queryParams = parseQueryParams(query);
            try {
                if (path == "/Health" || path == "/health" || path == "/healthz") {
                    std::stringstream ss;
                    ss << "{";
                    ss << "\"ok\":true,";
                    ss << "\"service\":\"x64dbg_mcp_plugin\",";
                    ss << "\"listenHost\":\"" << escapeJsonString(g_httpHost.c_str()) << "\",";
                    ss << "\"port\":" << g_httpPort << ",";
                    ss << "\"debugging\":" << (DbgIsDebugging() ? "true" : "false") << ",";
                    ss << "\"running\":" << (DbgIsRunning() ? "true" : "false");
                    ss << "}";
                    sendHttpResponse(clientSocket, 200, "application/json", ss.str());
                }
                else if (path == "/Log/Recent" || path == "/log/recent") {
                    int limit = 100;
                    unsigned long long since = 0;
                    bool clearAfter = false;

                    if (!queryParams["limit"].empty()) {
                        try { limit = std::stoi(queryParams["limit"]); } catch (...) {}
                        if (limit < 1) limit = 1;
                        if (limit > 2000) limit = 2000;
                    }
                    if (!queryParams["since"].empty()) {
                        try { since = std::stoull(queryParams["since"]); } catch (...) {}
                    }
                    std::string clearStr = queryParams["clear"];
                    std::transform(clearStr.begin(), clearStr.end(), clearStr.begin(), ::tolower);
                    clearAfter = (clearStr == "1" || clearStr == "true" || clearStr == "yes");

                    std::vector<EventLogEntry> entries;
                    {
                        std::lock_guard<std::mutex> lock(g_eventLogMutex);
                        for (const auto& entry : g_eventLog) {
                            if (entry.seq > since) {
                                entries.push_back(entry);
                            }
                        }
                        if (entries.size() > static_cast<size_t>(limit)) {
                            entries.erase(entries.begin(), entries.end() - limit);
                        }
                        if (clearAfter) {
                            g_eventLog.clear();
                        }
                    }

                    std::stringstream ss;
                    ss << "{";
                    ss << "\"count\":" << entries.size() << ",";
                    ss << "\"totalBuffered\":" << eventLogSize() << ",";
                    ss << "\"entries\":[";
                    for (size_t i = 0; i < entries.size(); i++) {
                        if (i > 0) ss << ",";
                        ss << "{"
                           << "\"seq\":" << entries[i].seq << ","
                           << "\"tickMs\":" << entries[i].tickMs << ","
                           << "\"kind\":\"" << escapeJsonString(entries[i].kind.c_str()) << "\","
                           << "\"text\":\"" << escapeJsonString(entries[i].text.c_str()) << "\""
                           << "}";
                    }
                    ss << "]}";
                    sendHttpResponse(clientSocket, 200, "application/json", ss.str());
                }
                else if (path == "/Log/Clear" || path == "/log/clear") {
                    size_t cleared = eventLogSize();
                    clearEventLog();
                    std::stringstream ss;
                    ss << "{";
                    ss << "\"success\":true,";
                    ss << "\"cleared\":" << cleared;
                    ss << "}";
                    sendHttpResponse(clientSocket, 200, "application/json", ss.str());
                }
                else if (path == "/Log/BreakpointContext/List" || path == "/log/breakpointcontext/list") {
                    const auto expressions = getBreakpointContextExpressions();
                    std::stringstream ss;
                    ss << "{";
                    ss << "\"count\":" << expressions.size() << ",";
                    ss << "\"items\":[";
                    for (size_t i = 0; i < expressions.size(); i++) {
                        if (i > 0) ss << ",";
                        ss << "{"
                           << "\"label\":\"" << escapeJsonString(expressions[i].label.c_str()) << "\","
                           << "\"expression\":\"" << escapeJsonString(expressions[i].expression.c_str()) << "\""
                           << "}";
                    }
                    ss << "]}";
                    sendHttpResponse(clientSocket, 200, "application/json", ss.str());
                }
                else if (path == "/Log/BreakpointContext/Set" || path == "/log/breakpointcontext/set") {
                    std::string spec = queryParams["items"];
                    if (spec.empty() && !body.empty()) {
                        spec = body;
                    }
                    spec = urlDecode(spec);
                    const auto expressions = parseBreakpointContextSpec(spec);
                    setBreakpointContextExpressions(expressions);

                    std::stringstream ss;
                    ss << "{";
                    ss << "\"success\":true,";
                    ss << "\"count\":" << expressions.size() << ",";
                    ss << "\"items\":[";
                    for (size_t i = 0; i < expressions.size(); i++) {
                        if (i > 0) ss << ",";
                        ss << "{"
                           << "\"label\":\"" << escapeJsonString(expressions[i].label.c_str()) << "\","
                           << "\"expression\":\"" << escapeJsonString(expressions[i].expression.c_str()) << "\""
                           << "}";
                    }
                    ss << "]}";
                    sendHttpResponse(clientSocket, 200, "application/json", ss.str());
                }
                else if (path == "/Log/BreakpointContext/Clear" || path == "/log/breakpointcontext/clear") {
                    const auto oldExpressions = getBreakpointContextExpressions();
                    setBreakpointContextExpressions({});
                    std::stringstream ss;
                    ss << "{";
                    ss << "\"success\":true,";
                    ss << "\"cleared\":" << oldExpressions.size();
                    ss << "}";
                    sendHttpResponse(clientSocket, 200, "application/json", ss.str());
                }
                else if (path == "/ExecCommand") {
                    std::string cmd = queryParams["cmd"];
                    if (cmd.empty() && !body.empty()) {
                        cmd = body;
                    } else {
                        cmd = urlDecode(cmd);
                    }
                    
                    if (cmd.empty()) {
                        sendHttpResponse(clientSocket, 400, "text/plain", "Missing command parameter");
                        continue;
                    }
                    int refRowCountBefore = GuiReferenceGetRowCount();
                    bool success = DbgCmdExecDirect(cmd.c_str());
                    int refRowCountAfter = GuiReferenceGetRowCount();
                    bool refChanged = (refRowCountAfter != refRowCountBefore);
                    if (!refChanged && refRowCountAfter > 0) {
                        std::string cmdLower = cmd;
                        std::transform(cmdLower.begin(), cmdLower.end(), cmdLower.begin(), ::tolower);
                        if (cmdLower.find("refstr") == 0 ||
                            cmdLower.find("reffind") == 0 ||
                            cmdLower.find("reffindrange") == 0 ||
                            cmdLower.find("findall") == 0 ||
                            cmdLower.find("findallmem") == 0 ||
                            cmdLower.find("findasm") == 0 ||
                            cmdLower.find("modcallfind") == 0 ||
                            cmdLower.find("guidfind") == 0 ||
                            cmdLower.find("strref") == 0) {
                            refChanged = true;
                        }
                    }
                    int refOffset = 0;
                    int refLimit = 100;
                    if (!queryParams["offset"].empty()) {
                        try { refOffset = std::stoi(queryParams["offset"]); } catch (...) {}
                        if (refOffset < 0) refOffset = 0;
                    }
                    if (!queryParams["limit"].empty()) {
                        try { refLimit = std::stoi(queryParams["limit"]); } catch (...) {}
                        if (refLimit < 1) refLimit = 1;
                        if (refLimit > 5000) refLimit = 5000;
                    }
                    if (!success) {
                        std::stringstream ss;
                        ss << "{\"success\":false,\"refView\":{\"rowCount\":0,\"rows\":[]}}";
                        sendHttpResponse(clientSocket, 200, "application/json", ss.str());
                    } else {
                        int totalRows = refChanged ? refRowCountAfter : 0;

                        std::stringstream ss;
                        ss << "{";
                        ss << "\"success\":true,";
                        ss << "\"refView\":{";
                        ss << "\"rowCount\":" << totalRows << ",";
                        ss << "\"rows\":[";

                        if (totalRows > 0) {
                            if (refOffset >= totalRows) refOffset = totalRows;
                            int endRow = refOffset + refLimit;
                            if (endRow > totalRows) endRow = totalRows;
                            int numCols = 0;
                            for (int c = 0; c < 10; c++) {
                                char* cell = GuiReferenceGetCellContent(0, c);
                                if (cell) {
                                    if (cell[0] != '\0') {
                                        numCols = c + 1;
                                    }
                                    BridgeFree(cell);
                                }
                            }
                            if (numCols < 2) numCols = 2;

                            bool firstRow = true;
                            for (int row = refOffset; row < endRow; row++) {
                                if (!firstRow) ss << ",";
                                firstRow = false;
                                ss << "[";
                                for (int col = 0; col < numCols; col++) {
                                    if (col > 0) ss << ",";
                                    char* cell = GuiReferenceGetCellContent(row, col);
                                    if (cell) {
                                        ss << "\"" << escapeJsonString(cell) << "\"";
                                        BridgeFree(cell);
                                    } else {
                                        ss << "\"\"";
                                    }
                                }
                                ss << "]";
                            }
                        }

                        ss << "]}}";
                        sendHttpResponse(clientSocket, 200, "application/json", ss.str());
                    }
                }
                else if (path == "/IsDebugActive") {
                    bool isRunning = DbgIsRunning();
                    _plugin_logprintf("DbgIsRunning() called, result: %s\n", isRunning ? "true" : "false");
                    std::stringstream ss;
                    ss << "{\"isRunning\":" << (isRunning ? "true" : "false") << "}";
                    sendHttpResponse(clientSocket, 200, "application/json", ss.str());
                }
                else if (path == "/Is_Debugging") {
                    bool isDebugging = DbgIsDebugging();
                    std::stringstream ss;
                    ss << "{\"isDebugging\":" << (isDebugging ? "true" : "false") << "}";
                    sendHttpResponse(clientSocket, 200, "application/json", ss.str());
                }
                else if (path == "/Register/Get") {
                    std::string regName = queryParams["register"];
                    if (regName.empty()) {
                        sendHttpResponse(clientSocket, 400, "text/plain", "Missing register parameter");
                        continue;
                    }
                    Script::Register::RegisterEnum reg;
                    if (regName == "EAX" || regName == "eax") reg = Script::Register::EAX;
                    else if (regName == "EBX" || regName == "ebx") reg = Script::Register::EBX;
                    else if (regName == "ECX" || regName == "ecx") reg = Script::Register::ECX;
                    else if (regName == "EDX" || regName == "edx") reg = Script::Register::EDX;
                    else if (regName == "ESI" || regName == "esi") reg = Script::Register::ESI;
                    else if (regName == "EDI" || regName == "edi") reg = Script::Register::EDI;
                    else if (regName == "EBP" || regName == "ebp") reg = Script::Register::EBP;
                    else if (regName == "ESP" || regName == "esp") reg = Script::Register::ESP;
                    else if (regName == "EIP" || regName == "eip") reg = Script::Register::EIP;
#ifdef _WIN64
                    else if (regName == "RAX" || regName == "rax") reg = Script::Register::RAX;
                    else if (regName == "RBX" || regName == "rbx") reg = Script::Register::RBX;
                    else if (regName == "RCX" || regName == "rcx") reg = Script::Register::RCX;
                    else if (regName == "RDX" || regName == "rdx") reg = Script::Register::RDX;
                    else if (regName == "RSI" || regName == "rsi") reg = Script::Register::RSI;
                    else if (regName == "RDI" || regName == "rdi") reg = Script::Register::RDI;
                    else if (regName == "RBP" || regName == "rbp") reg = Script::Register::RBP;
                    else if (regName == "RSP" || regName == "rsp") reg = Script::Register::RSP;
                    else if (regName == "RIP" || regName == "rip") {
#ifdef _WIN64
                        reg = Script::Register::RIP;
#else
                        reg = Script::Register::EIP;
#endif
                    }
                    else if (regName == "R8" || regName == "r8") reg = Script::Register::R8;
                    else if (regName == "R9" || regName == "r9") reg = Script::Register::R9;
                    else if (regName == "R10" || regName == "r10") reg = Script::Register::R10;
                    else if (regName == "R11" || regName == "r11") reg = Script::Register::R11;
                    else if (regName == "R12" || regName == "r12") reg = Script::Register::R12;
                    else if (regName == "R13" || regName == "r13") reg = Script::Register::R13;
                    else if (regName == "R14" || regName == "r14") reg = Script::Register::R14;
                    else if (regName == "R15" || regName == "r15") reg = Script::Register::R15;
#endif
                    else {
                        sendHttpResponse(clientSocket, 400, "text/plain", "Unknown register");
                        continue;
                    }
                    
                    duint value = Script::Register::Get(reg);
                    std::stringstream ss;
                    ss << "0x" << std::hex << value;
                    sendHttpResponse(clientSocket, 200, "text/plain", ss.str());
                }
                else if (path == "/Register/Set") {
                    std::string regName = queryParams["register"];
                    std::string valueStr = queryParams["value"];
                    if (regName.empty() || valueStr.empty()) {
                        sendHttpResponse(clientSocket, 400, "text/plain", "Missing register or value parameter");
                        continue;
                    }
                    Script::Register::RegisterEnum reg;
                    if (regName == "EAX" || regName == "eax") reg = Script::Register::EAX;
                    else if (regName == "EBX" || regName == "ebx") reg = Script::Register::EBX;
                    else if (regName == "ECX" || regName == "ecx") reg = Script::Register::ECX;
                    else if (regName == "EDX" || regName == "edx") reg = Script::Register::EDX;
                    else if (regName == "ESI" || regName == "esi") reg = Script::Register::ESI;
                    else if (regName == "EDI" || regName == "edi") reg = Script::Register::EDI;
                    else if (regName == "EBP" || regName == "ebp") reg = Script::Register::EBP;
                    else if (regName == "ESP" || regName == "esp") reg = Script::Register::ESP;
                    else if (regName == "EIP" || regName == "eip") reg = Script::Register::EIP;
#ifdef _WIN64
                    else if (regName == "RAX" || regName == "rax") reg = Script::Register::RAX;
                    else if (regName == "RBX" || regName == "rbx") reg = Script::Register::RBX;
                    else if (regName == "RCX" || regName == "rcx") reg = Script::Register::RCX;
                    else if (regName == "RDX" || regName == "rdx") reg = Script::Register::RDX;
                    else if (regName == "RSI" || regName == "rsi") reg = Script::Register::RSI;
                    else if (regName == "RDI" || regName == "rdi") reg = Script::Register::RDI;
                    else if (regName == "RBP" || regName == "rbp") reg = Script::Register::RBP;
                    else if (regName == "RSP" || regName == "rsp") reg = Script::Register::RSP;
                    else if (regName == "RIP" || regName == "rip") {
#ifdef _WIN64
                        reg = Script::Register::RIP;
#else
                        reg = Script::Register::EIP;
#endif
                    }
                    else if (regName == "R8" || regName == "r8") reg = Script::Register::R8;
                    else if (regName == "R9" || regName == "r9") reg = Script::Register::R9;
                    else if (regName == "R10" || regName == "r10") reg = Script::Register::R10;
                    else if (regName == "R11" || regName == "r11") reg = Script::Register::R11;
                    else if (regName == "R12" || regName == "r12") reg = Script::Register::R12;
                    else if (regName == "R13" || regName == "r13") reg = Script::Register::R13;
                    else if (regName == "R14" || regName == "r14") reg = Script::Register::R14;
                    else if (regName == "R15" || regName == "r15") reg = Script::Register::R15;
#endif
                    else {
                        sendHttpResponse(clientSocket, 400, "text/plain", "Unknown register");
                        continue;
                    }
                    
                    duint value = 0;
                    try {
                        if (valueStr.substr(0, 2) == "0x") {
                            value = std::stoull(valueStr.substr(2), nullptr, 16);
                        } else {
                            value = std::stoull(valueStr, nullptr, 16);
                        }
                    } catch (const std::exception& e) {
                        sendHttpResponse(clientSocket, 400, "text/plain", "Invalid value format");
                        continue;
                    }
                    
                    bool success = Script::Register::Set(reg, value);
                    sendHttpResponse(clientSocket, success ? 200 : 500, "text/plain", 
                        success ? "Register set successfully" : "Failed to set register");
                }
                else if (path == "/Memory/Read") {
                    std::string addrStr = queryParams["addr"];
                    std::string sizeStr = queryParams["size"];
                    
                    if (addrStr.empty() || sizeStr.empty()) {
                        sendHttpResponse(clientSocket, 400, "text/plain", "Missing address or size");
                        continue;
                    }
                    
                    duint addr = 0;
                    duint size = 0;
                    try {
                        if (addrStr.substr(0, 2) == "0x") {
                            addr = std::stoull(addrStr.substr(2), nullptr, 16);
                        } else {
                            addr = std::stoull(addrStr, nullptr, 16);
                        }
                        size = std::stoull(sizeStr, nullptr, 10);
                    } catch (const std::exception& e) {
                        sendHttpResponse(clientSocket, 400, "text/plain", "Invalid address or size format");
                        continue;
                    }
                    
                    if (size > 1024 * 1024) {
                        sendHttpResponse(clientSocket, 400, "text/plain", "Size too large");
                        continue;
                    }
                    
                    std::vector<unsigned char> buffer(size);
                    duint sizeRead = 0;
                    
                    if (!Script::Memory::Read(addr, buffer.data(), size, &sizeRead)) {
                        sendHttpResponse(clientSocket, 500, "text/plain", "Failed to read memory");
                        continue;
                    }
                    
                    std::stringstream ss;
                    for (duint i = 0; i < sizeRead; i++) {
                        ss << std::setw(2) << std::setfill('0') << std::hex << (int)buffer[i];
                    }
                    
                    sendHttpResponse(clientSocket, 200, "text/plain", ss.str());
                }
                else if (path == "/Memory/Write") {
                    std::string addrStr = queryParams["addr"];
                    std::string dataStr = !body.empty() ? body : queryParams["data"];
                    
                    if (addrStr.empty() || dataStr.empty()) {
                        sendHttpResponse(clientSocket, 400, "text/plain", "Missing address or data");
                        continue;
                    }
                    
                    duint addr = 0;
                    try {
                        if (addrStr.substr(0, 2) == "0x") {
                            addr = std::stoull(addrStr.substr(2), nullptr, 16);
                        } else {
                            addr = std::stoull(addrStr, nullptr, 16);
                        }
                    } catch (const std::exception& e) {
                        sendHttpResponse(clientSocket, 400, "text/plain", "Invalid address format");
                        continue;
                    }
                    
                    std::vector<unsigned char> buffer;
                    for (size_t i = 0; i < dataStr.length(); i += 2) {
                        if (i + 1 >= dataStr.length()) break;
                        std::string byteString = dataStr.substr(i, 2);
                        try {
                            unsigned char byte = (unsigned char)std::stoi(byteString, nullptr, 16);
                            buffer.push_back(byte);
                        } catch (const std::exception& e) {
                            sendHttpResponse(clientSocket, 400, "text/plain", "Invalid data format");
                            continue;
                        }
                    }
                    
                    duint sizeWritten = 0;
                    bool success = Script::Memory::Write(addr, buffer.data(), buffer.size(), &sizeWritten);
                    sendHttpResponse(clientSocket, success ? 200 : 500, "text/plain", 
                        success ? "Memory written successfully" : "Failed to write memory");
                }
                else if (path == "/Memory/IsValidPtr") {
                    std::string addrStr = queryParams["addr"];
                    if (addrStr.empty()) {
                        sendHttpResponse(clientSocket, 400, "text/plain", "Missing address parameter");
                        continue;
                    }
                    
                    duint addr = 0;
                    try {
                        if (addrStr.substr(0, 2) == "0x") {
                            addr = std::stoull(addrStr.substr(2), nullptr, 16);
                        } else {
                            addr = std::stoull(addrStr, nullptr, 16);
                        }
                    } catch (const std::exception& e) {
                        sendHttpResponse(clientSocket, 400, "text/plain", "Invalid address format");
                        continue;
                    }
                    
                    bool isValid = Script::Memory::IsValidPtr(addr);
                    sendHttpResponse(clientSocket, 200, "text/plain", isValid ? "true" : "false");
                }
                else if (path == "/Memory/GetProtect") {
                    std::string addrStr = queryParams["addr"];
                    if (addrStr.empty()) {
                        sendHttpResponse(clientSocket, 400, "text/plain", "Missing address parameter");
                        continue;
                    }
                    
                    duint addr = 0;
                    try {
                        if (addrStr.substr(0, 2) == "0x") {
                            addr = std::stoull(addrStr.substr(2), nullptr, 16);
                        } else {
                            addr = std::stoull(addrStr, nullptr, 16);
                        }
                    } catch (const std::exception& e) {
                        sendHttpResponse(clientSocket, 400, "text/plain", "Invalid address format");
                        continue;
                    }
                    
                    unsigned int protect = Script::Memory::GetProtect(addr);
                    std::stringstream ss;
                    ss << "0x" << std::hex << protect;
                    sendHttpResponse(clientSocket, 200, "text/plain", ss.str());
                }
                
                else if (path == "/Debug/Run") {
                    sendHttpResponse(clientSocket, 409, "application/json",
                        "{\"ok\":false,\"error\":\"Synchronous Debug/Run is disabled to avoid blocking the HTTP server; use /Debug/RunAsync or press F9 in x64dbg.\"}");
                }
                else if (path == "/Debug/RunAsync") {
                    bool queued = queueDebugAction(DebugAction::Run);
                    sendHttpResponse(clientSocket, queued ? 202 : 500, "application/json",
                        queued ? "{\"queued\":true,\"action\":\"Run\"}" : "{\"queued\":false,\"error\":\"Debug action worker is not running\"}");
                }
                else if (path == "/Debug/Pause") {
                    sendHttpResponse(clientSocket, 409, "application/json",
                        "{\"ok\":false,\"error\":\"Synchronous Debug/Pause is disabled; use /Debug/PauseAsync.\"}");
                }
                else if (path == "/Debug/PauseAsync") {
                    bool queued = queueDebugAction(DebugAction::Pause);
                    sendHttpResponse(clientSocket, queued ? 202 : 500, "application/json",
                        queued ? "{\"queued\":true,\"action\":\"Pause\"}" : "{\"queued\":false,\"error\":\"Debug action worker is not running\"}");
                }
                else if (path == "/Debug/Stop") {
                    sendHttpResponse(clientSocket, 409, "application/json",
                        "{\"ok\":false,\"error\":\"Synchronous Debug/Stop is disabled; use /Debug/StopAsync.\"}");
                }
                else if (path == "/Debug/StopAsync") {
                    bool queued = queueDebugAction(DebugAction::Stop);
                    sendHttpResponse(clientSocket, queued ? 202 : 500, "application/json",
                        queued ? "{\"queued\":true,\"action\":\"Stop\"}" : "{\"queued\":false,\"error\":\"Debug action worker is not running\"}");
                }
                else if (path == "/Debug/StepIn") {
                    sendHttpResponse(clientSocket, 409, "application/json",
                        "{\"ok\":false,\"error\":\"Synchronous Debug/StepIn is disabled; use /Debug/StepInAsync.\"}");
                }
                else if (path == "/Debug/StepInAsync") {
                    bool queued = queueDebugAction(DebugAction::StepIn);
                    sendHttpResponse(clientSocket, queued ? 202 : 500, "application/json",
                        queued ? "{\"queued\":true,\"action\":\"StepIn\"}" : "{\"queued\":false,\"error\":\"Debug action worker is not running\"}");
                }
                else if (path == "/Debug/StepOver") {
                    sendHttpResponse(clientSocket, 409, "application/json",
                        "{\"ok\":false,\"error\":\"Synchronous Debug/StepOver is disabled; use /Debug/StepOverAsync.\"}");
                }
                else if (path == "/Debug/StepOverAsync") {
                    bool queued = queueDebugAction(DebugAction::StepOver);
                    sendHttpResponse(clientSocket, queued ? 202 : 500, "application/json",
                        queued ? "{\"queued\":true,\"action\":\"StepOver\"}" : "{\"queued\":false,\"error\":\"Debug action worker is not running\"}");
                }
                else if (path == "/Debug/StepOut") {
                    sendHttpResponse(clientSocket, 409, "application/json",
                        "{\"ok\":false,\"error\":\"Synchronous Debug/StepOut is disabled; use /Debug/StepOutAsync.\"}");
                }
                else if (path == "/Debug/StepOutAsync") {
                    bool queued = queueDebugAction(DebugAction::StepOut);
                    sendHttpResponse(clientSocket, queued ? 202 : 500, "application/json",
                        queued ? "{\"queued\":true,\"action\":\"StepOut\"}" : "{\"queued\":false,\"error\":\"Debug action worker is not running\"}");
                }
                else if (path == "/Debug/SetBreakpoint") {
                    std::string addrStr = queryParams["addr"];
                    if (addrStr.empty()) {
                        sendHttpResponse(clientSocket, 400, "text/plain", "Missing address parameter");
                        continue;
                    }
                    
                    duint addr = 0;
                    try {
                        if (addrStr.substr(0, 2) == "0x") {
                            addr = std::stoull(addrStr.substr(2), nullptr, 16);
                        } else {
                            addr = std::stoull(addrStr, nullptr, 16);
                        }
                    } catch (const std::exception& e) {
                        sendHttpResponse(clientSocket, 400, "text/plain", "Invalid address format");
                        continue;
                    }
                    
                    bool success = Script::Debug::SetBreakpoint(addr);
                    sendHttpResponse(clientSocket, success ? 200 : 500, "text/plain", 
                        success ? "Breakpoint set successfully" : "Failed to set breakpoint");
                }
                else if (path == "/Debug/DeleteBreakpoint") {
                    std::string addrStr = queryParams["addr"];
                    if (addrStr.empty()) {
                        sendHttpResponse(clientSocket, 400, "text/plain", "Missing address parameter");
                        continue;
                    }
                    
                    duint addr = 0;
                    try {
                        if (addrStr.substr(0, 2) == "0x") {
                            addr = std::stoull(addrStr.substr(2), nullptr, 16);
                        } else {
                            addr = std::stoull(addrStr, nullptr, 16);
                        }
                    } catch (const std::exception& e) {
                        sendHttpResponse(clientSocket, 400, "text/plain", "Invalid address format");
                        continue;
                    }
                    
                    bool success = Script::Debug::DeleteBreakpoint(addr);
                    sendHttpResponse(clientSocket, success ? 200 : 500, "text/plain", 
                        success ? "Breakpoint deleted successfully" : "Failed to delete breakpoint");
                }
                else if (path == "/Breakpoint/SetSilent") {
                    std::string addrStr = queryParams["addr"];
                    std::string silentStr = queryParams["silent"];
                    if (addrStr.empty()) {
                        sendHttpResponse(clientSocket, 400, "application/json",
                            "{\"error\":\"Missing required 'addr' parameter\"}");
                        continue;
                    }

                    duint addr = 0;
                    if (!tryParseHexAddress(addrStr, addr)) {
                        sendHttpResponse(clientSocket, 400, "application/json",
                            "{\"error\":\"Invalid address format\"}");
                        continue;
                    }

                    std::string silentLower = silentStr;
                    std::transform(silentLower.begin(), silentLower.end(), silentLower.begin(), ::tolower);
                    bool requestedSilent = !(silentLower == "0" || silentLower == "false" || silentLower == "off" || silentLower == "no");

                    BRIDGEBP bp;
                    if (!getBreakpointByAddress(addr, bp)) {
                        sendHttpResponse(clientSocket, 404, "application/json",
                            "{\"error\":\"Breakpoint not found\"}");
                        continue;
                    }

                    std::string attemptsSummary;
                    bool finalSilent = bp.silent;
                    bool applied = applyBreakpointSilentFlag(addr, requestedSilent, attemptsSummary, finalSilent);

                    std::stringstream ss;
                    ss << "{";
                    ss << "\"success\":" << (applied ? "true" : "false") << ",";
                    ss << "\"addr\":\"" << formatBreakpointAddress(addr) << "\",";
                    ss << "\"requestedSilent\":" << (requestedSilent ? "true" : "false") << ",";
                    ss << "\"finalSilent\":" << (finalSilent ? "true" : "false") << ",";
                    ss << "\"attempts\":\"" << escapeJsonString(attemptsSummary.c_str()) << "\"";
                    ss << "}";
                    sendHttpResponse(clientSocket, applied ? 200 : 409, "application/json", ss.str());
                }
                
                else if (path == "/Assembler/Assemble") {
                    std::string addrStr = queryParams["addr"];
                    std::string instruction = queryParams["instruction"];
                    if (instruction.empty() && !body.empty()) {
                        instruction = body;
                    }
                    
                    if (addrStr.empty() || instruction.empty()) {
                        sendHttpResponse(clientSocket, 400, "text/plain", "Missing address or instruction parameter");
                        continue;
                    }
                    
                    duint addr = 0;
                    try {
                        if (addrStr.substr(0, 2) == "0x") {
                            addr = std::stoull(addrStr.substr(2), nullptr, 16);
                        } else {
                            addr = std::stoull(addrStr, nullptr, 16);
                        }
                    } catch (const std::exception& e) {
                        sendHttpResponse(clientSocket, 400, "text/plain", "Invalid address format");
                        continue;
                    }
                    
                    unsigned char dest[16];
                    int size = 16;
                    bool success = Script::Assembler::Assemble(addr, dest, &size, instruction.c_str());
                    
                    if (success) {
                        std::stringstream ss;
                        ss << "{\"success\":true,\"size\":" << size << ",\"bytes\":\"";
                        for (int i = 0; i < size; i++) {
                            ss << std::setw(2) << std::setfill('0') << std::hex << (int)dest[i];
                        }
                        ss << "\"}";
                        sendHttpResponse(clientSocket, 200, "application/json", ss.str());
                    } else {
                        sendHttpResponse(clientSocket, 500, "text/plain", "Failed to assemble instruction");
                    }
                }
                else if (path == "/Assembler/AssembleMem") {
                    std::string addrStr = queryParams["addr"];
                    std::string instruction = queryParams["instruction"];
                    if (instruction.empty() && !body.empty()) {
                        instruction = body;
                    }
                    
                    if (addrStr.empty() || instruction.empty()) {
                        sendHttpResponse(clientSocket, 400, "text/plain", "Missing address or instruction parameter");
                        continue;
                    }
                    
                    duint addr = 0;
                    try {
                        if (addrStr.substr(0, 2) == "0x") {
                            addr = std::stoull(addrStr.substr(2), nullptr, 16);
                        } else {
                            addr = std::stoull(addrStr, nullptr, 16);
                        }
                    } catch (const std::exception& e) {
                        sendHttpResponse(clientSocket, 400, "text/plain", "Invalid address format");
                        continue;
                    }
                    
                    bool success = Script::Assembler::AssembleMem(addr, instruction.c_str());
                    sendHttpResponse(clientSocket, success ? 200 : 500, "text/plain", 
                        success ? "Instruction assembled in memory successfully" : "Failed to assemble instruction in memory");
                }
                else if (path == "/Stack/Pop") {
                    duint value = Script::Stack::Pop();
                    std::stringstream ss;
                    ss << "0x" << std::hex << value;
                    sendHttpResponse(clientSocket, 200, "text/plain", ss.str());
                }
                else if (path == "/Stack/Push") {
                    std::string valueStr = queryParams["value"];
                    if (valueStr.empty()) {
                        sendHttpResponse(clientSocket, 400, "text/plain", "Missing value parameter");
                        continue;
                    }
                    
                    duint value = 0;
                    try {
                        if (valueStr.substr(0, 2) == "0x") {
                            value = std::stoull(valueStr.substr(2), nullptr, 16);
                        } else {
                            value = std::stoull(valueStr, nullptr, 16);
                        }
                    } catch (const std::exception& e) {
                        sendHttpResponse(clientSocket, 400, "text/plain", "Invalid value format");
                        continue;
                    }
                    
                    duint prevTop = Script::Stack::Push(value);
                    std::stringstream ss;
                    ss << "0x" << std::hex << prevTop;
                    sendHttpResponse(clientSocket, 200, "text/plain", ss.str());
                }
                else if (path == "/Stack/Peek") {
                    std::string offsetStr = queryParams["offset"];
                    int offset = 0;
                    if (!offsetStr.empty()) {
                        try {
                            offset = std::stoi(offsetStr);
                        } catch (const std::exception& e) {
                            sendHttpResponse(clientSocket, 400, "text/plain", "Invalid offset format");
                            continue;
                        }
                    }
                    
                    duint value = Script::Stack::Peek(offset);
                    std::stringstream ss;
                    ss << "0x" << std::hex << value;
                    sendHttpResponse(clientSocket, 200, "text/plain", ss.str());
                }
                else if (path == "/Disasm/GetInstructionRange") {
                    std::string addrStr = queryParams["addr"];
                    std::string countStr = queryParams["count"];
                    
                    if (addrStr.empty()) {
                        sendHttpResponse(clientSocket, 400, "text/plain", "Missing address parameter");
                        continue;
                    }
                    
                    duint addr = 0;
                    int count = 1;
                    
                    try {
                        if (addrStr.substr(0, 2) == "0x") {
                            addr = std::stoull(addrStr.substr(2), nullptr, 16);
                        } else {
                            addr = std::stoull(addrStr, nullptr, 16);
                        }
                        
                        if (!countStr.empty()) {
                            count = std::stoi(countStr);
                        }
                    } catch (const std::exception& e) {
                        sendHttpResponse(clientSocket, 400, "text/plain", "Invalid address or count format");
                        continue;
                    }
                    
                    if (count <= 0 || count > 100) {
                        sendHttpResponse(clientSocket, 400, "text/plain", "Count must be between 1 and 100");
                        continue;
                    }
                    
                    // Get multiple instructions
                    std::stringstream ss;
                    ss << "[";
                    
                    duint currentAddr = addr;
                    for (int i = 0; i < count; i++) {
                        DISASM_INSTR instr;
                        DbgDisasmAt(currentAddr, &instr);
                        
                        if (instr.instr_size > 0) {
                            if (i > 0) ss << ",";
                            
                            ss << "{";
                            ss << "\"address\":\"0x" << std::hex << currentAddr << "\",";
                            ss << "\"instruction\":\"" << instr.instruction << "\",";
                            ss << "\"size\":" << std::dec << instr.instr_size;
                            ss << "}";
                            
                            currentAddr += instr.instr_size;
                        } else {
                            break;
                        }
                    }
                    
                    ss << "]";
                    sendHttpResponse(clientSocket, 200, "application/json", ss.str());
                }
                else if (path == "/Disasm/StepInWithDisasm") {
                    sendHttpResponse(clientSocket, 409, "application/json",
                        "{\"ok\":false,\"error\":\"StepInWithDisasm used a synchronous step and is disabled; use /Debug/StepInAsync and then /Disasm/GetInstructionRange after the debugger stops.\"}");
                }
                else if (path == "/Flag/Get") {
                    std::string flagName = queryParams["flag"];
                    if (flagName.empty()) {
                        sendHttpResponse(clientSocket, 400, "text/plain", "Missing flag parameter");
                        continue;
                    }
                    bool val = false;
                    if (flagName == "ZF" || flagName == "zf") val = Script::Flag::GetZF();
                    else if (flagName == "OF" || flagName == "of") val = Script::Flag::GetOF();
                    else if (flagName == "CF" || flagName == "cf") val = Script::Flag::GetCF();
                    else if (flagName == "PF" || flagName == "pf") val = Script::Flag::GetPF();
                    else if (flagName == "SF" || flagName == "sf") val = Script::Flag::GetSF();
                    else if (flagName == "TF" || flagName == "tf") val = Script::Flag::GetTF();
                    else if (flagName == "AF" || flagName == "af") val = Script::Flag::GetAF();
                    else if (flagName == "DF" || flagName == "df") val = Script::Flag::GetDF();
                    else if (flagName == "IF" || flagName == "if") val = Script::Flag::GetIF();
                    else {
                        sendHttpResponse(clientSocket, 400, "text/plain", "Unknown flag");
                        continue;
                    }
                    sendHttpResponse(clientSocket, 200, "text/plain", val ? "true" : "false");
                }
                else if (path == "/Flag/Set") {
                    std::string flagName = queryParams["flag"];
                    std::string valueStr = queryParams["value"];
                    if (flagName.empty() || valueStr.empty()) {
                        sendHttpResponse(clientSocket, 400, "text/plain", "Missing flag or value parameter");
                        continue;
                    }
                    std::string vLower = valueStr;
                    std::transform(vLower.begin(), vLower.end(), vLower.begin(), ::tolower);
                    bool value = (vLower == "true" || vLower == "1");
                    bool success = false;
                    if (flagName == "ZF" || flagName == "zf") success = Script::Flag::SetZF(value);
                    else if (flagName == "OF" || flagName == "of") success = Script::Flag::SetOF(value);
                    else if (flagName == "CF" || flagName == "cf") success = Script::Flag::SetCF(value);
                    else if (flagName == "PF" || flagName == "pf") success = Script::Flag::SetPF(value);
                    else if (flagName == "SF" || flagName == "sf") success = Script::Flag::SetSF(value);
                    else if (flagName == "TF" || flagName == "tf") success = Script::Flag::SetTF(value);
                    else if (flagName == "AF" || flagName == "af") success = Script::Flag::SetAF(value);
                    else if (flagName == "DF" || flagName == "df") success = Script::Flag::SetDF(value);
                    else if (flagName == "IF" || flagName == "if") success = Script::Flag::SetIF(value);
                    else {
                        sendHttpResponse(clientSocket, 400, "text/plain", "Unknown flag");
                        continue;
                    }
                    if (success)
                        GuiUpdateRegisterView();
                    sendHttpResponse(clientSocket, success ? 200 : 500, "text/plain",
                        success ? "Flag set successfully" : "Failed to set flag");
                }
                
                else if (path == "/Pattern/FindMem") {
                    std::string startStr = queryParams["start"];
                    std::string sizeStr = queryParams["size"];
                    std::string pattern = queryParams["pattern"];
                    std::string Pattern = urlDecode(pattern);
                    if (startStr.empty() || sizeStr.empty() || pattern.empty()) {
                        sendHttpResponse(clientSocket, 400, "text/plain", "Missing start, size, or pattern parameter");
                        continue;
                    }
                    
                    duint start = 0, size = 0;

                    Pattern.erase(std::remove_if(pattern.begin(), pattern.end(), 
                                  [](unsigned char c) { return std::isspace(c); }), 
                    Pattern.end());

                    try {
                        if (startStr.substr(0, 2) == "0x") {
                            start = std::stoull(startStr.substr(2), nullptr, 16);
                        } else {
                            start = std::stoull(startStr, nullptr, 16);
                        }
                        if (sizeStr.substr(0, 2) == "0x") {
                            size = std::stoull(sizeStr.substr(2), nullptr, 16);
                        } else {
                            size = std::stoull(sizeStr, nullptr, 16);
                        }
                    } catch (const std::exception& e) {
                        sendHttpResponse(clientSocket, 400, "text/plain", "Invalid start or size format");
                        continue;
                    }
                    
                    duint result = Script::Pattern::FindMem(start, size, Pattern.c_str());
                    if (result != 0) {
                        std::stringstream ss;
                        ss << "0x" << std::hex << result;
                        sendHttpResponse(clientSocket, 200, "text/plain", ss.str());
                    } else {
                        sendHttpResponse(clientSocket, 404, "text/plain", "Pattern not found");
                    }
                }
                else if (path == "/Misc/ParseExpression") {
                    std::string expression = queryParams["expression"];
                    if (expression.empty() && !body.empty()) {
                        expression = body;
                    }
                    expression = urlDecode(expression);
                    trimParam(expression);

                    if (expression.empty()) {
                        sendHttpResponse(clientSocket, 400, "text/plain", "Missing expression parameter");
                        continue;
                    }

                    const bool wantJson = (queryParams["format"] == "json");
                    duint value = 0;
                    const bool success = Script::Misc::ParseExpression(expression.c_str(), &value);

                    if (!success) {
                        _plugin_logprintf(
                            "[HTTP /Misc/ParseExpression] failed (see DBG log). expr: %s\n",
                            expression.c_str());
                        if (wantJson) {
                            sendHttpResponse(clientSocket, 500, "application/json",
                                "{\"ok\":false,\"error\":\"Failed to parse expression\"}");
                        } else {
                            sendHttpResponse(clientSocket, 500, "text/plain", "Failed to parse expression");
                        }
                        continue;
                    }

                    if (wantJson) {
                        std::stringstream ss;
                        ss << "{\"ok\":true,\"value\":\"0x" << std::hex << value << "\"}";
                        sendHttpResponse(clientSocket, 200, "application/json", ss.str());
                    } else {
                        std::stringstream ss;
                        ss << "0x" << std::hex << value;
                        sendHttpResponse(clientSocket, 200, "text/plain", ss.str());
                    }
                }
                else if (path == "/Misc/RemoteGetProcAddress") {
                    std::string module = queryParams["module"];
                    std::string api = queryParams["api"];
                    
                    if (module.empty() || api.empty()) {
                        sendHttpResponse(clientSocket, 400, "text/plain", "Missing module or api parameter");
                        continue;
                    }
                    
                    duint addr = Script::Misc::RemoteGetProcAddress(module.c_str(), api.c_str());
                    if (addr != 0) {
                        std::stringstream ss;
                        ss << "0x" << std::hex << addr;
                        sendHttpResponse(clientSocket, 200, "text/plain", ss.str());
                    } else {
                        sendHttpResponse(clientSocket, 404, "text/plain", "Function not found");
                    }
                }
                else if (path == "/MemoryBase") {
                    std::string addrStr = queryParams["addr"];
                    if (addrStr.empty() && !body.empty()) {
                        addrStr = body;
                    }
                    // Convert string address to duint
                    duint addr = 0;
                    try {
                        addr = std::stoull(addrStr, nullptr, 16); // Parse as hex
                    }
                    catch (const std::exception& e) {
                        sendHttpResponse(clientSocket, 400, "text/plain", "Invalid address format");
                        continue;
                    }
                    // Get the base address and size
                    duint size = 0;
                    duint baseAddr = DbgMemFindBaseAddr(addr, &size);
                    if (baseAddr == 0) {
                        sendHttpResponse(clientSocket, 404, "text/plain", "No module found for this address");
                    }
                    else {
                        // Format the response as JSON
                        std::stringstream ss;
                        ss << "{\"base_address\":\"0x" << std::hex << baseAddr << "\",\"size\":\"0x" << std::hex << size << "\"}";
                        sendHttpResponse(clientSocket, 200, "application/json", ss.str());
                    }
                }
                else if (path == "/GetModuleList") {
                    // Create a list to store the module information
                    ListInfo moduleList;
                    
                    // Get the list of modules
                    bool success = Script::Module::GetList(&moduleList);
                    
                    if (!success) {
                        sendHttpResponse(clientSocket, 500, "text/plain", "Failed to get module list");
                    }
                    else {
                        // Create a JSON array to hold the module information
                        std::stringstream jsonResponse;
                        jsonResponse << "[";
                        
                        // Iterate through each module in the list
                        size_t count = moduleList.count;
                        Script::Module::ModuleInfo* modules = (Script::Module::ModuleInfo*)moduleList.data;
                        
                        for (size_t i = 0; i < count; i++) {
                            if (i > 0) jsonResponse << ",";
                            
                            // Add module info as JSON object
                            jsonResponse << "{";
                            jsonResponse << "\"name\":\"" << escapeJsonString(modules[i].name) << "\",";
                            jsonResponse << "\"base\":\"0x" << std::hex << modules[i].base << "\",";
                            jsonResponse << "\"size\":\"0x" << std::hex << modules[i].size << "\",";
                            jsonResponse << "\"entry\":\"0x" << std::hex << modules[i].entry << "\",";
                            jsonResponse << "\"sectionCount\":" << std::dec << modules[i].sectionCount << ",";
                            jsonResponse << "\"path\":\"" << escapeJsonString(modules[i].path) << "\"";
                            jsonResponse << "}";
                        }
                        
                        jsonResponse << "]";
                        
                        // Free the list
                        BridgeFree(moduleList.data);
                        
                        // Send the response
                        sendHttpResponse(clientSocket, 200, "application/json", jsonResponse.str());
                    }
                }
                else if (path == "/SymbolEnum") {
                    // Module name is required to keep response sizes manageable
                    std::string moduleFilter = queryParams["module"];
                    if (moduleFilter.empty()) {
                        sendHttpResponse(clientSocket, 400, "application/json",
                            "{\"error\":\"Missing required 'module' parameter. Use GetModuleList to discover module names.\"}");
                        continue;
                    }
                    
                    // Parse pagination parameters
                    std::string offsetStr = queryParams["offset"];
                    std::string limitStr = queryParams["limit"];
                    
                    int offset = 0;
                    int limit = 5000;
                    
                    if (!offsetStr.empty()) {
                        try { offset = std::stoi(offsetStr); } catch (...) { offset = 0; }
                    }
                    if (!limitStr.empty()) {
                        try { limit = std::stoi(limitStr); } catch (...) { limit = 5000; }
                    }
                    
                    // Clamp values
                    if (offset < 0) offset = 0;
                    if (limit <= 0) limit = 5000;
                    if (limit > 50000) limit = 50000;
                    
                    std::string moduleFilterDecoded = urlDecode(moduleFilter);
                    
                    // Get all symbols using Script::Symbol::GetList
                    ListInfo symbolList;
                    bool success = Script::Symbol::GetList(&symbolList);
                    
                    if (!success || symbolList.data == nullptr) {
                        sendHttpResponse(clientSocket, 500, "application/json",
                            "{\"error\":\"Failed to enumerate symbols\",\"symbols\":[],\"total\":0}");
                        continue;
                    }
                    
                    size_t totalCount = symbolList.count;
                    Script::Symbol::SymbolInfo* symbols = (Script::Symbol::SymbolInfo*)symbolList.data;
                    
                    // Build JSON response - filter to requested module only
                    std::stringstream jsonResponse;
                    
                    int matchIndex = 0;   // Index among matching symbols
                    int emitted = 0;      // Number of symbols emitted in this page
                    int filteredTotal = 0; // Total matching symbols for this module
                    
                    // First pass: count total matching symbols for this module
                    for (size_t i = 0; i < totalCount; i++) {
                        if (_stricmp(symbols[i].mod, moduleFilterDecoded.c_str()) == 0) {
                            filteredTotal++;
                        }
                    }
                    
                    // Write header
                    jsonResponse << "{\"total\":" << filteredTotal
                                 << ",\"module\":\"" << escapeJsonString(moduleFilterDecoded.c_str()) << "\""
                                 << ",\"offset\":" << offset
                                 << ",\"limit\":" << limit
                                 << ",\"symbols\":[";
                    
                    // Second pass: emit symbols with pagination
                    for (size_t i = 0; i < totalCount && emitted < limit; i++) {
                        // Filter to requested module
                        if (_stricmp(symbols[i].mod, moduleFilterDecoded.c_str()) != 0) {
                            continue;
                        }
                        
                        // Apply offset (skip first N matching symbols)
                        if (matchIndex < offset) {
                            matchIndex++;
                            continue;
                        }
                        matchIndex++;
                        
                        // Determine type string
                        const char* typeStr = "unknown";
                        switch (symbols[i].type) {
                            case Script::Symbol::Function: typeStr = "function"; break;
                            case Script::Symbol::Import:   typeStr = "import"; break;
                            case Script::Symbol::Export:   typeStr = "export"; break;
                        }
                        
                        if (emitted > 0) jsonResponse << ",";
                        
                        jsonResponse << "{"
                                     << "\"rva\":\"0x" << std::hex << symbols[i].rva << "\","
                                     << "\"name\":\"" << escapeJsonString(symbols[i].name) << "\","
                                     << "\"manual\":" << (symbols[i].manual ? "true" : "false") << ","
                                     << "\"type\":\"" << typeStr << "\""
                                     << "}";
                        
                        emitted++;
                    }
                    
                    jsonResponse << "]}";
                    
                    // Free the list
                    BridgeFree(symbolList.data);

                    sendHttpResponse(clientSocket, 200, "application/json", jsonResponse.str());
                }
                else if (path == "/GetThreadList") {
                    THREADLIST threadList;
                    memset(&threadList, 0, sizeof(threadList));
                    DbgGetThreadList(&threadList);
                    
                    if (threadList.count == 0 || threadList.list == nullptr) {
                        sendHttpResponse(clientSocket, 200, "application/json",
                            "{\"count\":0,\"currentThread\":-1,\"threads\":[]}");
                        continue;
                    }
                    
                    std::stringstream jsonResponse;
                    jsonResponse << "{\"count\":" << threadList.count
                                 << ",\"currentThread\":" << threadList.CurrentThread
                                 << ",\"threads\":[";
                    
                    for (int i = 0; i < threadList.count; i++) {
                        THREADALLINFO& t = threadList.list[i];
                        
                        if (i > 0) jsonResponse << ",";
                        
                        // Map priority enum to readable string
                        const char* priorityStr = "Unknown";
                        switch (t.Priority) {
                            case _PriorityIdle:          priorityStr = "Idle"; break;
                            case _PriorityAboveNormal:   priorityStr = "AboveNormal"; break;
                            case _PriorityBelowNormal:   priorityStr = "BelowNormal"; break;
                            case _PriorityHighest:       priorityStr = "Highest"; break;
                            case _PriorityLowest:        priorityStr = "Lowest"; break;
                            case _PriorityNormal:        priorityStr = "Normal"; break;
                            case _PriorityTimeCritical:  priorityStr = "TimeCritical"; break;
                            default: break;
                        }
                        
                        // Map wait reason enum to readable string
                        const char* waitStr = "Unknown";
                        switch (t.WaitReason) {
                            case _Executive:        waitStr = "Executive"; break;
                            case _FreePage:         waitStr = "FreePage"; break;
                            case _PageIn:           waitStr = "PageIn"; break;
                            case _PoolAllocation:   waitStr = "PoolAllocation"; break;
                            case _DelayExecution:   waitStr = "DelayExecution"; break;
                            case _Suspended:        waitStr = "Suspended"; break;
                            case _UserRequest:      waitStr = "UserRequest"; break;
                            case _WrExecutive:      waitStr = "WrExecutive"; break;
                            case _WrFreePage:       waitStr = "WrFreePage"; break;
                            case _WrPageIn:         waitStr = "WrPageIn"; break;
                            case _WrPoolAllocation: waitStr = "WrPoolAllocation"; break;
                            case _WrDelayExecution: waitStr = "WrDelayExecution"; break;
                            case _WrSuspended:      waitStr = "WrSuspended"; break;
                            case _WrUserRequest:    waitStr = "WrUserRequest"; break;
                            case _WrQueue:          waitStr = "WrQueue"; break;
                            case _WrLpcReceive:     waitStr = "WrLpcReceive"; break;
                            case _WrLpcReply:       waitStr = "WrLpcReply"; break;
                            case _WrVirtualMemory:  waitStr = "WrVirtualMemory"; break;
                            case _WrPageOut:        waitStr = "WrPageOut"; break;
                            case _WrRendezvous:     waitStr = "WrRendezvous"; break;
                            default: break;
                        }
                        
                        jsonResponse << "{"
                            << "\"threadNumber\":" << t.BasicInfo.ThreadNumber << ","
                            << "\"threadId\":" << std::dec << t.BasicInfo.ThreadId << ","
                            << "\"threadName\":\"" << escapeJsonString(t.BasicInfo.threadName) << "\","
                            << "\"startAddress\":\"0x" << std::hex << t.BasicInfo.ThreadStartAddress << "\","
                            << "\"localBase\":\"0x" << std::hex << t.BasicInfo.ThreadLocalBase << "\","
                            << "\"cip\":\"0x" << std::hex << t.ThreadCip << "\","
                            << "\"suspendCount\":" << std::dec << t.SuspendCount << ","
                            << "\"priority\":\"" << priorityStr << "\","
                            << "\"waitReason\":\"" << waitStr << "\","
                            << "\"lastError\":" << std::dec << t.LastError << ","
                            << "\"cycles\":" << std::dec << t.Cycles
                            << "}";
                    }
                    
                    jsonResponse << "]}";
                    
                    // Free the thread list
                    BridgeFree(threadList.list);
                    
                    sendHttpResponse(clientSocket, 200, "application/json", jsonResponse.str());
                }
                else if (path == "/GetTebAddress") {
                    std::string tidStr = queryParams["tid"];
                    if (tidStr.empty()) {
                        sendHttpResponse(clientSocket, 400, "text/plain", "Missing 'tid' parameter (thread ID)");
                        continue;
                    }
                    
                    DWORD tid = 0;
                    try {
                        tid = (DWORD)std::stoul(tidStr, nullptr, 0);
                    } catch (const std::exception& e) {
                        sendHttpResponse(clientSocket, 400, "text/plain", "Invalid tid format");
                        continue;
                    }
                    
                    duint tebAddr = DbgGetTebAddress(tid);
                    if (tebAddr == 0) {
                        sendHttpResponse(clientSocket, 404, "application/json",
                            "{\"error\":\"TEB not found for given thread ID\"}");
                        continue;
                    }
                    
                    std::stringstream ss;
                    ss << "{\"tid\":" << std::dec << tid
                       << ",\"tebAddress\":\"0x" << std::hex << tebAddr << "\"}";
                    sendHttpResponse(clientSocket, 200, "application/json", ss.str());
                }
                else if (path == "/String/GetAt") {
                    std::string addrStr = queryParams["addr"];
                    if (addrStr.empty()) {
                        sendHttpResponse(clientSocket, 400, "application/json",
                            "{\"error\":\"Missing required 'addr' parameter\"}");
                        continue;
                    }
                    
                    duint addr = 0;
                    try {
                        addr = std::stoull(addrStr, nullptr, 16);
                    } catch (const std::exception& e) {
                        sendHttpResponse(clientSocket, 400, "application/json",
                            "{\"error\":\"Invalid address format\"}");
                        continue;
                    }
                    
                    char text[MAX_STRING_SIZE] = {0};
                    bool found = DbgGetStringAt(addr, text);
                    
                    std::stringstream ss;
                    ss << "{\"address\":\"0x" << std::hex << addr << "\","
                       << "\"found\":" << (found ? "true" : "false") << ","
                       << "\"string\":\"" << escapeJsonString(text) << "\"}";
                    sendHttpResponse(clientSocket, 200, "application/json", ss.str());
                }
                else if (path == "/Xref/Get") {
                    std::string addrStr = queryParams["addr"];
                    if (addrStr.empty()) {
                        sendHttpResponse(clientSocket, 400, "application/json",
                            "{\"error\":\"Missing required 'addr' parameter\"}");
                        continue;
                    }
                    
                    duint addr = 0;
                    try {
                        addr = std::stoull(addrStr, nullptr, 16);
                    } catch (const std::exception& e) {
                        sendHttpResponse(clientSocket, 400, "application/json",
                            "{\"error\":\"Invalid address format\"}");
                        continue;
                    }
                    
                    XREF_INFO xrefInfo = {0};
                    bool success = DbgXrefGet(addr, &xrefInfo);
                    
                    std::stringstream ss;
                    ss << "{\"address\":\"0x" << std::hex << addr << "\","
                       << "\"refcount\":" << std::dec << (success ? xrefInfo.refcount : 0) << ","
                       << "\"references\":[";
                    
                    if (success && xrefInfo.references != nullptr) {
                        for (duint i = 0; i < xrefInfo.refcount; i++) {
                            if (i > 0) ss << ",";
                            
                            const char* typeStr = "none";
                            switch (xrefInfo.references[i].type) {
                                case XREF_DATA: typeStr = "data"; break;
                                case XREF_JMP:  typeStr = "jmp"; break;
                                case XREF_CALL: typeStr = "call"; break;
                                default: typeStr = "none"; break;
                            }
                            
                            // Also try to get the string at the target address for context
                            char refString[MAX_STRING_SIZE] = {0};
                            DbgGetStringAt(xrefInfo.references[i].addr, refString);
                            
                            ss << "{\"addr\":\"0x" << std::hex << xrefInfo.references[i].addr << "\","
                               << "\"type\":\"" << typeStr << "\"";
                            
                            if (refString[0] != '\0') {
                                ss << ",\"string\":\"" << escapeJsonString(refString) << "\"";
                            }
                            
                            ss << "}";
                        }
                        
                        // Free the references array
                        BridgeFree(xrefInfo.references);
                    }
                    
                    ss << "]}";
                    sendHttpResponse(clientSocket, 200, "application/json", ss.str());
                }
                else if (path == "/Xref/Count") {
                    std::string addrStr = queryParams["addr"];
                    if (addrStr.empty()) {
                        sendHttpResponse(clientSocket, 400, "application/json",
                            "{\"error\":\"Missing required 'addr' parameter\"}");
                        continue;
                    }
                    
                    duint addr = 0;
                    try {
                        addr = std::stoull(addrStr, nullptr, 16);
                    } catch (const std::exception& e) {
                        sendHttpResponse(clientSocket, 400, "application/json",
                            "{\"error\":\"Invalid address format\"}");
                        continue;
                    }
                    
                    size_t count = DbgGetXrefCountAt(addr);
                    
                    std::stringstream ss;
                    ss << "{\"address\":\"0x" << std::hex << addr << "\","
                       << "\"count\":" << std::dec << count << "}";
                    sendHttpResponse(clientSocket, 200, "application/json", ss.str());
                }
                else if (path == "/MemoryMap") {
                    MEMMAP memmap;
                    memset(&memmap, 0, sizeof(memmap));
                    bool success = DbgMemMap(&memmap);
                    
                    if (!success || memmap.page == nullptr || memmap.count == 0) {
                        sendHttpResponse(clientSocket, 500, "application/json",
                            "{\"error\":\"Failed to get memory map\",\"pages\":[]}");
                        continue;
                    }
                    
                    std::stringstream ss;
                    ss << "{\"count\":" << memmap.count << ",\"pages\":[";
                    
                    for (int i = 0; i < memmap.count; i++) {
                        if (i > 0) ss << ",";
                        MEMPAGE& p = memmap.page[i];
                        
                        // Decode protection to string
                        const char* protectStr = "---";
                        DWORD prot = p.mbi.Protect & 0xFF;
                        if (prot == PAGE_EXECUTE_READWRITE) protectStr = "ERW";
                        else if (prot == PAGE_EXECUTE_READ) protectStr = "ER-";
                        else if (prot == PAGE_EXECUTE_WRITECOPY) protectStr = "ERW";
                        else if (prot == PAGE_READWRITE) protectStr = "-RW";
                        else if (prot == PAGE_READONLY) protectStr = "-R-";
                        else if (prot == PAGE_WRITECOPY) protectStr = "-RW";
                        else if (prot == PAGE_EXECUTE) protectStr = "E--";
                        else if (prot == PAGE_NOACCESS) protectStr = "---";
                        
                        // Decode type
                        const char* typeStr = "Unknown";
                        if (p.mbi.Type == MEM_IMAGE) typeStr = "IMG";
                        else if (p.mbi.Type == MEM_MAPPED) typeStr = "MAP";
                        else if (p.mbi.Type == MEM_PRIVATE) typeStr = "PRV";
                        
                        ss << "{\"base\":\"0x" << std::hex << (duint)p.mbi.BaseAddress << "\","
                           << "\"size\":\"0x" << std::hex << p.mbi.RegionSize << "\","
                           << "\"protect\":\"" << protectStr << "\","
                           << "\"type\":\"" << typeStr << "\","
                           << "\"info\":\"" << escapeJsonString(p.info) << "\"}";
                    }
                    
                    ss << "]}";
                    sendHttpResponse(clientSocket, 200, "application/json", ss.str());
                }
                else if (path == "/Memory/RemoteAlloc") {
                    std::string addrStr = queryParams["addr"];
                    std::string sizeStr = queryParams["size"];
                    
                    if (sizeStr.empty()) {
                        sendHttpResponse(clientSocket, 400, "application/json",
                            "{\"error\":\"Missing required 'size' parameter\"}");
                        continue;
                    }
                    
                    duint addr = 0;
                    duint size = 0;
                    try {
                        if (!addrStr.empty()) addr = std::stoull(addrStr, nullptr, 16);
                        size = std::stoull(sizeStr, nullptr, 16);
                    } catch (const std::exception& e) {
                        sendHttpResponse(clientSocket, 400, "application/json",
                            "{\"error\":\"Invalid parameter format\"}");
                        continue;
                    }
                    
                    duint result = Script::Memory::RemoteAlloc(addr, size);
                    
                    if (result == 0) {
                        sendHttpResponse(clientSocket, 500, "application/json",
                            "{\"error\":\"RemoteAlloc failed\"}");
                    } else {
                        std::stringstream ss;
                        ss << "{\"address\":\"0x" << std::hex << result << "\","
                           << "\"size\":\"0x" << std::hex << size << "\"}";
                        sendHttpResponse(clientSocket, 200, "application/json", ss.str());
                    }
                }
                else if (path == "/Memory/RemoteFree") {
                    std::string addrStr = queryParams["addr"];
                    if (addrStr.empty()) {
                        sendHttpResponse(clientSocket, 400, "application/json",
                            "{\"error\":\"Missing required 'addr' parameter\"}");
                        continue;
                    }
                    
                    duint addr = 0;
                    try {
                        addr = std::stoull(addrStr, nullptr, 16);
                    } catch (const std::exception& e) {
                        sendHttpResponse(clientSocket, 400, "application/json",
                            "{\"error\":\"Invalid address format\"}");
                        continue;
                    }
                    
                    bool success = Script::Memory::RemoteFree(addr);
                    std::stringstream ss;
                    ss << "{\"success\":" << (success ? "true" : "false") << "}";
                    sendHttpResponse(clientSocket, 200, "application/json", ss.str());
                }
                else if (path == "/GetBranchDestination") {
                    std::string addrStr = queryParams["addr"];
                    if (addrStr.empty()) {
                        sendHttpResponse(clientSocket, 400, "application/json",
                            "{\"error\":\"Missing required 'addr' parameter\"}");
                        continue;
                    }
                    
                    duint addr = 0;
                    try {
                        addr = std::stoull(addrStr, nullptr, 16);
                    } catch (const std::exception& e) {
                        sendHttpResponse(clientSocket, 400, "application/json",
                            "{\"error\":\"Invalid address format\"}");
                        continue;
                    }
                    
                    duint dest = DbgGetBranchDestination(addr);
                    
                    std::stringstream ss;
                    ss << "{\"address\":\"0x" << std::hex << addr << "\","
                       << "\"destination\":\"0x" << std::hex << dest << "\","
                       << "\"resolved\":" << (dest != 0 ? "true" : "false") << "}";
                    sendHttpResponse(clientSocket, 200, "application/json", ss.str());
                }
                else if (path == "/GetCallStack") {
                    const DBGFUNCTIONS* dbgFunc = DbgFunctions();
                    if (!dbgFunc || !dbgFunc->GetCallStackEx) {
                        sendHttpResponse(clientSocket, 500, "application/json",
                            "{\"error\":\"GetCallStackEx not available\"}");
                        continue;
                    }
                    
                    DBGCALLSTACK callstack;
                    memset(&callstack, 0, sizeof(callstack));
                    dbgFunc->GetCallStackEx(&callstack, true);
                    
                    std::stringstream ss;
                    ss << "{\"total\":" << callstack.total << ",\"entries\":[";
                    
                    if (callstack.entries != nullptr) {
                        for (int i = 0; i < callstack.total; i++) {
                            if (i > 0) ss << ",";
                            DBGCALLSTACKENTRY& e = callstack.entries[i];
                            ss << "{\"addr\":\"0x" << std::hex << e.addr << "\","
                               << "\"from\":\"0x" << std::hex << e.from << "\","
                               << "\"to\":\"0x" << std::hex << e.to << "\","
                               << "\"comment\":\"" << escapeJsonString(e.comment) << "\"}";
                        }
                        BridgeFree(callstack.entries);
                    }
                    
                    ss << "]}";
                    sendHttpResponse(clientSocket, 200, "application/json", ss.str());
                }
                else if (path == "/Breakpoint/List") {
                    std::string typeStr = queryParams["type"];
                    
                    // Default to listing all breakpoint types
                    BPXTYPE bpType = bp_normal;
                    if (typeStr == "hardware") bpType = bp_hardware;
                    else if (typeStr == "memory") bpType = bp_memory;
                    else if (typeStr == "dll") bpType = bp_dll;
                    else if (typeStr == "exception") bpType = bp_exception;
                    else if (typeStr == "normal" || typeStr.empty()) bpType = bp_normal;
                    
                    // If type is "all", we gather all types
                    bool getAllTypes = (typeStr == "all" || typeStr.empty());
                    
                    std::stringstream ss;
                    ss << "{\"breakpoints\":[";
                    
                    int totalEmitted = 0;
                    
                    // Types to iterate
                    BPXTYPE types[] = { bp_normal, bp_hardware, bp_memory, bp_dll, bp_exception };
                    int numTypes = getAllTypes ? 5 : 1;
                    BPXTYPE* typeList = getAllTypes ? types : &bpType;
                    
                    for (int t = 0; t < numTypes; t++) {
                        BPMAP bpmap;
                        memset(&bpmap, 0, sizeof(bpmap));
                        int count = DbgGetBpList(typeList[t], &bpmap);
                        
                        if (count > 0 && bpmap.bp != nullptr) {
                            for (int i = 0; i < bpmap.count; i++) {
                                if (totalEmitted > 0) ss << ",";
                                BRIDGEBP& bp = bpmap.bp[i];
                                
                                const char* bpTypeStr = "unknown";
                                switch (bp.type) {
                                    case bp_normal:    bpTypeStr = "normal"; break;
                                    case bp_hardware:  bpTypeStr = "hardware"; break;
                                    case bp_memory:    bpTypeStr = "memory"; break;
                                    case bp_dll:       bpTypeStr = "dll"; break;
                                    case bp_exception: bpTypeStr = "exception"; break;
                                    default: break;
                                }
                                
                                ss << "{\"type\":\"" << bpTypeStr << "\","
                                   << "\"addr\":\"0x" << std::hex << bp.addr << "\","
                                   << "\"enabled\":" << (bp.enabled ? "true" : "false") << ","
                                   << "\"singleshoot\":" << (bp.singleshoot ? "true" : "false") << ","
                                   << "\"active\":" << (bp.active ? "true" : "false") << ","
                                   << "\"name\":\"" << escapeJsonString(bp.name) << "\","
                                   << "\"module\":\"" << escapeJsonString(bp.mod) << "\","
                                   << "\"hitCount\":" << std::dec << bp.hitCount << ","
                                   << "\"fastResume\":" << (bp.fastResume ? "true" : "false") << ","
                                   << "\"silent\":" << (bp.silent ? "true" : "false") << ","
                                   << "\"breakCondition\":\"" << escapeJsonString(bp.breakCondition) << "\","
                                   << "\"logText\":\"" << escapeJsonString(bp.logText) << "\","
                                   << "\"commandText\":\"" << escapeJsonString(bp.commandText) << "\""
                                   << "}";
                                totalEmitted++;
                            }
                            BridgeFree(bpmap.bp);
                        }
                    }
                    
                    ss << "],\"count\":" << std::dec << totalEmitted << "}";
                    sendHttpResponse(clientSocket, 200, "application/json", ss.str());
                }
                else if (path == "/Label/Set") {
                    std::string addrStr = queryParams["addr"];
                    std::string text = queryParams["text"];
                    if (!body.empty() && text.empty()) text = body;
                    text = urlDecode(text);
                    
                    if (addrStr.empty() || text.empty()) {
                        sendHttpResponse(clientSocket, 400, "application/json",
                            "{\"error\":\"Missing required 'addr' and 'text' parameters\"}");
                        continue;
                    }
                    
                    duint addr = 0;
                    try {
                        addr = std::stoull(addrStr, nullptr, 16);
                    } catch (const std::exception& e) {
                        sendHttpResponse(clientSocket, 400, "application/json",
                            "{\"error\":\"Invalid address format\"}");
                        continue;
                    }
                    
                    bool success = DbgSetLabelAt(addr, text.c_str());
                    std::stringstream ss;
                    ss << "{\"success\":" << (success ? "true" : "false") << ","
                       << "\"address\":\"0x" << std::hex << addr << "\","
                       << "\"label\":\"" << escapeJsonString(text.c_str()) << "\"}";
                    sendHttpResponse(clientSocket, 200, "application/json", ss.str());
                }
                else if (path == "/Label/Get") {
                    std::string addrStr = queryParams["addr"];
                    if (addrStr.empty()) {
                        sendHttpResponse(clientSocket, 400, "application/json",
                            "{\"error\":\"Missing required 'addr' parameter\"}");
                        continue;
                    }
                    
                    duint addr = 0;
                    try {
                        addr = std::stoull(addrStr, nullptr, 16);
                    } catch (const std::exception& e) {
                        sendHttpResponse(clientSocket, 400, "application/json",
                            "{\"error\":\"Invalid address format\"}");
                        continue;
                    }
                    
                    char text[MAX_LABEL_SIZE] = {0};
                    bool found = DbgGetLabelAt(addr, SEG_DEFAULT, text);
                    
                    std::stringstream ss;
                    ss << "{\"address\":\"0x" << std::hex << addr << "\","
                       << "\"found\":" << (found ? "true" : "false") << ","
                       << "\"label\":\"" << escapeJsonString(text) << "\"}";
                    sendHttpResponse(clientSocket, 200, "application/json", ss.str());
                }
                else if (path == "/Label/List") {
                    ListInfo labelList;
                    bool success = Script::Label::GetList(&labelList);
                    
                    if (!success || labelList.data == nullptr) {
                        sendHttpResponse(clientSocket, 200, "application/json",
                            "{\"count\":0,\"labels\":[]}");
                        continue;
                    }
                    
                    Script::Label::LabelInfo* labels = (Script::Label::LabelInfo*)labelList.data;
                    size_t count = labelList.count;
                    
                    std::stringstream ss;
                    ss << "{\"count\":" << std::dec << count << ",\"labels\":[";
                    
                    for (size_t i = 0; i < count; i++) {
                        if (i > 0) ss << ",";
                        ss << "{\"module\":\"" << escapeJsonString(labels[i].mod) << "\","
                           << "\"rva\":\"0x" << std::hex << labels[i].rva << "\","
                           << "\"text\":\"" << escapeJsonString(labels[i].text) << "\","
                           << "\"manual\":" << (labels[i].manual ? "true" : "false") << "}";
                    }
                    
                    ss << "]}";
                    BridgeFree(labelList.data);
                    sendHttpResponse(clientSocket, 200, "application/json", ss.str());
                }
                else if (path == "/Comment/Set") {
                    std::string addrStr = queryParams["addr"];
                    std::string text = queryParams["text"];
                    if (!body.empty() && text.empty()) text = body;
                    text = urlDecode(text);
                    
                    if (addrStr.empty() || text.empty()) {
                        sendHttpResponse(clientSocket, 400, "application/json",
                            "{\"error\":\"Missing required 'addr' and 'text' parameters\"}");
                        continue;
                    }
                    
                    duint addr = 0;
                    try {
                        addr = std::stoull(addrStr, nullptr, 16);
                    } catch (const std::exception& e) {
                        sendHttpResponse(clientSocket, 400, "application/json",
                            "{\"error\":\"Invalid address format\"}");
                        continue;
                    }
                    
                    bool success = DbgSetCommentAt(addr, text.c_str());
                    std::stringstream ss;
                    ss << "{\"success\":" << (success ? "true" : "false") << ","
                       << "\"address\":\"0x" << std::hex << addr << "\"}";
                    sendHttpResponse(clientSocket, 200, "application/json", ss.str());
                }
                else if (path == "/Comment/Get") {
                    std::string addrStr = queryParams["addr"];
                    if (addrStr.empty()) {
                        sendHttpResponse(clientSocket, 400, "application/json",
                            "{\"error\":\"Missing required 'addr' parameter\"}");
                        continue;
                    }
                    
                    duint addr = 0;
                    try {
                        addr = std::stoull(addrStr, nullptr, 16);
                    } catch (const std::exception& e) {
                        sendHttpResponse(clientSocket, 400, "application/json",
                            "{\"error\":\"Invalid address format\"}");
                        continue;
                    }
                    
                    char text[MAX_COMMENT_SIZE] = {0};
                    bool found = DbgGetCommentAt(addr, text);
                    
                    std::stringstream ss;
                    ss << "{\"address\":\"0x" << std::hex << addr << "\","
                       << "\"found\":" << (found ? "true" : "false") << ","
                       << "\"comment\":\"" << escapeJsonString(text) << "\"}";
                    sendHttpResponse(clientSocket, 200, "application/json", ss.str());
                }
                else if (path == "/RegisterDump") {
                    REGDUMP_AVX512 regdump;
                    memset(&regdump, 0, sizeof(regdump));
                    bool success = DbgGetRegDumpEx(&regdump, sizeof(regdump));
                    
                    if (!success) {
                        sendHttpResponse(clientSocket, 500, "application/json",
                            "{\"error\":\"Failed to get register dump\"}");
                        continue;
                    }
                    
                    std::stringstream ss;
                    const ULONG_PTR rflags = regdump.regcontext.eflags;
                    const auto rflag = [rflags](unsigned bit) {
                        return ((rflags >> bit) & 1) != 0;
                    };
                    ss << "{";
                    
                    // General purpose registers
                    ss << "\"cax\":\"0x" << std::hex << regdump.regcontext.cax << "\","
                       << "\"ccx\":\"0x" << std::hex << regdump.regcontext.ccx << "\","
                       << "\"cdx\":\"0x" << std::hex << regdump.regcontext.cdx << "\","
                       << "\"cbx\":\"0x" << std::hex << regdump.regcontext.cbx << "\","
                       << "\"csp\":\"0x" << std::hex << regdump.regcontext.csp << "\","
                       << "\"cbp\":\"0x" << std::hex << regdump.regcontext.cbp << "\","
                       << "\"csi\":\"0x" << std::hex << regdump.regcontext.csi << "\","
                       << "\"cdi\":\"0x" << std::hex << regdump.regcontext.cdi << "\","
#ifdef _WIN64
                       << "\"r8\":\"0x" << std::hex << regdump.regcontext.r8 << "\","
                       << "\"r9\":\"0x" << std::hex << regdump.regcontext.r9 << "\","
                       << "\"r10\":\"0x" << std::hex << regdump.regcontext.r10 << "\","
                       << "\"r11\":\"0x" << std::hex << regdump.regcontext.r11 << "\","
                       << "\"r12\":\"0x" << std::hex << regdump.regcontext.r12 << "\","
                       << "\"r13\":\"0x" << std::hex << regdump.regcontext.r13 << "\","
                       << "\"r14\":\"0x" << std::hex << regdump.regcontext.r14 << "\","
                       << "\"r15\":\"0x" << std::hex << regdump.regcontext.r15 << "\","
#endif
                       << "\"cip\":\"0x" << std::hex << regdump.regcontext.cip << "\","
                       << "\"eflags\":\"0x" << std::hex << regdump.regcontext.eflags << "\","
                    
                    // Segment registers
                       << "\"gs\":\"0x" << std::hex << regdump.regcontext.gs << "\","
                       << "\"fs\":\"0x" << std::hex << regdump.regcontext.fs << "\","
                       << "\"es\":\"0x" << std::hex << regdump.regcontext.es << "\","
                       << "\"ds\":\"0x" << std::hex << regdump.regcontext.ds << "\","
                       << "\"cs\":\"0x" << std::hex << regdump.regcontext.cs << "\","
                       << "\"ss\":\"0x" << std::hex << regdump.regcontext.ss << "\","
                    
                    // Debug registers
                       << "\"dr0\":\"0x" << std::hex << regdump.regcontext.dr0 << "\","
                       << "\"dr1\":\"0x" << std::hex << regdump.regcontext.dr1 << "\","
                       << "\"dr2\":\"0x" << std::hex << regdump.regcontext.dr2 << "\","
                       << "\"dr3\":\"0x" << std::hex << regdump.regcontext.dr3 << "\","
                       << "\"dr6\":\"0x" << std::hex << regdump.regcontext.dr6 << "\","
                       << "\"dr7\":\"0x" << std::hex << regdump.regcontext.dr7 << "\","
                    
                    // RFLAGS condition codes (REGDUMP_AVX512 has no separate FLAGS; decode from eflags)
                       << "\"flags\":{"
                       << "\"ZF\":" << (rflag(6) ? "true" : "false") << ","
                       << "\"OF\":" << (rflag(11) ? "true" : "false") << ","
                       << "\"CF\":" << (rflag(0) ? "true" : "false") << ","
                       << "\"PF\":" << (rflag(2) ? "true" : "false") << ","
                       << "\"SF\":" << (rflag(7) ? "true" : "false") << ","
                       << "\"TF\":" << (rflag(8) ? "true" : "false") << ","
                       << "\"AF\":" << (rflag(4) ? "true" : "false") << ","
                       << "\"DF\":" << (rflag(10) ? "true" : "false") << ","
                       << "\"IF\":" << (rflag(9) ? "true" : "false")
                       << "},"
                    
                    // Last error/status (codes only in REGDUMP_AVX512)
                       << "\"lastError\":{\"code\":" << std::dec << regdump.lastError << ",\"name\":\"\"},"
                       << "\"lastStatus\":{\"code\":" << std::dec << regdump.lastStatus << ",\"name\":\"\"}"
                       << "}";
                    
                    sendHttpResponse(clientSocket, 200, "application/json", ss.str());
                }
                else if (path == "/Debug/SetHardwareBreakpoint") {
                    std::string addrStr = queryParams["addr"];
                    std::string typeStr = queryParams["type"]; // access, write, execute
                    
                    if (addrStr.empty()) {
                        sendHttpResponse(clientSocket, 400, "application/json",
                            "{\"error\":\"Missing required 'addr' parameter\"}");
                        continue;
                    }
                    
                    duint addr = 0;
                    try {
                        addr = std::stoull(addrStr, nullptr, 16);
                    } catch (const std::exception& e) {
                        sendHttpResponse(clientSocket, 400, "application/json",
                            "{\"error\":\"Invalid address format\"}");
                        continue;
                    }
                    
                    Script::Debug::HardwareType hwType = Script::Debug::HardwareExecute;
                    if (typeStr == "access") hwType = Script::Debug::HardwareAccess;
                    else if (typeStr == "write") hwType = Script::Debug::HardwareWrite;
                    else if (typeStr == "execute") hwType = Script::Debug::HardwareExecute;
                    
                    bool success = Script::Debug::SetHardwareBreakpoint(addr, hwType);
                    std::stringstream ss;
                    ss << "{\"success\":" << (success ? "true" : "false") << ","
                       << "\"address\":\"0x" << std::hex << addr << "\"}";
                    sendHttpResponse(clientSocket, 200, "application/json", ss.str());
                }
                else if (path == "/Debug/DeleteHardwareBreakpoint") {
                    std::string addrStr = queryParams["addr"];
                    if (addrStr.empty()) {
                        sendHttpResponse(clientSocket, 400, "application/json",
                            "{\"error\":\"Missing required 'addr' parameter\"}");
                        continue;
                    }
                    
                    duint addr = 0;
                    try {
                        addr = std::stoull(addrStr, nullptr, 16);
                    } catch (const std::exception& e) {
                        sendHttpResponse(clientSocket, 400, "application/json",
                            "{\"error\":\"Invalid address format\"}");
                        continue;
                    }
                    
                    bool success = Script::Debug::DeleteHardwareBreakpoint(addr);
                    std::stringstream ss;
                    ss << "{\"success\":" << (success ? "true" : "false") << ","
                       << "\"address\":\"0x" << std::hex << addr << "\"}";
                    sendHttpResponse(clientSocket, 200, "application/json", ss.str());
                }
                else if (path == "/EnumTcpConnections") {
                    const DBGFUNCTIONS* dbgFunc = DbgFunctions();
                    if (!dbgFunc || !dbgFunc->EnumTcpConnections) {
                        sendHttpResponse(clientSocket, 500, "application/json",
                            "{\"error\":\"EnumTcpConnections not available\"}");
                        continue;
                    }
                    
                    ListInfo tcpList;
                    bool success = dbgFunc->EnumTcpConnections(&tcpList);
                    
                    if (!success || tcpList.data == nullptr) {
                        sendHttpResponse(clientSocket, 200, "application/json",
                            "{\"count\":0,\"connections\":[]}");
                        continue;
                    }
                    
                    TCPCONNECTIONINFO* connections = (TCPCONNECTIONINFO*)tcpList.data;
                    size_t count = tcpList.count;
                    
                    std::stringstream ss;
                    ss << "{\"count\":" << std::dec << count << ",\"connections\":[";
                    
                    for (size_t i = 0; i < count; i++) {
                        if (i > 0) ss << ",";
                        ss << "{\"remoteAddress\":\"" << escapeJsonString(connections[i].RemoteAddress) << "\","
                           << "\"remotePort\":" << std::dec << connections[i].RemotePort << ","
                           << "\"localAddress\":\"" << escapeJsonString(connections[i].LocalAddress) << "\","
                           << "\"localPort\":" << std::dec << connections[i].LocalPort << ","
                           << "\"state\":\"" << escapeJsonString(connections[i].StateText) << "\"}";
                    }
                    
                    ss << "]}";
                    BridgeFree(tcpList.data);
                    sendHttpResponse(clientSocket, 200, "application/json", ss.str());
                }
                else if (path == "/Patch/List") {
                    const DBGFUNCTIONS* dbgFunc = DbgFunctions();
                    if (!dbgFunc || !dbgFunc->PatchEnum) {
                        sendHttpResponse(clientSocket, 500, "application/json",
                            "{\"error\":\"PatchEnum not available\"}");
                        continue;
                    }
                    
                    // First call to get size needed
                    size_t cbsize = 0;
                    dbgFunc->PatchEnum(nullptr, &cbsize);
                    
                    if (cbsize == 0) {
                        sendHttpResponse(clientSocket, 200, "application/json",
                            "{\"count\":0,\"patches\":[]}");
                        continue;
                    }
                    
                    size_t count = cbsize / sizeof(DBGPATCHINFO);
                    std::vector<DBGPATCHINFO> patches(count);
                    
                    if (!dbgFunc->PatchEnum(patches.data(), &cbsize)) {
                        sendHttpResponse(clientSocket, 500, "application/json",
                            "{\"error\":\"PatchEnum failed\"}");
                        continue;
                    }
                    
                    std::stringstream ss;
                    ss << "{\"count\":" << std::dec << count << ",\"patches\":[";
                    
                    for (size_t i = 0; i < count; i++) {
                        if (i > 0) ss << ",";
                        ss << "{\"module\":\"" << escapeJsonString(patches[i].mod) << "\","
                           << "\"address\":\"0x" << std::hex << patches[i].addr << "\","
                           << "\"oldByte\":\"0x" << std::hex << (int)patches[i].oldbyte << "\","
                           << "\"newByte\":\"0x" << std::hex << (int)patches[i].newbyte << "\"}";
                    }
                    
                    ss << "]}";
                    sendHttpResponse(clientSocket, 200, "application/json", ss.str());
                }
                else if (path == "/Patch/Get") {
                    std::string addrStr = queryParams["addr"];
                    if (addrStr.empty()) {
                        sendHttpResponse(clientSocket, 400, "application/json",
                            "{\"error\":\"Missing required 'addr' parameter\"}");
                        continue;
                    }
                    
                    duint addr = 0;
                    try {
                        addr = std::stoull(addrStr, nullptr, 16);
                    } catch (const std::exception& e) {
                        sendHttpResponse(clientSocket, 400, "application/json",
                            "{\"error\":\"Invalid address format\"}");
                        continue;
                    }
                    
                    const DBGFUNCTIONS* dbgFunc = DbgFunctions();
                    if (!dbgFunc) {
                        sendHttpResponse(clientSocket, 500, "application/json",
                            "{\"error\":\"DbgFunctions not available\"}");
                        continue;
                    }
                    
                    DBGPATCHINFO patchInfo;
                    memset(&patchInfo, 0, sizeof(patchInfo));
                    bool found = false;
                    
                    if (dbgFunc->PatchGetEx) {
                        found = dbgFunc->PatchGetEx(addr, &patchInfo);
                    } else if (dbgFunc->PatchGet) {
                        found = dbgFunc->PatchGet(addr);
                    }
                    
                    std::stringstream ss;
                    ss << "{\"address\":\"0x" << std::hex << addr << "\","
                       << "\"patched\":" << (found ? "true" : "false");
                    
                    if (found && dbgFunc->PatchGetEx) {
                        ss << ",\"module\":\"" << escapeJsonString(patchInfo.mod) << "\","
                           << "\"oldByte\":\"0x" << std::hex << (int)patchInfo.oldbyte << "\","
                           << "\"newByte\":\"0x" << std::hex << (int)patchInfo.newbyte << "\"";
                    }
                    
                    ss << "}";
                    sendHttpResponse(clientSocket, 200, "application/json", ss.str());
                }
                else if (path == "/EnumHandles") {
                    const DBGFUNCTIONS* dbgFunc = DbgFunctions();
                    if (!dbgFunc || !dbgFunc->EnumHandles) {
                        sendHttpResponse(clientSocket, 500, "application/json",
                            "{\"error\":\"EnumHandles not available\"}");
                        continue;
                    }
                    
                    ListInfo handleList;
                    bool success = dbgFunc->EnumHandles(&handleList);
                    
                    if (!success || handleList.data == nullptr) {
                        sendHttpResponse(clientSocket, 200, "application/json",
                            "{\"count\":0,\"handles\":[]}");
                        continue;
                    }
                    
                    HANDLEINFO* handles = (HANDLEINFO*)handleList.data;
                    size_t count = handleList.count;
                    
                    std::stringstream ss;
                    ss << "{\"count\":" << std::dec << count << ",\"handles\":[";
                    
                    for (size_t i = 0; i < count; i++) {
                        if (i > 0) ss << ",";
                        
                        // Try to get the handle name and type
                        char handleName[256] = {0};
                        char typeName[256] = {0};
                        if (dbgFunc->GetHandleName) {
                            dbgFunc->GetHandleName(handles[i].Handle, handleName, sizeof(handleName), typeName, sizeof(typeName));
                        }
                        
                        ss << "{\"handle\":\"0x" << std::hex << handles[i].Handle << "\","
                           << "\"typeNumber\":" << std::dec << (int)handles[i].TypeNumber << ","
                           << "\"grantedAccess\":\"0x" << std::hex << handles[i].GrantedAccess << "\","
                           << "\"name\":\"" << escapeJsonString(handleName) << "\","
                           << "\"typeName\":\"" << escapeJsonString(typeName) << "\"}";
                    }
                    
                    ss << "]}";
                    BridgeFree(handleList.data);
                    sendHttpResponse(clientSocket, 200, "application/json", ss.str());
                }
                
            }
            catch (const std::exception& e) {
                sendHttpResponse(clientSocket, 500, "text/plain", std::string("Internal Server Error: ") + e.what());
            }
        }
        closesocket(clientSocket);
    }
    if (g_serverSocket != INVALID_SOCKET) {
        closesocket(g_serverSocket);
        g_serverSocket = INVALID_SOCKET;
    }

    WSACleanup();
    markHttpServerStopped();
    return 0;
}

std::string readHttpRequest(SOCKET clientSocket) {
    std::string request;
    char buffer[MAX_REQUEST_SIZE];
    int timeoutMs = 3000;
    setsockopt(clientSocket, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeoutMs, sizeof(timeoutMs));
    u_long mode = 0;
    ioctlsocket(clientSocket, FIONBIO, &mode);

    while (request.find("\r\n\r\n") == std::string::npos && request.length() < MAX_REQUEST_SIZE - 1) {
        int remaining = MAX_REQUEST_SIZE - 1 - (int)request.length();
        int chunkSize = remaining < (int)sizeof(buffer) - 1 ? remaining : (int)sizeof(buffer) - 1;
        int bytesReceived = recv(clientSocket, buffer, chunkSize, 0);
        if (bytesReceived <= 0) {
            break;
        }
        buffer[bytesReceived] = '\0';
        request.append(buffer, bytesReceived);
        if (bytesReceived < chunkSize) {
            break;
        }
    }
    
    return request;
}

void parseHttpRequest(const std::string& request, std::string& method, std::string& path, std::string& query, std::string& body) {
    size_t firstLineEnd = request.find("\r\n");
    if (firstLineEnd == std::string::npos) {
        return;
    }
    
    std::string requestLine = request.substr(0, firstLineEnd);
    size_t methodEnd = requestLine.find(' ');
    if (methodEnd == std::string::npos) {
        return;
    }
    
    method = requestLine.substr(0, methodEnd);
    
    size_t urlEnd = requestLine.find(' ', methodEnd + 1);
    if (urlEnd == std::string::npos) {
        return;
    }
    
    std::string url = requestLine.substr(methodEnd + 1, urlEnd - methodEnd - 1);
    size_t queryStart = url.find('?');
    if (queryStart != std::string::npos) {
        path = url.substr(0, queryStart);
        query = url.substr(queryStart + 1);
    } else {
        path = url;
        query = "";
    }
    size_t headersEnd = request.find("\r\n\r\n");
    if (headersEnd == std::string::npos) {
        return;
    }
    body = request.substr(headersEnd + 4);
}

void sendHttpResponse(SOCKET clientSocket, int statusCode, const std::string& contentType, const std::string& responseBody) {
    std::string statusText;
    switch (statusCode) {
        case 200: statusText = "OK"; break;
        case 202: statusText = "Accepted"; break;
        case 400: statusText = "Bad Request"; break;
        case 404: statusText = "Not Found"; break;
        case 409: statusText = "Conflict"; break;
        case 500: statusText = "Internal Server Error"; break;
        default: statusText = "Unknown";
    }
    std::stringstream response;
    response << "HTTP/1.1 " << statusCode << " " << statusText << "\r\n";
    response << "Content-Type: " << contentType << "\r\n";
    response << "Content-Length: " << responseBody.length() << "\r\n";
    response << "Connection: close\r\n";
    response << "\r\n";
    response << responseBody;
    std::string responseStr = response.str();
    send(clientSocket, responseStr.c_str(), (int)responseStr.length(), 0);
}

std::unordered_map<std::string, std::string> parseQueryParams(const std::string& query) {
    std::unordered_map<std::string, std::string> params;
    
    size_t pos = 0;
    size_t nextPos;
    
    while (pos < query.length()) {
        nextPos = query.find('&', pos);
        if (nextPos == std::string::npos) {
            nextPos = query.length();
        }
        
        std::string pair = query.substr(pos, nextPos - pos);
        size_t equalPos = pair.find('=');
        
        if (equalPos != std::string::npos) {
            std::string key = pair.substr(0, equalPos);
            std::string value = pair.substr(equalPos + 1);
            params[key] = value;
        }
        
        pos = nextPos + 1;
    }
    
    return params;
}

bool cbEnableHttpServer(int argc, char* argv[]) {
    if (g_httpServerRunning) {
        _plugin_logputs("Stopping HTTP server...");
        stopHttpServer();
        _plugin_logputs("HTTP server stopped");
    } else {
        _plugin_logputs("Starting HTTP server...");
        if (startHttpServer()) {
            _plugin_logprintf("HTTP server started on port %d\n", g_httpPort);
        } else {
            _plugin_logputs("Failed to start HTTP server");
        }
    }
    return true;
}

bool cbSetHttpPort(int argc, char* argv[]) {
    if (argc < 2) {
        _plugin_logputs("Usage: httpport [port_number]");
        return false;
    }
    
    int port;
    try {
        port = std::stoi(argv[1]);
    }
    catch (const std::exception&) {
        _plugin_logputs("Invalid port number");
        return false;
    }
    
    if (port <= 0 || port > 65535) {
        _plugin_logputs("Port number must be between 1 and 65535");
        return false;
    }
    
    g_httpPort = port;
    
    if (g_httpServerRunning) {
        _plugin_logputs("Restarting HTTP server with new port...");
        stopHttpServer();
        if (startHttpServer()) {
            _plugin_logprintf("HTTP server restarted on port %d\n", g_httpPort);
        } else {
            _plugin_logputs("Failed to restart HTTP server");
        }
    } else {
        _plugin_logprintf("HTTP port set to %d\n", g_httpPort);
    }
    
    return true;
}

bool cbSetHttpHost(int argc, char* argv[]) {
    if (argc < 2) {
        _plugin_logputs("Usage: httphost [127.0.0.1|0.0.0.0|IPv4]");
        return false;
    }

    std::string host = argv[1];
    sockaddr_in testAddr;
    memset(&testAddr, 0, sizeof(testAddr));
    if (!resolveListenAddress(host, testAddr)) {
        _plugin_logputs("Invalid host. Use 127.0.0.1, 0.0.0.0, *, any, or a numeric IPv4 address.");
        return false;
    }

    g_httpHost = host;

    if (g_httpServerRunning) {
        _plugin_logputs("Restarting HTTP server with new host...");
        stopHttpServer();
        if (startHttpServer()) {
            _plugin_logprintf("HTTP server restarted on %s:%d\n", g_httpHost.c_str(), g_httpPort);
        } else {
            _plugin_logputs("Failed to restart HTTP server");
        }
    } else {
        _plugin_logprintf("HTTP host set to %s\n", g_httpHost.c_str());
    }

    return true;
}

void registerCommands() {
    _plugin_registercommand(g_pluginHandle, "httpserver", cbEnableHttpServer, 
                           "Toggle HTTP server on/off");
    _plugin_registercommand(g_pluginHandle, "httpport", cbSetHttpPort, 
                           "Set HTTP server port");
    _plugin_registercommand(g_pluginHandle, "httphost", cbSetHttpHost,
                           "Set HTTP server listen host");
}
