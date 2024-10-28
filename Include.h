#pragma once

#include <algorithm>
#include <map>
#include <vector>
#include <string>
#include <iostream>
#include <windows.h>
#include <TlHelp32.h>
#include <WinTrust.h>
#include <SoftPub.h>
#include <Psapi.h>
#include <iomanip>
#include <algorithm>
#include <thread>
#include <atomic>

#pragma comment(lib, "Wintrust.lib")
#pragma comment(lib, "Crypt32.lib")


__int64 Get_Service_PID(const char* name);
__int64 privilege(const char* priv);
void Get_PcaSvc_File(HANDLE hConsole);

std::string getDigitalSignature(const std::string& filePath);
std::vector<std::string> extract_paths(const std::string& input);
bool file_exists(const std::string& path);
std::vector<DWORD> get_all_process_ids();
std::string find_pcaclient(HANDLE process_handle);
std::string get_process_name(DWORD process_id);
std::string get_service_name(DWORD process_id);
void getLastLaunchTime(const std::string& path);
std::string getOwnPath();
bool iequals(const std::string& a, const std::string& b);

struct GenericRule {
    std::string name;
    std::string rule;
};

extern std::vector<GenericRule> genericRules;

void addGenericRule(const std::string& name, const std::string& rule);

void initializeGenericRules();

bool scan_with_yara(const std::string& path, std::vector<std::string>& matched_rules);