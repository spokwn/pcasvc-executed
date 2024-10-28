#include "Include.h"

__int64 Get_Service_PID(const char* name)
{

	auto shandle = OpenSCManagerA(0, 0, 0),
		shandle_ = OpenServiceA(shandle, name, SERVICE_QUERY_STATUS);

	if (!shandle || !shandle_) return 0;

	SERVICE_STATUS_PROCESS ssp{}; DWORD bytes;

	bool query = QueryServiceStatusEx(shandle_, SC_STATUS_PROCESS_INFO, (LPBYTE)&ssp, sizeof(ssp), &bytes);

	CloseServiceHandle(shandle);
	CloseServiceHandle(shandle_);
	return ssp.dwProcessId;

}

__int64 privilege(const char* priv)
{
	HANDLE thandle;
	LUID identifier;
	TOKEN_PRIVILEGES privileges{};

	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &thandle)) {
		std::cerr << "OpenProcessToken error: " << GetLastError() << std::endl;
		return 0;
	}

	if (!LookupPrivilegeValueA(nullptr, priv, &identifier)) {
		std::cerr << "LookupPrivilegeValueA error: " << GetLastError() << std::endl;
		CloseHandle(thandle);
		return 0;
	}

	privileges.PrivilegeCount = 1;
	privileges.Privileges[0].Luid = identifier;
	privileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

	if (!AdjustTokenPrivileges(thandle, FALSE, &privileges, sizeof(privileges), nullptr, nullptr)) {
		std::cerr << "AdjustTokenPrivileges error: " << GetLastError() << std::endl;
		CloseHandle(thandle);
		return 0;
	}

	DWORD error = GetLastError();
	if (error == ERROR_NOT_ALL_ASSIGNED) {
		std::cerr << "privileges error at assign." << std::endl;
		CloseHandle(thandle);
		return 0;
	}

	CloseHandle(thandle);
	return 1;
}

std::vector<std::string> extract_paths(const std::string& input) {
	std::vector<std::string> paths;
	size_t pos = 0;
	while ((pos = input.find(",MonitorProcess,", pos)) != std::string::npos) {
		size_t start = pos + 16;
		size_t end = input.find(',', start);
		std::string path = input.substr(start, end - start);
		if (path.length() >= 3 && isalpha(path[0]) && path[1] == ':' && (path[2] == '\\' || path[2] == '/')) {
			paths.push_back(path);
		}
		pos = end;
	}
	return paths;
}

bool file_exists(const std::string& path) {
	return GetFileAttributesA(path.c_str()) != INVALID_FILE_ATTRIBUTES;
}

std::vector<DWORD> get_all_process_ids() {
	std::vector<DWORD> process_ids;

	DWORD process_array[4096], needed_bytes;
	if (EnumProcesses(process_array, sizeof(process_array), &needed_bytes)) {
		DWORD process_count = needed_bytes / sizeof(DWORD);
		for (DWORD i = 0; i < process_count; i++) {
			if (process_array[i] != 0) {
				process_ids.push_back(process_array[i]);
			}
		}
	}

	return process_ids;
}

std::string getOwnPath() {
	char buffer[MAX_PATH];
	DWORD filename = GetModuleFileNameA(NULL, buffer, MAX_PATH);

	return std::string(buffer, filename);
}
bool iequals(const std::string& a, const std::string& b) {
	return (a.size() == b.size()) &&
		std::equal(a.begin(), a.end(), b.begin(),
			[](char a, char b) {
				return std::tolower(a) == std::tolower(b);
			});
}


std::string find_pcaclient(HANDLE process_handle) {
	SYSTEM_INFO sys_info;
	GetSystemInfo(&sys_info);

	MEMORY_BASIC_INFORMATION mbi;
	LPCVOID address = sys_info.lpMinimumApplicationAddress;

	while (address < sys_info.lpMaximumApplicationAddress) {
		if (VirtualQueryEx(process_handle, address, &mbi, sizeof(mbi)) == sizeof(mbi)) {
			if (mbi.State == MEM_COMMIT && (mbi.Protect & PAGE_READWRITE) && !(mbi.Protect & PAGE_GUARD)) {
				std::string buffer(mbi.RegionSize, '\0');
				SIZE_T bytesRead;
				if (ReadProcessMemory(process_handle, mbi.BaseAddress, &buffer[0], mbi.RegionSize, &bytesRead)) {
					buffer.resize(bytesRead);
					size_t pos = buffer.find("TRACE,");
					if (pos != std::string::npos) {
						return buffer.substr(pos);
					}
				}
			}
			address = (LPBYTE)mbi.BaseAddress + mbi.RegionSize;
		}
		else {
			break;
		}
	}

	return "";
}

std::string get_process_name(DWORD process_id) {
	HANDLE process_handle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, process_id);
	if (process_handle) {
		CHAR process_name[MAX_PATH];
		GetModuleBaseNameA(process_handle, NULL, process_name, MAX_PATH);
		CloseHandle(process_handle);
		return std::string(process_name);
	}
	return "";
}

std::string get_service_name(DWORD process_id) {
	SC_HANDLE sc_manager = OpenSCManager(NULL, NULL, SC_MANAGER_ENUMERATE_SERVICE);
	if (sc_manager) {
		DWORD bytes_needed;
		DWORD service_count;
		EnumServicesStatusExA(sc_manager, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_STATE_ALL, NULL, 0, &bytes_needed, &service_count, NULL, NULL);
		std::vector<BYTE> buffer(bytes_needed);
		EnumServicesStatusExA(sc_manager, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_STATE_ALL, buffer.data(), bytes_needed, &bytes_needed, &service_count, NULL, NULL);
		LPENUM_SERVICE_STATUS_PROCESSA services = (LPENUM_SERVICE_STATUS_PROCESSA)buffer.data();
		for (DWORD i = 0; i < service_count; ++i) {
			if (services[i].ServiceStatusProcess.dwProcessId == process_id) {
				CloseServiceHandle(sc_manager);
				return std::string(services[i].lpServiceName);
			}
		}
		CloseServiceHandle(sc_manager);
	}
	return "";
}

std::string getDigitalSignature(const std::string& filePath) {
	WCHAR wideFilePath[MAX_PATH];
	MultiByteToWideChar(CP_UTF8, 0, filePath.c_str(), -1, wideFilePath, MAX_PATH);

	if (GetFileAttributesW(wideFilePath) == INVALID_FILE_ATTRIBUTES) {
		return "Deleted";
	}

	WINTRUST_FILE_INFO fileInfo;
	ZeroMemory(&fileInfo, sizeof(fileInfo));
	fileInfo.cbStruct = sizeof(WINTRUST_FILE_INFO);
	fileInfo.pcwszFilePath = wideFilePath;

	GUID guidAction = WINTRUST_ACTION_GENERIC_VERIFY_V2;

	WINTRUST_DATA winTrustData;
	ZeroMemory(&winTrustData, sizeof(winTrustData));
	winTrustData.cbStruct = sizeof(winTrustData);
	winTrustData.dwUIChoice = WTD_UI_NONE;
	winTrustData.fdwRevocationChecks = WTD_REVOKE_NONE;
	winTrustData.dwUnionChoice = WTD_CHOICE_FILE;
	winTrustData.dwStateAction = WTD_STATEACTION_VERIFY;
	winTrustData.pFile = &fileInfo;

	LONG lStatus = WinVerifyTrust(NULL, &guidAction, &winTrustData);

	std::string result = "Not signed";

	if (lStatus == ERROR_SUCCESS) {
		CRYPT_PROVIDER_DATA const* psProvData = WTHelperProvDataFromStateData(winTrustData.hWVTStateData);
		if (psProvData) {
			CRYPT_PROVIDER_DATA* nonConstProvData = const_cast<CRYPT_PROVIDER_DATA*>(psProvData);
			CRYPT_PROVIDER_SGNR* pProvSigner = WTHelperGetProvSignerFromChain(nonConstProvData, 0, FALSE, 0);
			if (pProvSigner) {
				CRYPT_PROVIDER_CERT* pProvCert = WTHelperGetProvCertFromChain(pProvSigner, 0);
				if (pProvCert && pProvCert->pCert) {
					char subjectName[256];
					CertNameToStrA(pProvCert->pCert->dwCertEncodingType,
						&pProvCert->pCert->pCertInfo->Subject,
						CERT_X500_NAME_STR,
						subjectName,
						sizeof(subjectName));

					std::string subject(subjectName);
					std::transform(subject.begin(), subject.end(), subject.begin(), ::tolower);

					if (subject.find("manthe industries, llc") != std::string::npos) {
						result = "Not signed (vapeclient)";
					}
					else if (subject.find("slinkware") != std::string::npos) {
						result = "Not signed (slinky)";
					}
					else {
						result = "Signed    ";
					}
				}
			}
		}
	}

	winTrustData.dwStateAction = WTD_STATEACTION_CLOSE;
	WinVerifyTrust(NULL, &guidAction, &winTrustData);

	return result;
}

void getLastLaunchTime(const std::string& path) {
	HANDLE hFile = CreateFileA(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
	if (hFile == INVALID_HANDLE_VALUE) {
		return;
	}

	FILETIME creationTime, lastAccessTime, lastWriteTime;
	if (!GetFileTime(hFile, &creationTime, &lastAccessTime, &lastWriteTime)) {
		CloseHandle(hFile);
		return;
	}

	SYSTEMTIME stUTC, stLocal;
	FileTimeToSystemTime(&lastAccessTime, &stUTC);
	SystemTimeToTzSpecificLocalTime(nullptr, &stUTC, &stLocal);

	std::cout << "Last acces: (" << stLocal.wDay << "/" << stLocal.wMonth << "/" << stLocal.wYear << " " << stLocal.wHour << ":" << std::setw(2) << std::setfill('0') << stLocal.wMinute << ")   ";

	CloseHandle(hFile);
}

/* end chatGPT*/