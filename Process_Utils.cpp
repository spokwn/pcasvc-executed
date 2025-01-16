#include "Include.h"
#include "Replaceparser.h"

std::string replaceParserDir;

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

struct ReplaceResult {
	std::string filename;
	std::string replaceType;
	std::string details;
};

static std::map<std::pair<std::string, std::string>, ReplaceResult> gLatestResults;

std::string ToLower(const std::string& str) {
	std::string result = str;
	std::transform(result.begin(), result.end(), result.begin(), ::tolower);
	return result;
}

bool WriteExeToTemp(const std::string& replaceParserDir) {
	std::string exePath = replaceParserDir + "\\replaceparser.exe";

	std::ofstream exeFile(exePath, std::ios::binary);
	if (!exeFile) {
		std::cerr << "Failed to create executable file: " << exePath << std::endl;
		return false;
	}

	exeFile.write(reinterpret_cast<const char*>(ReplaceParserHex), sizeof(ReplaceParserHex));
	exeFile.close();

	return true;
}

bool DeleteReplaceParserDir(const std::string& replaceParserDir) {
	try {
		std::filesystem::remove_all(replaceParserDir);
		return true;
	}
	catch (const std::filesystem::filesystem_error& e) {
		std::cerr << "Error deleting directory " << replaceParserDir << ": " << e.what() << std::endl;
		return false;
	}
}

bool ExecuteReplaceParser(const std::string& replaceParserDir) {
	std::string exePath = replaceParserDir + "\\replaceparser.exe";
	std::string replacesTxtPath = replaceParserDir + "\\replaces.txt";
	std::string commandLine = "\"" + exePath + "\" \"" + replacesTxtPath + "\"";

	STARTUPINFOA si;
	PROCESS_INFORMATION pi;
	ZeroMemory(&si, sizeof(si));
	si.cb = sizeof(si);
	ZeroMemory(&pi, sizeof(pi));

	HANDLE hNull = CreateFileA("NUL", GENERIC_WRITE, FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hNull == INVALID_HANDLE_VALUE) {
		std::cerr << "Failed to open NUL device." << std::endl;
		return false;
	}

	si.dwFlags |= STARTF_USESTDHANDLES;
	si.hStdOutput = hNull;
	si.hStdError = hNull;

	if (!CreateProcessA(
		NULL,
		const_cast<char*>(commandLine.c_str()),
		NULL,
		NULL,
		TRUE,
		0,
		NULL,
		replaceParserDir.c_str(),
		&si,
		&pi
	)) {
		std::cerr << "Failed to execute replaceparser.exe. Error: " << GetLastError() << std::endl;
		CloseHandle(hNull);
		return false;
	}

	WaitForSingleObject(pi.hProcess, INFINITE);
	CloseHandle(pi.hProcess);
	CloseHandle(pi.hThread);
	CloseHandle(hNull);

	return true;
}


void FindReplace(const std::string& inputFileName) {
	std::string logPath = replaceParserDir + "\\replaces.txt";
	std::string inputFileNameLower = ToLower(inputFileName);
	std::ifstream file(logPath);
	if (!file.is_open()) {
		return;
	}
	std::string line;
	while (std::getline(file, line)) {
		if (line.empty()) continue;
		std::string replaceType, pattern;
		if (line.rfind("Explorer replacement found in file: ", 0) == 0) {
			replaceType = "Explorer";
			pattern = "Explorer replacement found in file: ";
		}
		else if (line.rfind("Copy replacement found in file: ", 0) == 0) {
			replaceType = "Copy";
			pattern = "Copy replacement found in file: ";
		}
		else if (line.rfind("Type pattern found in file: ", 0) == 0) {
			replaceType = "Type";
			pattern = "Type pattern found in file: ";
		}
		else {
			continue;
		}
		size_t pos = line.find(pattern);
		if (pos == std::string::npos) continue;
		std::string foundFileName = line.substr(pos + pattern.size());
		std::string foundFileNameLower = ToLower(foundFileName);
		if (foundFileNameLower == inputFileNameLower) {
			bool openBraceFound = false;
			std::string detailsCollected;
			std::string detailsLine;
			while (std::getline(file, detailsLine)) {
				if (!openBraceFound) {
					size_t bracePos = detailsLine.find('{');
					if (bracePos != std::string::npos) {
						openBraceFound = true;
						if (bracePos + 1 < detailsLine.size()) {
							detailsCollected += detailsLine.substr(bracePos + 1) + "\n";
						}
					}
				}
				else {
					size_t closePos = detailsLine.find('}');
					if (closePos != std::string::npos) {
						if (closePos > 0) {
							detailsCollected += detailsLine.substr(0, closePos);
						}
						break;
					}
					else {
						detailsCollected += detailsLine + "\n";
					}
				}
			}
			std::pair<std::string, std::string> key = { foundFileName, replaceType };
			gLatestResults[key] = { foundFileName, replaceType, detailsCollected };
		}
	}
	file.close();
}

void WriteAllReplacementsToFileAndPrintSummary() {
	try {
		if (gLatestResults.empty()) {
			std::cout << "\n\nNo replacements found." << std::endl;
			return;
		}

		std::string outputFileName = "replaces.txt";
		std::ofstream outFile(outputFileName);

		if (!outFile.is_open()) {
			throw std::ios_base::failure("Failed to open the output file: " + outputFileName);
		}

		for (const auto& kv : gLatestResults) {
			outFile << "Found replacement type: " << kv.second.replaceType << "\n";
			outFile << "In file: " << kv.second.filename << "\n";
			outFile << "Replacement details:\n" << kv.second.details << "\n\n";
		}

		outFile.close();

		std::cout << "\n\nFound " << gLatestResults.size() << " replacements, check " << outputFileName << std::endl;

		std::string command = "start \"\" \"" + outputFileName + "\"";
		int result = std::system(command.c_str());

		if (result != 0) {
			std::cerr << "Failed to open the file: " << outputFileName << std::endl;
		}
	}
	catch (const std::ios_base::failure& e) {
		std::cerr << "I/O error: " << e.what() << std::endl;
	}
	catch (const std::exception& e) {
		std::cerr << "An unexpected error occurred: " << e.what() << std::endl;
	}
	catch (...) {
		std::cerr << "An unknown error occurred." << std::endl;
	}
}

bool initReplaceParser() {
	char tempPathBuffer[MAX_PATH];
	DWORD tempPathLen = GetTempPathA(MAX_PATH, tempPathBuffer);
	if (tempPathLen == 0 || tempPathLen > MAX_PATH) {
		std::cerr << "Failed to get temporary directory." << std::endl;
		return 1;
	}

	std::string tempPath = std::string(tempPathBuffer);
	if (tempPath.back() == '\\' || tempPath.back() == '/') {
		tempPath.pop_back();
	}

	replaceParserDir = tempPath + "\\replaceparser";
	if (!CreateDirectoryA(replaceParserDir.c_str(), NULL)) {
		if (GetLastError() != ERROR_ALREADY_EXISTS) {
			std::cerr << "Failed to create directory: " << replaceParserDir << std::endl;
			return 1;
		}
	}
	if (!WriteExeToTemp(replaceParserDir) || !ExecuteReplaceParser(replaceParserDir)) {
		return false;
	}
	return true;
}

bool DestroyReplaceParser() {
	if (!DeleteReplaceParserDir(replaceParserDir)) {
		std::cerr << "There was a problem deleting the replaceparser folder." << std::endl;
		return false;
	}
	return true;
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

static bool VerifyFileViaCatalog(LPCWSTR filePath)
{
	HANDLE hCatAdmin = NULL;
	if (!CryptCATAdminAcquireContext(&hCatAdmin, NULL, 0))
		return false;

	HANDLE hFile = CreateFileW(filePath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
	if (hFile == INVALID_HANDLE_VALUE)
	{
		CryptCATAdminReleaseContext(hCatAdmin, 0);
		return false;
	}

	DWORD dwHashSize = 0;
	if (!CryptCATAdminCalcHashFromFileHandle(hFile, &dwHashSize, NULL, 0))
	{
		CloseHandle(hFile);
		CryptCATAdminReleaseContext(hCatAdmin, 0);
		return false;
	}

	BYTE* pbHash = new BYTE[dwHashSize];
	if (!CryptCATAdminCalcHashFromFileHandle(hFile, &dwHashSize, pbHash, 0))
	{
		delete[] pbHash;
		CloseHandle(hFile);
		CryptCATAdminReleaseContext(hCatAdmin, 0);
		return false;
	}

	CloseHandle(hFile);

	CATALOG_INFO catInfo = { 0 };
	catInfo.cbStruct = sizeof(catInfo);

	HANDLE hCatInfo = CryptCATAdminEnumCatalogFromHash(hCatAdmin, pbHash, dwHashSize, 0, NULL);
	bool isCatalogSigned = false;

	while (hCatInfo && CryptCATCatalogInfoFromContext(hCatInfo, &catInfo, 0))
	{
		WINTRUST_CATALOG_INFO wtc = {};
		wtc.cbStruct = sizeof(wtc);
		wtc.pcwszCatalogFilePath = catInfo.wszCatalogFile;
		wtc.pbCalculatedFileHash = pbHash;
		wtc.cbCalculatedFileHash = dwHashSize;
		wtc.pcwszMemberFilePath = filePath;

		WINTRUST_DATA wtd = {};
		wtd.cbStruct = sizeof(wtd);
		wtd.dwUnionChoice = WTD_CHOICE_CATALOG;
		wtd.pCatalog = &wtc;
		wtd.dwUIChoice = WTD_UI_NONE;
		wtd.fdwRevocationChecks = WTD_REVOKE_NONE;
		wtd.dwProvFlags = 0;
		wtd.dwStateAction = WTD_STATEACTION_VERIFY;

		GUID action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
		LONG res = WinVerifyTrust(NULL, &action, &wtd);

		wtd.dwStateAction = WTD_STATEACTION_CLOSE;
		WinVerifyTrust(NULL, &action, &wtd);

		if (res == ERROR_SUCCESS)
		{
			isCatalogSigned = true;
			break;
		}
		hCatInfo = CryptCATAdminEnumCatalogFromHash(hCatAdmin, pbHash, dwHashSize, 0, &hCatInfo);
	}

	if (hCatInfo)
		CryptCATAdminReleaseCatalogContext(hCatAdmin, hCatInfo, 0);

	CryptCATAdminReleaseContext(hCatAdmin, 0);
	delete[] pbHash;

	return isCatalogSigned;
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
		result = "Signed    ";
		CRYPT_PROVIDER_DATA const* psProvData = WTHelperProvDataFromStateData(winTrustData.hWVTStateData);
		if (psProvData) {
			CRYPT_PROVIDER_DATA* nonConstProvData = const_cast<CRYPT_PROVIDER_DATA*>(psProvData);
			CRYPT_PROVIDER_SGNR* pProvSigner = WTHelperGetProvSignerFromChain(nonConstProvData, 0, FALSE, 0);
			if (pProvSigner) {
				CRYPT_PROVIDER_CERT* pProvCert = WTHelperGetProvCertFromChain(pProvSigner, 0);
				if (pProvCert && pProvCert->pCert) {
					char subjectName[256] = { 0 };
					CertNameToStrA(
						pProvCert->pCert->dwCertEncodingType,
						&pProvCert->pCert->pCertInfo->Subject,
						CERT_X500_NAME_STR,
						subjectName,
						sizeof(subjectName)
					);

					std::string subject(subjectName);
					std::transform(subject.begin(), subject.end(), subject.begin(), ::tolower);

					if (subject.find("manthe industries, llc") != std::string::npos ||
						subject.find("slinkware") != std::string::npos) {
						result = "Cheat Signature";
					}

					PCCERT_CONTEXT pCert = pProvCert->pCert;

					DWORD hashSize = 0;
					if (CertGetCertificateContextProperty(pCert, CERT_SHA1_HASH_PROP_ID, nullptr, &hashSize)) {
						std::vector<BYTE> hash(hashSize);
						if (CertGetCertificateContextProperty(pCert, CERT_SHA1_HASH_PROP_ID, hash.data(), &hashSize)) {
							CRYPT_HASH_BLOB hashBlob;
							hashBlob.cbData = hashSize;
							hashBlob.pbData = hash.data();

							HCERTSTORE hStore = CertOpenStore(
								CERT_STORE_PROV_SYSTEM_W,
								0,
								NULL,
								CERT_SYSTEM_STORE_CURRENT_USER | CERT_STORE_OPEN_EXISTING_FLAG,
								L"Root"
							);

							if (hStore) {
								PCCERT_CONTEXT foundCert = CertFindCertificateInStore(
									hStore,
									pCert->dwCertEncodingType,
									0,
									CERT_FIND_SHA1_HASH,
									&hashBlob,
									NULL
								);

								if (foundCert) {
									result = "Fake Signature";
									CertFreeCertificateContext(foundCert);
								}
								CertCloseStore(hStore, 0);
							}
						}
					}
				}
			}
		}
	}
	else {
		if (VerifyFileViaCatalog(wideFilePath)) {
			result = "Signed    ";
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
