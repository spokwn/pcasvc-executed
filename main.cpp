#include "Include.h"

int main() {
    SetConsoleTitleA("Service-Execution, forked by espouken");
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);

    if (!privilege("SeDebugPrivilege")) {
        return 1;
    }

    initializeGenericRules();
    initReplaceParser();

    std::vector<DWORD> process_ids = get_all_process_ids();
    for (DWORD process_id : process_ids) {
        HANDLE process_handle = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, process_id);
        if (process_handle) {
            std::string pcaclient_content = find_pcaclient(process_handle);
            CloseHandle(process_handle);
            if (!pcaclient_content.empty()) {
                std::vector<std::string> paths = extract_paths(pcaclient_content);
                if (!paths.empty()) {
                    std::string process_name = get_process_name(process_id);
                    std::string service_name = process_name == "svchost.exe" ? get_service_name(process_id) : "";
                    std::cout << process_name;
                    if (!service_name.empty()) {
                        std::cout << " (Service: " << service_name << ")";
                    }
                    std::cout << " (" << process_id << ")" << std::endl;

                    for (const std::string& path : paths) {
                        std::string signatureStatus = getDigitalSignature(path);
                        if (file_exists(path)) {
                            SetConsoleTextAttribute(hConsole, 2);
                            std::cout << "\tFile is present   ";
                        }
                        else {
                            SetConsoleTextAttribute(hConsole, 4);
                            std::cout << "\tFile is deleted   ";
                        }
                        if (signatureStatus == "Signed    ") {
                            SetConsoleTextAttribute(hConsole, 2);
                        }
                        else {
                            SetConsoleTextAttribute(hConsole, 4);
                        }
                        std::cout << signatureStatus << "   ";
                        SetConsoleTextAttribute(hConsole, 7);
                        std::cout << path << "   ";

                        std::string filename;
                        size_t pos = path.find_last_of("\\/");
                        if (pos != std::string::npos) {
                            filename = path.substr(pos + 1);
                        }
                        else {
                            filename = path;
                        }

                        FindReplace(filename);

                        if (signatureStatus != "Signed    ") {
                            if (!iequals(path, getOwnPath())) {
                                std::vector<std::string> matched_rules;
                                bool yara_match = scan_with_yara(path, matched_rules);
                                if (yara_match) {
                                    SetConsoleTextAttribute(hConsole, 4);
                                    for (const auto& rule : matched_rules) {
                                        std::cout << "[Flagged " << rule << "]";
                                    }
                                    SetConsoleTextAttribute(hConsole, 7);
                                }
                            }
                        }
                        std::cout << std::endl;
                    }
                    std::cout << std::endl;
                }
            }
        }
    }

    Get_PcaSvc_File(hConsole);

    DestroyReplaceParser();
    WriteAllReplacementsToFileAndPrintSummary();

    std::cout << "\n\n" << "------End------";
    std::cin.ignore();
    return 0;
}
