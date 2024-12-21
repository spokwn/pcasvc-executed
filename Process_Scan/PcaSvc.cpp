#include "..\Include.h"

std::vector<std::string> Scan_PcaSvc()
{
    __int64 pid = Get_Service_PID("PcaSvc");
    if (!pid) return { "0" };

    HANDLE phandle = OpenProcess(PROCESS_ALL_ACCESS, 0, pid);
    if (!phandle) return { "0" };

    std::vector<std::string>list; MEMORY_BASIC_INFORMATION info;

    for (static __int64 address = 0; VirtualQueryEx(phandle, (LPVOID)address, &info, sizeof(info)); address += info.RegionSize)
    {
        if (info.State != MEM_COMMIT) continue;

        std::string memory;
        memory.resize(info.RegionSize);

        if (!ReadProcessMemory(phandle, (LPVOID)address, &memory[0], info.RegionSize, 0)) continue;

        for (__int64 pos = 0; pos != std::string::npos; pos = memory.find(":\\", pos + 1))
        {
            std::string path;

            for (__int64 x = pos - 1; memory[x] > 32 && memory[x] < 123; x++)
                path.push_back(memory[x]);

            if (path[path.length() - 4] != '.') {
                continue;
            }

            list.push_back(path);
        }
    }
    return list;
}


void Get_PcaSvc_File(HANDLE hConsole)
{
    std::vector<std::string> executions = Scan_PcaSvc();
    if (executions.empty() || executions[0] == "0")
    {
        std::cout << "PcaSvc Not Found";
        return;
    }

    std::cout << "PcaSvc\n";
    std::map<std::string, int> Lmap;

    for (const std::string& path : executions)
    {
        if (Lmap[path] == 0)
        {
            Lmap[path] = 1;

            std::string signatureStatus = getDigitalSignature(path);

            if (signatureStatus == "Deleted")
            {
                SetConsoleTextAttribute(hConsole, 4);
                std::cout << "\tFile is deleted   ";

                SetConsoleTextAttribute(hConsole, 7);
                std::cout << path;
            }
            else
            {
                if (file_exists(path))
                {
                    SetConsoleTextAttribute(hConsole, 2);
                    std::cout << "\tFile is present   ";
                }
                else
                {
                    SetConsoleTextAttribute(hConsole, 4);
                    std::cout << "\tFile status unknown   ";
                }

                if (signatureStatus == "Signed    ")
                {
                    SetConsoleTextAttribute(hConsole, 2);
                }
                else
                {
                    SetConsoleTextAttribute(hConsole, 4);
                }
                std::cout << "" << signatureStatus << "   ";

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
                                std::cout << "[" << rule << "]";
                            }
                            SetConsoleTextAttribute(hConsole, 7);
                        }
                    }
                }
            }
            std::cout << std::endl;
        }
    }
}
