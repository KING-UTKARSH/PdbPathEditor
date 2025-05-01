#include <string>
#include <iostream>
#include <fstream>
#include <vector>
#include <iomanip>
#include <cstring>
#include <filesystem>

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <DbgHelp.h>
#include <commdlg.h>

static bool GetPEAndPdb(const std::wstring& filePath, std::vector<char>& PEData, size_t& PdbOffset)
{
    std::ifstream file(filePath, std::ios::binary | std::ios::ate);
    if (!file.is_open())
    {
        std::wcerr << L"Failed to open file: " << filePath << std::endl;
        return false;
    }

    size_t size = file.tellg();
    file.seekg(0, std::ios::beg);

    std::vector<char> buffer(size);
    if (!file.read(buffer.data(), size))
    {
        std::cerr << "Failed to read file" << std::endl;
        return false;
    }

    file.close();

    if (size < sizeof(IMAGE_DOS_HEADER))
    {
        std::cerr << "File too small to be a valid PE file" << std::endl;
        return false;
    }

    const IMAGE_DOS_HEADER* dosHeader = reinterpret_cast<const IMAGE_DOS_HEADER*>(buffer.data());
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) // "MZ" signature
    {
        std::cerr << "Not a valid PE file - missing MZ signature" << std::endl;
        return false;
    }

    if (dosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS) > size)
    {
        std::cerr << "Invalid PE header offset" << std::endl;
        return false;
    }

    PEData.clear();
    PEData = buffer;

    const IMAGE_NT_HEADERS* ntHeaders = reinterpret_cast<const IMAGE_NT_HEADERS*>(buffer.data() + dosHeader->e_lfanew);

    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) // "PE\0\0" signature
    {
        std::cerr << "Not a valid PE file - missing PE signature" << std::endl;
        return false;
    }

    if (ntHeaders->OptionalHeader.NumberOfRvaAndSizes <= IMAGE_DIRECTORY_ENTRY_DEBUG)
    {
        std::cerr << "PE file doesn't have a debug directory" << std::endl;
        return false;
    }

    const IMAGE_DATA_DIRECTORY& debugDir = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG];

    if (debugDir.VirtualAddress == 0 || debugDir.Size == 0)
    {
        std::cerr << "No debug information found" << std::endl;
        return false;
    }

    const IMAGE_SECTION_HEADER* sectionHeaders = IMAGE_FIRST_SECTION(ntHeaders);
    uint32_t debugRva = debugDir.VirtualAddress;
    uint32_t debugOffset = 0;

    for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++)
    {
        size_t sectionHeaderOffset = (char*)&sectionHeaders[i] - buffer.data();
        if (sectionHeaderOffset + sizeof(IMAGE_SECTION_HEADER) > size)
        {
            std::cerr << "File too small to read section header " << i << std::endl;
            return false;
        }

        const IMAGE_SECTION_HEADER* sectionHeader = &sectionHeaders[i];

        if (debugRva >= sectionHeader->VirtualAddress && debugRva < sectionHeader->VirtualAddress + sectionHeader->Misc.VirtualSize)
        {
            debugOffset = debugRva - sectionHeader->VirtualAddress + sectionHeader->PointerToRawData;
            break;
        }
    }

    if (debugOffset == 0)
    {
        std::cerr << "Could not locate debug directory in file" << std::endl;
        return false;
    }

    for (uint32_t i = 0; i < debugDir.Size / sizeof(IMAGE_DEBUG_DIRECTORY); i++)
    {
        size_t debugEntryOffset = debugOffset + i * sizeof(IMAGE_DEBUG_DIRECTORY);

        if (debugEntryOffset + sizeof(IMAGE_DEBUG_DIRECTORY) > size)
        {
            std::cerr << "File too small to read debug entry " << i << std::endl;
            return false;
        }

        const IMAGE_DEBUG_DIRECTORY* debugEntry = reinterpret_cast<const IMAGE_DEBUG_DIRECTORY*>(buffer.data() + debugEntryOffset);

        if (debugEntry->Type == IMAGE_DEBUG_TYPE_CODEVIEW)
        {
            if (debugEntry->PointerToRawData + sizeof(DWORD) > size)
            {
                std::cerr << "File too small to read debug data signature" << std::endl;
                continue;
            }

            const DWORD* cvSignature = reinterpret_cast<const DWORD*>(buffer.data() + debugEntry->PointerToRawData);

            // Check for RSDS signature (PDB 7.0)
            if (*cvSignature == 'SDSR') // "RSDS"
            {
                size_t pdbPathOffset = debugEntry->PointerToRawData + sizeof(DWORD) + sizeof(GUID) + sizeof(DWORD);

                if (pdbPathOffset >= size)
                {
                    std::cerr << "File too small to read PDB path" << std::endl;
                    continue;
                }
                PdbOffset = pdbPathOffset;
                return true;
            }
            // Check for NB10 signature (older PDB format)
            else if (*cvSignature == '01BN') // "NB10"
            {
                size_t pdbPathOffset = debugEntry->PointerToRawData + sizeof(DWORD) + sizeof(DWORD) + sizeof(DWORD) + sizeof(DWORD);

                if (pdbPathOffset >= size)
                {
                    std::cerr << "File too small to read PDB path" << std::endl;
                    continue;
                }

                PdbOffset = pdbPathOffset;
                return true;
            }
        }
    }

    std::cerr << "No PDB information found in debug directory" << std::endl;
    return false;
}

static bool OpenFileDialog(std::wstring& outpath)
{
    OPENFILENAMEW ofn{}; ofn.lStructSize = sizeof(ofn);

    wchar_t filePath[MAX_PATH]{};

    ofn.hwndOwner = GetConsoleWindow();
    ofn.lpstrFile = filePath;
    ofn.nMaxFile = sizeof(filePath);
    ofn.lpstrFilter = L"PE File\0*.exe;*.dll;*.sys\0All Files\0*.*\0";
    ofn.nFilterIndex = 1;
    ofn.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST;

    if (GetOpenFileNameW(&ofn))
    {
        outpath = filePath;
        return true;
    }

    return false;
}

int main()
{
    while (true)
    {
        std::cout << "Hello, Welcome to Windows PE Pdb Path modifier made by KING UTKARSH.\n" << std::endl;

        std::cout << "Please select your file." << std::endl;
        std::wstring FilePath;
        if (OpenFileDialog(FilePath))
        {
            std::wcout << L"Your selcted file -> " << FilePath << std::endl;
            std::vector<char> PEData;
            size_t PdbOffset = 0;
            if (GetPEAndPdb(FilePath, PEData, PdbOffset))
            {
                const char* pdbPath = PEData.data() + PdbOffset;

                size_t maxLen = PEData.size() - PdbOffset;
                size_t pathLen = 0;

                while (pathLen < maxLen && pdbPath[pathLen] != '\0') pathLen++;

                if (pathLen > 0 && pathLen < maxLen)
                {
                    std::string OriginalPath(pdbPath, pathLen);
                    std::cout << "Original PDB Path: " << OriginalPath << " Length: " << OriginalPath.length() << std::endl;
                    std::cout << "Please enter the new pdb string whose length is less that or equal to " << OriginalPath.length() << " > ";
                    std::string NewPdbPath;
                    std::cin >> NewPdbPath;
                    std::cout << std::endl;
                    std::cout << "User input: " << NewPdbPath << ", Length: " << NewPdbPath.length() << std::endl;
                    bool WriteSucces = false;
                    if (NewPdbPath.length() == 1 && NewPdbPath == "q")
                    {
                        std::cout << "Skipping..." << std::endl;
                    }
                    else if (NewPdbPath.length() == 1 && NewPdbPath == "0")
                    {
                        std::cout << "Zero inputed, filling null" << std::endl;
                        memset((void*)pdbPath, 0, pathLen + 1);
                        WriteSucces = true;
                    }
                    else if (NewPdbPath.length() <= pathLen)
                    {
                        memset((void*)pdbPath, 0, pathLen + 1);
                        memcpy_s((void*)pdbPath, pathLen + 1, NewPdbPath.c_str(), NewPdbPath.length() + 1);
                        WriteSucces = true;
                    }
                    else
                    {
                        std::cerr << "Invalid input" << std::endl;
                    }

                    if (WriteSucces)
                    {
                        std::filesystem::path path(FilePath);
                        std::string NewFileName = path.parent_path().string() + "\\" + path.stem().string() + std::string("_modified") + path.extension().string();
                        std::cout << "Output filename -> " << NewFileName << std::endl;
                        std::ofstream outfile(NewFileName, std::iostream::binary);
                        if (outfile.is_open())
                        {
                            outfile.write(PEData.data(), PEData.size());
                            std::cout << "Output file written succesfully" << std::endl;
                        }
                        else
                        {
                            std::cerr << "Failed to open output file" << std::endl;
                        }
                    }
                }
                else
                {
                    std::cerr << "Invalid pdb path length" << std::endl;
                }
            }
        }
        else
        {
            std::cerr << "No file selected." << std::endl;
        }
        std::cin.get();
        std::cout << "\nPress any key to back or q to exit...";
        if (getchar() == 'q') break;
        system("cls");
    }
    return 0;
}