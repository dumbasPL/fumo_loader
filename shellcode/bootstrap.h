#pragma once
#include <Windows.h>
#include <array>

__forceinline auto get_bootstrap_shellcode(ULONG_PTR xor_key, ULONG_PTR section_virtual_offset, ULONG section_size) {
    std::array<BYTE, 67> entrypoint = {
        // constants
        0x48, 0xB9, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rcx, 0h
        0x48, 0xBA, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rdx, 0h
        0x49, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov r8, 0h

        // add image base address to constants (this removes the need for a relocation table)
        0x65, 0x48, 0x8B, 0x04, 0x25, 0x60, 0x00, 0x00, 0x00,       // mov rax, gs:[60h] ; PEB
        0x48, 0x8B, 0x40, 0x10,                                     // mov rax, [rax+10h] ; PEB.ImageBaseAddress
        0x48, 0x01, 0xC2,                                           // add rdx, rax
        0x49, 0x01, 0xC0,                                           // add r8, rax

        // save section start so we can jump to it later
        0x4C, 0x8B, 0xCA,                                           // mov r9, rdx

        // decrypt section                                          // loop1:
        0x48, 0x31, 0x0A,                                           // xor QWORD PTR [rdx], rcx
        0x48, 0x83, 0xC2, 0x08,                                     // add rdx, 8
        0x49, 0x3B, 0xD0,                                           // cmp rdx, r8
        0x72, 0xF4,                                                 // jb loop1

        // jump to section (rcx still contains the xor key)
        0x41, 0xFF, 0xE1 // jmp r9
    };

    // update constants
    *(ULONG_PTR*)&entrypoint[2] = xor_key;
    *(ULONG_PTR*)&entrypoint[12] = section_virtual_offset;
    *(ULONG_PTR*)&entrypoint[22] = section_virtual_offset + section_size;
    return entrypoint;
}