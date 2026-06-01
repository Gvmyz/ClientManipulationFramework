#include "DllInjection.h"

#include <cstdint>
#include <cstring>
#include <fstream>
#include <vector>

#include <TlHelp32.h>

#include "ProcessMemory.h"
#include "ProcessThread.h"
#include "ModuleResolver.h"

namespace {
	// Passed as the thread argument to the remote loader stub.
	struct LoaderParams {
		std::uintptr_t image_base;  // remote base of the mapped image (HMODULE)
		std::uintptr_t dll_main;    // absolute VA of DllMain in the remote process
	};

	// x64 shellcode — thread entry, RCX = LoaderParams*
	// Calls DllMain(image_base, DLL_PROCESS_ATTACH, NULL) then returns DllMain's result.
	//
	// Microsoft x64 ABI: at the moment a CALL is executed, RSP must be 16-byte aligned.
	// The stub itself is entered via a CALL (from BaseThreadInitThunk), so on entry
	//   RSP = 16n - 8
	// We need RSP = 16n right before `call rax`. We also need 32 bytes of shadow space
	// above the return address. Total adjustment: 32 (shadow) + 8 (realignment) = 0x28.
	//
	//   entry:                RSP = 16n - 8
	//   sub rsp, 0x28  (40):  RSP = 16n - 48 = 16(n-3)       ; aligned
	//   call rax              ; ABI-correct
	constexpr std::uint8_t k_loader_stub[] = {
		0x48, 0x83, 0xEC, 0x28,        // sub  rsp, 0x28 <- shadow space + alignment
		0x48, 0x8B, 0x41, 0x08,        // mov  rax, [rcx+0x08]  ; dll_main ptr
		0x45, 0x33, 0xC0,              // xor  r8d, r8d          ; lpvReserved = NULL
		0xBA, 0x01, 0x00, 0x00, 0x00,  // mov  edx, 1            ; DLL_PROCESS_ATTACH
		0x48, 0x8B, 0x09,              // mov  rcx, [rcx]        ; hinstDLL
		0xFF, 0xD0,                    // call rax
		0x48, 0x83, 0xC4, 0x28,        // add  rsp, 0x28
		0xC3                           // ret
	};

	// x64 shellcode for thread hijacking — entered with arbitrary register/RSP state
	// (whatever the hijacked thread had at the moment SuspendThread + SetThreadContext
	// redirected its RIP here). Calls LoadLibraryW(dll_path) and then jumps back to
	// the thread's original RIP, leaving every register, flag, and the stack pointer
	// exactly as the thread expects.
	//
	// Three 64-bit immediates are patched in at injection time:
	//   - offset 27: absolute VA of the wide DLL-path string (sits right after this stub)
	//   - offset 37: absolute VA of LoadLibraryW in the target (same as in injector, per-boot ASLR)
	//   - offset 67: original RIP captured via GetThreadContext
	//
	// Layout of the stack across the call:
	//   1. Push RFLAGS + all volatile regs (rax, rcx, rdx, r8-r11) + r12.
	//   2. Stash post-push RSP in r12 (non-volatile, preserved by LoadLibraryW).
	//   3. AND rsp, -0x10 then sub 0x20 → 16-aligned with 32 bytes of shadow space.
	//   4. Call LoadLibraryW.
	//   5. Restore RSP via r12, pop all saved registers + flags.
	//   6. push/xchg/ret dance to jump to the original RIP without leaving RAX
	//      clobbered (we just popped it; the indirect jump would normally need a reg).

	// Save volatile registers but the others are given back to original state by LoadLibraryW's calling convention. We also save R12, which we use to stash the post-push RSP for later restoration.
	constexpr std::uint8_t k_hijack_stub[] = {
		/* +00 */ 0x9C,                                              // pushfq
		/* +01 */ 0x50,                                              // push rax
		/* +02 */ 0x51,                                              // push rcx
		/* +03 */ 0x52,                                              // push rdx
		/* +04 */ 0x41, 0x50,                                        // push r8
		/* +06 */ 0x41, 0x51,                                        // push r9
		/* +08 */ 0x41, 0x52,                                        // push r10
		/* +10 */ 0x41, 0x53,                                        // push r11
		/* +12 */ 0x41, 0x54,                                        // push r12
		/* +14 */ 0x49, 0x89, 0xE4,                                  // mov r12, rsp
		/* +17 */ 0x48, 0x83, 0xE4, 0xF0,                            // and rsp, -0x10
		/* +21 */ 0x48, 0x83, 0xEC, 0x20,                            // sub rsp, 0x20    ; shadow space
		/* +25 */ 0x48, 0xB9,                                        // mov rcx, imm64   ; dll path
		/* +27 */ 0,0,0,0,0,0,0,0,                                   //                  <-- patch (dll_path VA)
		/* +35 */ 0x48, 0xB8,                                        // mov rax, imm64   ; LoadLibraryW
		/* +37 */ 0,0,0,0,0,0,0,0,                                   //                  <-- patch (LoadLibraryW VA)
		/* +45 */ 0xFF, 0xD0,                                        // call rax
		/* +47 */ 0x4C, 0x89, 0xE4,                                  // mov rsp, r12     ; restore RSP
		/* +50 */ 0x41, 0x5C,                                        // pop r12
		/* +52 */ 0x41, 0x5B,                                        // pop r11
		/* +54 */ 0x41, 0x5A,                                        // pop r10
		/* +56 */ 0x41, 0x59,                                        // pop r9
		/* +58 */ 0x41, 0x58,                                        // pop r8
		/* +60 */ 0x5A,                                              // pop rdx
		/* +61 */ 0x59,                                              // pop rcx
		/* +62 */ 0x58,                                              // pop rax
		/* +63 */ 0x9D,                                              // popfq
		/* +64 */ 0x50,                                              // push rax         ; stash restored rax
		/* +65 */ 0x48, 0xB8,                                        // mov rax, imm64   ; original RIP
		/* +67 */ 0,0,0,0,0,0,0,0,                                   //                  <-- patch (orig RIP)
		/* +75 */ 0x48, 0x87, 0x04, 0x24,                            // xchg rax, [rsp]  ; swap: [rsp]=orig_rip, rax=orig rax
		/* +79 */ 0xC3                                               // ret              ; jumps to orig_rip, rsp back to original
	};

	constexpr std::size_t k_hijack_dll_path_offset = 27;
	constexpr std::size_t k_hijack_loadlibrary_offset = 37;
	constexpr std::size_t k_hijack_origrip_offset = 67;
}

namespace PT::DllInjection {
	std::optional<DWORD> inject_dll_loadlibrary(const WinHandle& process, const std::wstring_view dll_path) {
		if (!process || dll_path.empty()) return std::nullopt;

		const SIZE_T path_size = (dll_path.size() + 1) * sizeof(wchar_t);

		void* remote_path = PT::ProcessMemory::remote_alloc(process, path_size, PAGE_READWRITE);

		if (!remote_path) return std::nullopt;

		if (!PT::ProcessMemory::remote_write(process, remote_path, dll_path.data(), path_size)) {
			PT::ProcessMemory::remote_free(process, remote_path);
			return std::nullopt;
		}

		auto load_library = reinterpret_cast<LPTHREAD_START_ROUTINE>(PT::ModuleResolver::resolve_local_function(L"kernel32.dll", "LoadLibraryW"));

		if (!load_library) {
			PT::ProcessMemory::remote_free(process, remote_path);
			return std::nullopt;
		}

		auto thread = PT::ProcessThread::create_remote_thread(process, load_library, remote_path);

		if (!thread) {
			PT::ProcessMemory::remote_free(process, remote_path);
			return std::nullopt;
		}

		if (PT::ProcessThread::wait_for_thread(thread) != WAIT_OBJECT_0) {
			PT::ProcessMemory::remote_free(process, remote_path);
			return std::nullopt;
		}

		DWORD exit_code = 0;
		if (!PT::ProcessThread::get_thread_exit_code(thread, exit_code) || exit_code == 0) {
			PT::ProcessMemory::remote_free(process, remote_path);
			return std::nullopt;
		}

		PT::ProcessMemory::remote_free(process, remote_path);

		if (exit_code == 0) return std::nullopt; // LoadLibraryW returns NULL on failure

		return exit_code; // The exit code is the base address of the loaded module in the target process
	}

	std::optional<std::uintptr_t> inject_dll_manualmap(const WinHandle& process, const std::wstring_view dll_path) {
		if (!process || dll_path.empty()) return std::nullopt;

		// --- Read the DLL from disk into a raw file buffer ---
		std::ifstream file(std::wstring(dll_path), std::ios::binary | std::ios::ate);
		if (!file.is_open()) return std::nullopt;

		const auto file_size = static_cast<std::size_t>(file.tellg());
		file.seekg(0);
		std::vector<std::uint8_t> file_buf(file_size);
		if (!file.read(reinterpret_cast<char*>(file_buf.data()), static_cast<std::streamsize>(file_size)))
			return std::nullopt;

		// --- Parse and validate PE headers ---
		PIMAGE_DOS_HEADER dos_hdr = reinterpret_cast<PIMAGE_DOS_HEADER>(file_buf.data());
		if (dos_hdr->e_magic != IMAGE_DOS_SIGNATURE) return std::nullopt;

		PIMAGE_NT_HEADERS nt_hdrs = reinterpret_cast<PIMAGE_NT_HEADERS>(file_buf.data() + dos_hdr->e_lfanew);
		if (nt_hdrs->Signature != IMAGE_NT_SIGNATURE) return std::nullopt;
		if (nt_hdrs->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64) return std::nullopt;

		const DWORD image_size = nt_hdrs->OptionalHeader.SizeOfImage;
		const DWORD headers_size = nt_hdrs->OptionalHeader.SizeOfHeaders;
		const DWORD entry_point_rva = nt_hdrs->OptionalHeader.AddressOfEntryPoint;
		const auto  pref_base = static_cast<std::uintptr_t>(nt_hdrs->OptionalHeader.ImageBase);

		// --- Build a locally-mapped copy (sections at their virtual addresses) ---
		std::vector<std::uint8_t> image(image_size, 0);
		std::memcpy(image.data(), file_buf.data(), headers_size);

		PIMAGE_SECTION_HEADER sections = IMAGE_FIRST_SECTION(nt_hdrs);
		for (WORD i = 0; i < nt_hdrs->FileHeader.NumberOfSections; ++i) {
			if (sections[i].SizeOfRawData == 0) continue;
			std::memcpy(
				image.data() + sections[i].VirtualAddress,
				file_buf.data() + sections[i].PointerToRawData,
				sections[i].SizeOfRawData
			);
		}

		// --- Allocate remote memory for the mapped image ---
		void* remote_base = PT::ProcessMemory::remote_alloc(process, image_size, PAGE_EXECUTE_READWRITE);
		if (!remote_base) return std::nullopt;
		const auto remote_addr = reinterpret_cast<std::uintptr_t>(remote_base);

		// --- Apply base relocations (delta = how much the actual base differs from preferred) ---
		const std::uintptr_t delta = remote_addr - pref_base;
		if (delta != 0) {
			const auto& reloc_dir = nt_hdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
			if (reloc_dir.VirtualAddress != 0 && reloc_dir.Size != 0) {
				auto* block = reinterpret_cast<PIMAGE_BASE_RELOCATION>(image.data() + reloc_dir.VirtualAddress);
				const auto* reloc_end = reinterpret_cast<const std::uint8_t*>(block) + reloc_dir.Size;

				while (reinterpret_cast<const std::uint8_t*>(block) < reloc_end && block->SizeOfBlock > 0) {
					const DWORD  num_entries = (block->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
					const WORD* entries = reinterpret_cast<const WORD*>(block + 1);

					for (DWORD j = 0; j < num_entries; ++j) {
						const WORD type = entries[j] >> 12;
						const WORD offset = entries[j] & 0x0FFF;

						if (type == IMAGE_REL_BASED_DIR64) {
							auto* patch = reinterpret_cast<std::uint64_t*>(
								image.data() + block->VirtualAddress + offset);
							*patch += static_cast<std::uint64_t>(delta);
						} else if (type == IMAGE_REL_BASED_HIGHLOW) {
							auto* patch = reinterpret_cast<std::uint32_t*>(
								image.data() + block->VirtualAddress + offset);
							*patch += static_cast<std::uint32_t>(delta);
						}
						// IMAGE_REL_BASED_ABSOLUTE (0) = padding entry, skip
					}

					block = reinterpret_cast<PIMAGE_BASE_RELOCATION>(
						reinterpret_cast<std::uint8_t*>(block) + block->SizeOfBlock);
				}
			}
		}

		// --- Resolve imports: write function addresses into the local IAT copy ---
		// System DLLs (kernel32, user32, ...) load at the same VA in all processes on the
		// same boot session, so addresses resolved locally are valid in the target.
		const auto& import_dir = nt_hdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
		if (import_dir.VirtualAddress != 0) {
			auto* desc = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(image.data() + import_dir.VirtualAddress);
			for (; desc->Name != 0; ++desc) {
				const char* mod_name = reinterpret_cast<const char*>(image.data() + desc->Name);
				HMODULE hmod = LoadLibraryA(mod_name);
				if (!hmod) {
					PT::ProcessMemory::remote_free(process, remote_base);
					return std::nullopt;
				}

				// Use the INT (OriginalFirstThunk) for name/ordinal lookup,
				// patch the IAT (FirstThunk) with resolved addresses.
				const DWORD int_rva = desc->OriginalFirstThunk ? desc->OriginalFirstThunk : desc->FirstThunk;
				auto* thunk_int = reinterpret_cast<PIMAGE_THUNK_DATA>(image.data() + int_rva);
				auto* thunk_iat = reinterpret_cast<PIMAGE_THUNK_DATA>(image.data() + desc->FirstThunk);

				for (; thunk_int->u1.AddressOfData != 0; ++thunk_int, ++thunk_iat) {
					FARPROC func_addr = nullptr;
					if (IMAGE_SNAP_BY_ORDINAL(thunk_int->u1.Ordinal)) {
						func_addr = GetProcAddress(hmod,
												   reinterpret_cast<LPCSTR>(IMAGE_ORDINAL(thunk_int->u1.Ordinal)));
					} else {
						const auto* ibn = reinterpret_cast<PIMAGE_IMPORT_BY_NAME>(
							image.data() + thunk_int->u1.AddressOfData);
						func_addr = GetProcAddress(hmod, ibn->Name);
					}

					if (!func_addr) {
						PT::ProcessMemory::remote_free(process, remote_base);
						return std::nullopt;
					}

					thunk_iat->u1.Function = reinterpret_cast<ULONGLONG>(func_addr);
				}
			}
		}

		// --- Copy the fully-patched image into the target process ---
		if (!PT::ProcessMemory::remote_write(process, remote_base, image.data(), image_size)) {
			PT::ProcessMemory::remote_free(process, remote_base);
			return std::nullopt;
		}

		// --- Force the target to load each imported DLL ---
		// We resolved import addresses from the injector's address space. For system DLLs
		// (kernel32, user32, ...) ASLR is per-boot, not per-process, so those addresses
		// are also valid in the target — but ONLY if the same DLL is actually mapped
		// there. If e.g. user32 isn't already loaded in the target, the IAT slots we
		// wrote point into unmapped memory and the first indirect call crashes the target.
		//
		// Drive a remote LoadLibraryA per imported DLL, reusing the name string that
		// already lives at remote_base + desc->Name inside the mapped image.
		if (import_dir.VirtualAddress != 0) {
			auto load_library_a = reinterpret_cast<LPTHREAD_START_ROUTINE>(
				PT::ModuleResolver::resolve_local_function(L"kernel32.dll", "LoadLibraryA"));
			if (!load_library_a) {
				PT::ProcessMemory::remote_free(process, remote_base);
				return std::nullopt;
			}

			auto* desc = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(image.data() + import_dir.VirtualAddress);
			for (; desc->Name != 0; ++desc) {
				void* remote_name = reinterpret_cast<void*>(remote_addr + desc->Name);
				auto load_thread = PT::ProcessThread::create_remote_thread(process, load_library_a, remote_name);
				if (!load_thread) {
					PT::ProcessMemory::remote_free(process, remote_base);
					return std::nullopt;
				}
				if (PT::ProcessThread::wait_for_thread(load_thread) != WAIT_OBJECT_0) {
					PT::ProcessMemory::remote_free(process, remote_base);
					return std::nullopt;
				}
				// LoadLibraryA returns the HMODULE; thread exit code is its low 32 bits.
				// We don't strictly require it — if the local resolution succeeded the DLL
				// exists on disk — but a 0 here means the call failed outright in the target.
				DWORD load_exit = 0;
				if (!PT::ProcessThread::get_thread_exit_code(load_thread, load_exit) || load_exit == 0) {
					PT::ProcessMemory::remote_free(process, remote_base);
					return std::nullopt;
				}
			}
		}

		// --- Call DllMain via a small loader stub executed as a remote thread ---
		// The stub receives a LoaderParams* in RCX (the thread argument).
		if (entry_point_rva == 0) {
			// No DllMain — nothing to call, but the image is mapped. Treat as success.
			return remote_addr;
		}
		const auto dll_main_addr = remote_addr + entry_point_rva;

		LoaderParams params{remote_addr, dll_main_addr};

		constexpr std::size_t stub_size = sizeof(k_loader_stub);
		constexpr std::size_t params_size = sizeof(LoaderParams);

		// POSSIBLY Set per-section protections (More real-life)
		void* remote_stub = PT::ProcessMemory::remote_alloc(
			process, stub_size + params_size, PAGE_EXECUTE_READWRITE);
		if (!remote_stub) {
			PT::ProcessMemory::remote_free(process, remote_base);
			return std::nullopt;
		}

		void* remote_params = reinterpret_cast<void*>(
			reinterpret_cast<std::uintptr_t>(remote_stub) + stub_size);

		const bool written =
			PT::ProcessMemory::remote_write(process, remote_stub, k_loader_stub, stub_size) &&
			PT::ProcessMemory::remote_write(process, remote_params, &params, params_size);

		if (!written) {
			PT::ProcessMemory::remote_free(process, remote_stub);
			PT::ProcessMemory::remote_free(process, remote_base);
			return std::nullopt;
		}

		auto thread = PT::ProcessThread::create_remote_thread(
			process,
			reinterpret_cast<LPTHREAD_START_ROUTINE>(remote_stub),
			remote_params
		);

		if (!thread) {
			PT::ProcessMemory::remote_free(process, remote_stub);
			PT::ProcessMemory::remote_free(process, remote_base);
			return std::nullopt;
		}

		const bool waited = PT::ProcessThread::wait_for_thread(thread) == WAIT_OBJECT_0;

		// Read the stub thread exit code (= DllMain's return value, or an exception code
		// like 0xC0000005 if the thread crashed). Treat anything other than TRUE as failure.
		DWORD stub_exit = 0;
		const bool got_exit = PT::ProcessThread::get_thread_exit_code(thread, stub_exit);

		PT::ProcessMemory::remote_free(process, remote_stub);

		if (!waited || !got_exit || stub_exit != static_cast<DWORD>(TRUE)) {
			PT::ProcessMemory::remote_free(process, remote_base);
			return std::nullopt;
		}

		return remote_addr;
	}

	std::optional<DWORD> inject_dll_threadhijack(const WinHandle& process, const std::wstring_view dll_path) {
		if (!process || dll_path.empty()) return std::nullopt;

		const DWORD pid = GetProcessId(process.get());
		if (pid == 0) return std::nullopt;

		// Find a thread in the target we can open with the required rights
		WinHandle thread{};
		DWORD hijacked_tid = 0;
		{
			WinHandle snap{CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0)};
			if (!snap) return std::nullopt;

			THREADENTRY32 te{};
			te.dwSize = sizeof(te);
			if (Thread32First(snap.get(), &te)) {
				do {
					if (te.th32OwnerProcessID != pid) continue;

					HANDLE h = OpenThread(
						THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_QUERY_INFORMATION,
						FALSE,
						te.th32ThreadID
					);
					if (h) {
						thread = WinHandle(h);
						hijacked_tid = te.th32ThreadID;
						break;
					}
				} while (Thread32Next(snap.get(), &te));
			}
		}
		if (!thread) return std::nullopt;

		// Resolve LoadLibraryW locally (per-boot ASLR for kernel32 means the VA matches in target)
		const auto load_library_w = PT::ModuleResolver::resolve_local_function(L"kernel32.dll", "LoadLibraryW");
		if (!load_library_w) return std::nullopt;

		// Suspend the thread and snapshot its context
		if (SuspendThread(thread.get()) == static_cast<DWORD>(-1)) return std::nullopt;

		alignas(16) CONTEXT ctx {};
		ctx.ContextFlags = CONTEXT_ALL;
		if (!GetThreadContext(thread.get(), &ctx)) {
			ResumeThread(thread.get());
			return std::nullopt;
		}
		// User-mode RIP the thread will execute next (What we want to overwrite)
		const std::uintptr_t original_rip = ctx.Rip;

		// Allocate remote memory: [shellcode | dll_path_w]
		const SIZE_T path_bytes = (dll_path.size() + 1) * sizeof(wchar_t);
		const SIZE_T stub_bytes = sizeof(k_hijack_stub);
		const SIZE_T total_bytes = stub_bytes + path_bytes;

		void* remote_mem = PT::ProcessMemory::remote_alloc(process, total_bytes, PAGE_EXECUTE_READWRITE);
		if (!remote_mem) {
			ResumeThread(thread.get());
			return std::nullopt;
		}
		const auto remote_base = reinterpret_cast<std::uintptr_t>(remote_mem);
		const auto remote_path = remote_base + stub_bytes;

		// Build patched shellcode in a local buffer
		std::vector<std::uint8_t> stub(k_hijack_stub, k_hijack_stub + stub_bytes);

		const auto load_library_va = reinterpret_cast<std::uintptr_t>(load_library_w);
		std::memcpy(stub.data() + k_hijack_dll_path_offset, &remote_path, sizeof(std::uintptr_t));
		std::memcpy(stub.data() + k_hijack_loadlibrary_offset, &load_library_va, sizeof(std::uintptr_t));
		std::memcpy(stub.data() + k_hijack_origrip_offset, &original_rip, sizeof(std::uintptr_t));

		// Write the shellcode and the wide DLL path into the target
		const bool wrote =
			PT::ProcessMemory::remote_write(process, remote_mem, stub.data(), stub_bytes) &&
			PT::ProcessMemory::remote_write(process,
											reinterpret_cast<void*>(remote_path), dll_path.data(), path_bytes);
		if (!wrote) {
			PT::ProcessMemory::remote_free(process, remote_mem);
			ResumeThread(thread.get());
			return std::nullopt;
		}

		// Redirect RIP to our shellcode (control fields only)
		ctx.Rip = remote_base;
		ctx.ContextFlags = CONTEXT_CONTROL;
		if (!SetThreadContext(thread.get(), &ctx)) {
			PT::ProcessMemory::remote_free(process, remote_mem);
			ResumeThread(thread.get());
			return std::nullopt;
		}

		// Resume: the hijacked thread runs the stub, loads the DLL, then continues
		if (ResumeThread(thread.get()) == static_cast<DWORD>(-1)) {
			// Don't free remote_mem — the thread may still execute the stub.
			return std::nullopt;
		}

		// Give the hijacked thread a brief window to execute LoadLibraryW so a follow-up
		// find_module_base in the caller can resolve the new module. Intentionally leak
		// remote_mem: the stub may run later if the thread was in a long-running syscall.
		// POSSIBLY USE A CANARY!
		Sleep(500);

		return hijacked_tid;
	}

	bool call_exported_function(const WinHandle& process, const std::wstring_view& local_dll_path, const std::uintptr_t remote_module_base, const std::string_view& function_name) {
		if (!process || local_dll_path.empty() || function_name.empty() || remote_module_base == 0) return false;

		HMODULE local_module = LoadLibraryW(std::wstring(local_dll_path).c_str());
		if (!local_module) return false;

		FARPROC local_func = GetProcAddress(local_module, std::string(function_name.data()).c_str());
		if (!local_func) {
			FreeLibrary(local_module);
			return false;
		}

		auto func_offset = reinterpret_cast<std::uintptr_t>(local_func) - reinterpret_cast<std::uintptr_t>(local_module);
		auto remote_func_addr = reinterpret_cast<LPTHREAD_START_ROUTINE>(remote_module_base + func_offset);

		auto thread = PT::ProcessThread::create_remote_thread(process, remote_func_addr, nullptr);
		if (!thread) {
			FreeLibrary(local_module);
			return false;
		}

		bool ok = PT::ProcessThread::wait_for_thread(thread) == WAIT_OBJECT_0;

		FreeLibrary(local_module);
		return ok;
	}
}

