#include <stdbool.h>
#include <limits.h>

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <shellapi.h>
#include <Shlwapi.h>

// Uncomment to allow "-v" in addition to "/v", for example.
// You will lose the ability to specify files that start with a hyphen.
//#define ARG_SWITCH_ALLOW_DASH 1

#define nullptr ((void *)0)

#define malloc(bytes) HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, (bytes));
#define zalloc(bytes) HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, (bytes));
#define free(ptr) HeapFree(GetProcessHeap(), 0, (ptr));

// DebugBreak causes some delay if there isn't a debugger,
// so don't call it in release builds.
#ifdef _DEBUG
#define DBG_BREAK() DebugBreak()
#else
#define DBG_BREAK()
#endif

#define IS_HANDLE_OK(h) ((h) != nullptr && (h) != INVALID_HANDLE_VALUE)
#define IS_HANDLE_BAD(h) (!IS_HANDLE_OK(h))

#define LI_ZERO ((LARGE_INTEGER){0})

static HANDLE conin;
static HANDLE conout;
static HANDLE conerr;
static WORD con_initial_attributes;
static HANDLE con_mutex;

static HANDLE print_changes_mutex;

typedef struct {
    bool help;

    bool quiet;
    bool verbose;
    bool print_headers; // Result of quiet and verbose flags.

    bool resume; // Don't print existing file contents before watching.
} Options;
static Options options;

// This intrinsic goes away in release mode?
#pragma function(memcpy)
void * memcpy(void * dest, const void * src, size_t size) {
    unsigned __int8 * curr_dest = (unsigned __int8 *)dest;
    const unsigned __int8 * curr_src = (unsigned __int8 *)src;
    while (size--) {
        *(curr_dest++) = *(curr_src++);
    }
    return dest;
}

void output_no_lock_w(const wchar_t * msg) {
    DWORD written;
    WriteConsoleW(conout, msg, (DWORD)wcslen(msg), &written, nullptr);
}

void output_no_lock_a(const char * msg) {
    DWORD written;
    WriteConsoleA(conout, msg, (DWORD)strlen(msg), &written, nullptr);
}

void output(const wchar_t * msg) {
    WaitForSingleObject(con_mutex, INFINITE);

    output_no_lock_w(msg);
    output_no_lock_w(L"\r\n");
    OutputDebugStringW(msg);
    OutputDebugStringW(L"\r\n");

    ReleaseMutex(con_mutex);
}

void outputf(const wchar_t * fmt, ...) {
    wchar_t buff[1024 + 1];
    va_list args;

    va_start(args, fmt);
    // Yes, writes a null terminator.
    wvsprintfW(buff, fmt, args);
    va_end(args);

    output(buff);
}

DWORD win_err(const wchar_t * prefix) {
    DWORD err = GetLastError();
    wchar_t msg[512];
    DWORD written;

    written = FormatMessageW(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        nullptr,
        err,
        0,
        msg,
        512,
        nullptr);
    if (written) {
        if (prefix) {
            outputf(L"%s: %s", prefix, msg);
        } else {
            output(msg);
        }
    }

    DBG_BREAK();

    return err;
}

DWORD min_dword(DWORD a, DWORD b) {
    if (a > b) {
        return a;
    } else {
        return b;
    }
}

DWORD cap_i64_to_i32(__int64 in) {
    if (in <= INT_MAX) {
        return (DWORD)in;
    } else {
        return INT_MAX;
    }
}

int _print_changes(HANDLE handle, __int64 file_size, const wchar_t * filename) {
    LARGE_INTEGER curr = { 0 };
    bool starting_over = false;
    __int64 total_to_read;
    __int64 total_read = 0;
    char * buffer;
    bool read_succ;
    DWORD single_read_count;

    SetFilePointerEx(handle, LI_ZERO, &curr, FILE_CURRENT);

    if (file_size < curr.QuadPart) {
        // The writing to this file has started over, probably.
        SetFilePointer(handle, 0, nullptr, FILE_BEGIN);
        curr.QuadPart = 0;
        starting_over = true;
    }
    total_to_read = file_size - curr.QuadPart;

    if (total_to_read <= 0) {
        return 0;
    }

    buffer = zalloc(cap_i64_to_i32(total_to_read));
    if (buffer == nullptr) {
        SetLastError(ERROR_OUTOFMEMORY);
        return win_err(filename);
    }

    // If options allow for it, print a header when the output switches files.
    // A file "starting over" is considered switching files.
    if (options.print_headers || (!options.quiet && starting_over)) {
        static const wchar_t * last_filename = nullptr;
        static bool have_printed_before = false;

        // The filenames don't get reallocated ever, so we can compare pointers.
        if (last_filename != filename || starting_over) {
            WORD attr = con_initial_attributes
                // Remove RGB components.
                & ~(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE)
                // Apply our color.
                | (starting_over ? (FOREGROUND_RED | FOREGROUND_GREEN) : FOREGROUND_GREEN);

            SetConsoleTextAttribute(conout, attr);
            if (have_printed_before) {
                output_no_lock_w(L"\r\n");
            } else {
                have_printed_before = true;
            }
            output_no_lock_w(L"==> ");
            output_no_lock_w(filename);
            output_no_lock_w(L" <==\r\n");
            SetConsoleTextAttribute(conout, con_initial_attributes);

            last_filename = filename;
        }
    }

    while (total_read < total_to_read) {
        read_succ = ReadFile(handle, buffer, cap_i64_to_i32(total_to_read - total_read), &single_read_count, nullptr);
        if (read_succ && single_read_count > 0) {
            WriteConsoleA(conout, buffer, single_read_count, &single_read_count, nullptr);
        }

        total_read += single_read_count;
    }

    free(buffer);
    return 0;
}

int print_changes(HANDLE handle, __int64 file_size, const wchar_t * filename) {
    int ret;
    WaitForSingleObject(print_changes_mutex, INFINITE);
    WaitForSingleObject(con_mutex, INFINITE);
    ret = _print_changes(handle, file_size, filename);
    ReleaseMutex(con_mutex);
    ReleaseMutex(print_changes_mutex);
    return ret;
}

__int64 get_file_size(HANDLE handle) {
    LARGE_INTEGER size = { 0 };
    if (!GetFileSizeEx(handle, &size)) {
        return 0;
    }
    return size.QuadPart;
}

wchar_t * wstr_dup(const wchar_t * src) {
    size_t len = wcslen(src);
    size_t size = (len + 1) * sizeof(wchar_t);
    wchar_t * d = malloc(size);
    if (d) {
        memcpy(d, src, size);
    }
    return d;
}

void split_path_to_dir_and_name(const wchar_t * fullpath, wchar_t ** dir_out, wchar_t ** name_out) {
    const size_t fullpath_len = wcslen(fullpath);
    signed __int64 split_point = -1;

    *dir_out = nullptr;
    *name_out = nullptr;

    if (fullpath_len == 0) {
        return;
    }

    for (const wchar_t * curr = fullpath + fullpath_len - 1; curr >= fullpath; --curr) {
        if (*curr == L'\\' || *curr == L'/') {
            split_point = curr - fullpath;
            break;
        }
    }

    if (split_point == -1) {
        // We found no slash.  The whole thing is the name.
        // That means it is relative to the current working directory.
        *dir_out = wstr_dup(L".");
        *name_out = wstr_dup(fullpath);
    } else if (split_point == fullpath_len - 1) {
        // The slash was at the very end.  The whole thing is a dir.
        // This is an error case.
        *dir_out = wstr_dup(fullpath);
    } else {
        wchar_t * dir  = wstr_dup(fullpath);

        if (split_point == 0) {
            // The first character is a slash, so the file is in the root directory.
            // We need to return the slash itself to represent the root.
            dir[split_point + 1] = 0;
        } else {
            dir[split_point] = 0;
        }
        *dir_out  = dir;

        *name_out = wstr_dup(fullpath + split_point + 1);
    }
}

DWORD watch_file(const wchar_t * fullpath) {
    wchar_t * dirpath = nullptr;
    wchar_t * filename = nullptr;
    int filename_len = 0;

    HANDLE file_handle;
    HANDLE dir_handle;
    FILE_NOTIFY_EXTENDED_INFORMATION * buffer = nullptr;
    DWORD buffer_size = 0;
    DWORD written = 0;

    if (PathIsDirectoryW(fullpath)) {
        SetLastError(ERROR_DIRECTORY_NOT_SUPPORTED);
        return win_err(fullpath);
    }

    if (wcslen(fullpath) >= INT_MAX) {
        // Due to Win32 API limitations.
        SetLastError(ERROR_FILENAME_EXCED_RANGE);
        return win_err(fullpath);
    }

    split_path_to_dir_and_name(fullpath, &dirpath, &filename);
    if (dirpath == nullptr) {
        SetLastError(ERROR_ASSERTION_FAILURE);
        return win_err(fullpath);
    }
    if (filename == nullptr) {
        SetLastError(ERROR_DIRECTORY_NOT_SUPPORTED);
        return win_err(fullpath);
    }

    filename_len = (int)wcslen(filename);

    file_handle = CreateFileW(fullpath, FILE_READ_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, 0, nullptr);
    if (IS_HANDLE_BAD(file_handle)) {
        return win_err(fullpath);
    }

    if (options.resume) {
        LARGE_INTEGER size = { 0 };
        if (GetFileSizeEx(file_handle, &size)) {
            SetFilePointerEx(file_handle, size, nullptr, FILE_BEGIN);
        }
    } else {
        // Before we start listening for changes, print the current state of the file.
        print_changes(file_handle, get_file_size(file_handle), fullpath);
    }

    dir_handle = CreateFileW(dirpath, FILE_LIST_DIRECTORY, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, nullptr);
    if (IS_HANDLE_BAD(dir_handle)) {
        return win_err(fullpath);
    }

    // First guess for size would be a notification for only the watched file.
    buffer_size = min_dword(
        (DWORD)(sizeof(*buffer) + (wcslen(filename) * sizeof(wchar_t))),
        1024);
    // This must be aligned by at least a DWORD, which HeapAlloc will satisfy.
    buffer = malloc(buffer_size);

    while (true) {
        if (buffer == nullptr) {
            SetLastError(ERROR_OUTOFMEMORY);
            return win_err(fullpath);
        }

        if (ReadDirectoryChangesExW(dir_handle, buffer, buffer_size, false, FILE_NOTIFY_CHANGE_LAST_WRITE, &written, nullptr, nullptr, ReadDirectoryNotifyExtendedInformation)) {
            if (written > 0) {
                FILE_NOTIFY_EXTENDED_INFORMATION * current = buffer;
                while (true) {
                    if (CompareStringW(LOCALE_USER_DEFAULT, LINGUISTIC_IGNORECASE,
                        current->FileName, current->FileNameLength / sizeof(wchar_t),
                        filename, filename_len)
                        == CSTR_EQUAL) {
                        print_changes(file_handle, current->FileSize.QuadPart, fullpath);
                    }

                    // Break out if there is no next entry.
                    if (current->NextEntryOffset > 0) {
                        current = (FILE_NOTIFY_EXTENDED_INFORMATION *)(((__int8 *)current) + current->NextEntryOffset);
                    } else {
                        break;
                    }
                }
            } else {
                output(L"notification, but buffer too small");
            }
        } else {
            return win_err(fullpath);
        }
    }

    return 0;
}

bool option_switch(wchar_t flag) {
    switch (flag) {
    case L'h':
    case L'?':
        options.help = true;
        break;
    case L'q':
        options.quiet = true;
        options.verbose = false;
        break;
    case L'r':
        options.resume = true;
        break;
    case L'v':
        options.quiet = false;
        options.verbose = true;
        break;
    default:
        return false;
    }
    return true;
}

bool is_arg_a_switch(const wchar_t * arg) {
    if (arg[0] == L'/') {
        return true;
    }

#if ARG_SWITCH_ALLOW_DASH
    if (arg[0] == L'-') {
        return true;
    }
#endif

    return false;
}

int wmain(int argc, wchar_t ** argv) {
    HANDLE * threads;
    int thread_count = 0;
    int thread_idx = 0;

    conin  = GetStdHandle(STD_INPUT_HANDLE);
    conout = GetStdHandle(STD_OUTPUT_HANDLE);
    if (IS_HANDLE_BAD(conin)) {
        return win_err(L"Could not get handle to standard output");
    }
    conerr = GetStdHandle(STD_ERROR_HANDLE);

    {
        DWORD mode;
        CONSOLE_SCREEN_BUFFER_INFO info;

        GetConsoleScreenBufferInfo(conout, &info);
        con_initial_attributes = info.wAttributes;

        // Try to enable "virtual terminal processing" for escape code support.
        if (GetConsoleMode(conout, &mode)) {
            SetConsoleMode(conout, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
        }
    }

    con_mutex = CreateMutexW(nullptr, false, nullptr);
    print_changes_mutex = CreateMutexW(nullptr, false, nullptr);
    if (IS_HANDLE_BAD(con_mutex) || IS_HANDLE_BAD(print_changes_mutex)) {
        return win_err(L"Could not create mutex");
    }

    for (int i = 1; i < argc; ++i) {
        wchar_t * curr = argv[i];
        if (is_arg_a_switch(curr)) {
            if (curr[1] && curr[2] == 0) {
                option_switch(curr[1]);
            } else {
                outputf(L"Invalid option %s", curr);
                return ERROR_INVALID_PARAMETER;
            }
        } else {
            ++thread_count;
        }
    }

    if (options.help) {
        static const char msg[] =
            "View any log file(s) in real time.\n"
            "\n"
            "log [option]... [file]...\n"
        #if ARG_SWITCH_ALLOW_DASH
            "Options may be prefixed with / or -\n"
        #endif
            "\n"
            "Options:\n"
            "  /?, /h \t" "Prints this message and exits.\n"
            "  /q     \t" "Removes the header when the output switches files.\n"
            "  /r     \t" "Do not print existing file contents before printing changes.\n"
            "  /v     \t" "Always show the header, even for just one file.\n"
            "";
        output_no_lock_a(msg);
        return 0;
    }

    if (options.verbose) {
        options.print_headers = true;
    } else if (options.quiet) {
        options.print_headers = false;
    } else if (thread_count > 1) {
        // User didn't specify, only print headers if there are multiple files.
        options.print_headers = true;
    }

    threads = malloc(sizeof(HANDLE) * thread_count);
    if (threads == nullptr) {
        output(L"Could not allocate memory for thread array");
        return ERROR_OUTOFMEMORY;
    }

    for (int i = 1; i < argc; ++i) {
        if (!is_arg_a_switch(argv[i])) {
            if (thread_idx >= thread_count) {
                output(L"Thread count mismatch");
                DBG_BREAK();
                return ERROR_ASSERTION_FAILURE;
            }

            if (thread_count == 1) {
                // This is the only file specified, just run on the main thread.
                return watch_file(argv[i]);
            } else {
                threads[thread_idx++] = CreateThread(nullptr, 0, &watch_file, argv[i], 0, nullptr);
            }
        }
    }

    if (thread_count > 0) {
        WaitForMultipleObjects(thread_count, threads, true, INFINITE);
    }

    return 0;
}

// Provide environment for a wmain, and nothing more.
void entry() {
    const wchar_t * cli = GetCommandLineW();
    wchar_t empty[] = L"";
    wchar_t * empty_ptr = empty;

    int argc = 0;
    wchar_t ** argv;

    argv = CommandLineToArgvW(cli, &argc);
    if (argv == nullptr) {
        argc = 0;
        argv = &empty_ptr;
    }

    ExitProcess(wmain(argc, argv));
}