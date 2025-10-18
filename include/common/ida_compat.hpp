// IDA SDK compatibility header for cross-platform builds
// This header should be included before any IDA SDK headers

#pragma once

// Fix pid_t conflict on Windows/MinGW
#if defined(__NT__) || defined(_WIN32)
    #if defined(__MINGW32__) || defined(__MINGW64__)
        // MinGW already defines pid_t in sys/types.h
        // Prevent IDA SDK from redefining it
        #include <sys/types.h>
        #define pid_t _ida_pid_t
    #endif
#endif
