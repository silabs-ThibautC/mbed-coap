#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>

// Public headers
#include "mbed-coap/sn_coap_header.h"
#include "mbed-coap/sn_coap_protocol.h"
#include "ns_types.h"

// Internal headers
#include "sn_coap_header_internal.h"
#include "sn_coap_protocol_internal.h"

extern void __afl_manual_init(void);
// --- End of AFL++ declarations ---

// Forward declaration for the function we want to fuzz,
// as it is not declared in any public header file.
extern sn_coap_hdr_s *sn_coap_parser(struct coap_s *handle, uint16_t packet_data_len, uint8_t *packet_data_ptr, coap_version_e *coap_version_ptr);

// Stubs for the protocol malloc/free.
// The fuzzer doesn't need to simulate allocation failures,
// so we can just use the standard library functions.
static void *protocol_malloc(uint16_t size) {
    return malloc(size);
}

static void protocol_free(void *ptr) {
    free(ptr);
}

// Per the user's request, we are placing this macro right before main().
__AFL_FUZZ_INIT();

int main(void) {
    // This is AFL++'s deferred forkserver setup.
    // It's used to initialize everything once, before the fuzzing loop starts.
    __afl_manual_init();

    // --- CoAP handle setup ---
    // This is based on the unit tests.
    struct coap_s coap_handle;
    memset(&coap_handle, 0, sizeof(struct coap_s));
    coap_handle.sn_coap_protocol_malloc = protocol_malloc;
    coap_handle.sn_coap_protocol_free = protocol_free;

    unsigned char *buf;
    unsigned int len;

    // AFL++ persistent mode with shared memory
    while (__AFL_LOOP(10000)) {
        // Get the input from AFL++.
        // This is much faster than reading from a file.
        buf = __AFL_FUZZ_TESTCASE_BUF;
        len = __AFL_FUZZ_TESTCASE_LEN;

        if (len <= 0) {
            continue;
        }

        // --- Call the target function ---
        coap_version_e coap_version;
        sn_coap_hdr_s *parsed_msg = sn_coap_parser(&coap_handle, len, buf, &coap_version);

        // --- Cleanup ---
        // Free the parsed message to avoid memory leaks.
        if (parsed_msg) {
            sn_coap_parser_release_allocated_coap_msg_mem(&coap_handle, parsed_msg);
        }
    }

    return 0;
} 