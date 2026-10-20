/* Compile the real SDK entry point using native backend fixtures. */
#define main ko_native_tests
#include "test_kernel_offset.c"
#undef main
#define main ko_payload_main
#include "../payloads/kernel-offset/main.c"
#undef main
const intptr_t KERNEL_ADDRESS_TEXT_BASE = (intptr_t)UINT64_C(0xffffffff8d640000);
const intptr_t KERNEL_ADDRESS_DATA_BASE = (intptr_t)UINT64_C(0xffffffff8e300000);
uint32_t kernel_get_fw_version(void) { return PROFILE_FIRMWARE; }
int sceKernelGetMainSocId(void) { return PROFILE_SOC; }
int kernel_copyout(intptr_t va, void *out, size_t length) { return read_mock(NULL, (uint64_t)va, out, length); }
#ifdef TEST_PROVIDER
const struct ko_provider ko_readiness_provider = {query_mock, NULL, {
    0x5a,0x5a,0x5a,0x5a,0x5a,0x5a,0x5a,0x5a,0x5a,0x5a,0x5a,0x5a,0x5a,0x5a,0x5a,0x5a,
    0x5a,0x5a,0x5a,0x5a,0x5a,0x5a,0x5a,0x5a,0x5a,0x5a,0x5a,0x5a,0x5a,0x5a,0x5a,0x5a
}};
#endif
int main(int argc, char **argv) {
    setup();
    if (argc > 1) query_fault = argv[1][0] == 'u' ? 1 : argv[1][0] == 'i' ? 16 : 5;
    return ko_payload_main();
}
