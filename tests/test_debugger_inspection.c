/* SPDX-License-Identifier: GPL-3.0-or-later */
#define PROCESS_INSPECTION_TEST
#include "../payloads/process-debugger/inspection.c"
#include <assert.h>
#include <stdio.h>
static unsigned char records[3*1096], maps[2*1160];
static size_t record_size, map_size;
static uint32_t firmware = 0x13600000u;
static int selector_error, retries, no_path, no_app, module_error, bad_module, entry_error, no_entry;
static void put32(unsigned char *p, uint32_t v) { memcpy(p,&v,4); }
static void put64(unsigned char *p, uint64_t v) { memcpy(p,&v,8); }
uint32_t kernel_get_fw_version(void) { return firmware; }
int sysctl(const int *mib, unsigned n, void *out, size_t *size, const void *in, size_t in_size)
{
    assert(mib[0] == CTL_KERN && mib[1] == KERN_PROC && !in && !in_size);
    if(selector_error) { errno=selector_error; return -1; }
    const void *source; size_t length;
    if(mib[2] == KERN_PROC_PROC) { assert(n==3); source=records; length=record_size; }
    else if(mib[2] == KERN_PROC_VMMAP) { assert(n==4 && mib[3]==4242); source=maps; length=map_size; }
    else {
        assert(n==4 && mib[2]==KERN_PROC_PATHNAME && mib[3]==4242);
        if(no_path) { errno=ENOENT; return -1; }
        source="/app0/test.elf"; length=15;
    }
    if(!out) { *size=length; return 0; }
    if(retries) { retries--; errno=ENOMEM; return -1; }
    assert(*size>=length); memcpy(out,source,length); *size=length; return 0;
}
int sceKernelGetAppInfo(pid_t pid, struct process_app_info *out)
{
    assert(pid==4242);
    if(no_app) return -1;
    out->app_id=0x123; out->app_type=4; memcpy(out->title_id,"PPSA00001",9); return 0;
}
int kernel_dynlib_handle(pid_t pid, const char *name, uint32_t *handle)
{
    assert(pid==4242 && !strcmp(name,"test.sprx"));
    if(module_error) { errno=ENOENT; return -1; }
    *handle=0x42; return 0;
}
intptr_t kernel_dynlib_mapbase_addr(pid_t pid, uint32_t handle)
{
    assert(pid==4242 && handle==0x42); return bad_module ? -1 : 0x400000;
}
intptr_t kernel_dynlib_entry_addr(pid_t pid, uint32_t handle)
{
    assert(pid==4242 && handle==0x42);
    if(entry_error) { errno=EACCES; return 0; }
    return no_entry ? 0 : 0x401000;
}
static void reset(void)
{
    firmware=0x13600000u; selector_error=retries=no_path=no_app=module_error=bad_module=entry_error=no_entry=0;
    memset(records,0,sizeof(records)); record_size=1096;
    put32(records,1096); put32(records+72,4242); put32(records+76,10);
    put64(records+336,1700000000); put64(records+344,123456);
    memcpy(records+447,"test.elf",9);
    memset(maps,0,sizeof(maps)); map_size=2*1160;
    for(int i=0;i<2;i++) {
        unsigned char *p=maps+i*1160;
        put32(p,1160); put64(p+8,0x400000+i*0x4000); put64(p+16,0x404000+i*0x4000);
        put64(p+24,i*0x4000); put32(p+56,5-i*2); memcpy(p+136,"/app0/test.elf",15);
    }
}
static void metadata_tests(void)
{
    struct target_process_info out;
    reset(); retries=2;
    assert(process_describe(4242,&out)==0 && out.pid==4242 && out.parent_pid==10);
    assert(out.fields==7 && out.start_seconds==1700000000 && out.start_microseconds==123456);
    assert(!strcmp(out.name,"test.elf") && !strcmp(out.path,"/app0/test.elf"));
    assert(!strcmp(out.title_id,"PPSA00001") && out.app_id==0x123 && out.app_type==4);
    reset(); no_path=no_app=1;
    assert(process_describe(4242,&out)==0 && out.fields==TARGET_INFO_PROCESS && !out.path[0]);
    reset(); put32(records+72,33); assert(process_describe(4242,&out)==-ESRCH);
    reset(); put32(records,1095); assert(process_describe(4242,&out)==-EPROTO);
    reset(); put64(records+344,1000000); assert(process_describe(4242,&out)==-EPROTO);
    reset(); record_size=2*1096; memcpy(records+1096,records,1096);
    assert(process_describe(4242,&out)==-EPROTO);
    reset(); firmware=0x14000000u; assert(process_describe(4242,&out)==-ENOTSUP);
    reset(); selector_error=EACCES; assert(process_describe(4242,&out)==-EACCES);
    reset(); retries=3; assert(process_describe(4242,&out)==-EAGAIN);
}
static void map_tests(void)
{
    struct target_map out[2]; size_t count;
    reset(); assert(process_maps(4242,out,2,&count)==0 && count==2);
    assert(out[0].start==0x400000 && out[0].end==0x404000 && out[0].offset==0);
    assert(out[0].permissions==5 && !strcmp(out[0].name,"/app0/test.elf"));
    assert(out[1].offset==0x4000 && out[1].permissions==3);
    assert(process_maps(4242,out,1,&count)==-ENOSPC && count==0);
    reset(); put32(maps,136); assert(process_maps(4242,out,2,&count)==-EPROTO && count==0);
    reset(); put64(maps+16,1ull<<48); assert(process_maps(4242,out,2,&count)==-EPROTO);
    reset(); put64(maps+1160+8,0x400000); assert(process_maps(4242,out,2,&count)==-EPROTO);
    reset(); put32(maps+56,8); assert(process_maps(4242,out,2,&count)==-EPROTO);
    reset(); memset(maps+136,'a',1024); assert(process_maps(4242,out,2,&count)==-EPROTO);
    reset(); memset(maps+136,'a',300); maps[436]=0;
    assert(process_maps(4242,out,2,&count)==0 && out[0].name_truncated && strlen(out[0].name)==255);
    reset(); selector_error=ENOENT; assert(process_maps(4242,out,2,&count)==-ENOENT);
    reset(); firmware=0; assert(process_maps(4242,out,2,&count)==-ENOTSUP);
}
static void module_tests(void)
{
    struct target_module out;
    reset(); assert(process_module(4242,"test.sprx",&out)==0 && out.base==0x400000 && out.entry==0x401000 && out.handle==0x42);
    assert(process_module(4242,"../test.sprx",&out)==-EINVAL);
    assert(process_module(4242,"",&out)==-EINVAL);
    module_error=1; assert(process_module(4242,"test.sprx",&out)==-ENOENT);
    module_error=0; no_entry=1; assert(process_module(4242,"test.sprx",&out)==0 && out.entry==0);
    no_entry=0; entry_error=1; assert(process_module(4242,"test.sprx",&out)==-EACCES);
    entry_error=0; bad_module=1; assert(process_module(4242,"test.sprx",&out)==-EIO);
}
int main(int argc, char **argv)
{
    assert(argc==2);
    if(!strcmp(argv[1],"metadata")) metadata_tests();
    else if(!strcmp(argv[1],"maps")) map_tests();
    else { assert(!strcmp(argv[1],"modules")); module_tests(); }
    puts("read-only inspection assertions passed"); return 0;
}
