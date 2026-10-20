/* SPDX-License-Identifier: GPL-3.0-or-later
 * Included by the pinned research installer only, never by the SDK client.
 * Publishes state in newly allocated resident storage; no existing resident is
 * patched in place. Persistent resident hooks are verified, not removed.
 */
#ifndef KO_LOADER_H
#define KO_LOADER_H
#include "ko_resident.h"
#include "readiness_producer.h"
#include "ko_build_id.h"
static struct ko_ready_producer ko_loader_producer;
static struct ko_resident_image ko_loader_image;
static uint64_t ko_loader_address, ko_loader_pmap, ko_loader_pml4;
static uint64_t ko_loader_session[2];
static int ko_loader_failed, ko_loader_soc;
static int ko_loader_prepare(void) {
    int (*soc)(void) = dlsym((void*)1, "sceKernelGetMainSocId");
    if (!soc || (ko_loader_soc=soc()) != 0x840fd0) return -1;
    int fd=open("/dev/urandom", O_RDONLY);
    if(fd < 0) return -1;
    unsigned char *p=(void*)ko_loader_session;
    size_t left=sizeof(ko_loader_session);
    while(left) {
        ssize_t n=read(fd,p,left);
        if(n <= 0) { close(fd); return -1; }
        p+=n; left-=(size_t)n;
    }
    if(close(fd)) return -1;
    return ko_nonzero(ko_loader_session,sizeof(ko_loader_session)) ? 0 : -1;
}
static int ko_loader_read(void *ctx,uint64_t address,void *out,size_t size) {
    (void)ctx;
    return copyout(out,address,size)==(ssize_t)size ? 0 : -1;
}
static int ko_loader_write(void *ctx,uint64_t address,const void *in,size_t size) {
    (void)ctx;
    return copyin(address,in,size)==(ssize_t)size ? 0 : -1;
}
static int ko_loader_add_check(uint64_t address,uint64_t expected) {
    uint64_t actual=0;
    if(ko_loader_image.check_count==KO_CHECK_MAX
        || (address>>47)!=UINT64_C(0x1ffff) || address>UINT64_MAX-7
        || ko_loader_read(0,address,&actual,8) || actual!=expected) {
        ko_loader_failed=1; return -1;
    }
    struct ko_live_check *check=&ko_loader_image.checks[ko_loader_image.check_count++];
    check->address=address; check->expected=expected;
    return 0;
}
static int ko_loader_begin(uint64_t address,uint64_t data,uint32_t firmware,uint64_t pmap) {
    ko_loader_address=address; ko_loader_pmap=pmap;
    struct ko_ready_reply identity={0};
    const unsigned char build_id[32]=KO_BUILD_ID_BYTES;
    identity.text=data-UINT64_C(0xcc0000); identity.data=data;
    identity.firmware=firmware; identity.soc=ko_loader_soc;
    identity.expected_cpus=KO_CPU_MASK; identity.active_hooks=1;
    memcpy(identity.build_id,build_id,32);
    memcpy(identity.session,ko_loader_session,sizeof(identity.session));
    if((firmware&0xffff0000u)!=0x13600000u || (data>>47)!=0x1ffff || (data&4095)
        || ko_loader_read(0,pmap+0x20,&ko_loader_pml4,8)
        || ko_loader_read(0,pmap+0x28,&identity.cr3,8)
        || !identity.cr3 || (identity.cr3&4095) || identity.cr3 >= (UINT64_C(1)<<36)
        || ko_producer_begin(&ko_loader_producer,&identity,0,0)) return -1;
    ko_loader_image.reply=ko_loader_producer.record;
    return ko_resident_publish(address,&ko_loader_image,ko_loader_read,ko_loader_write,0);
}
static void ko_loader_cpu(unsigned cpu,uint64_t entry,uint64_t tss,int have_int3) {
    const unsigned slots[3]={3,4,7};
    const unsigned offsets[3]={8,24,40};
    unsigned count=have_int3 ? 3 : 2;
    for(unsigned i=0;i<count;i++) {
        uint64_t expected=0;
        if(ko_loader_read(0,entry+offsets[i],&expected,8)
            || ko_loader_add_check(tss+28+slots[i]*8,expected)) {
            ko_loader_failed=1; return;
        }
    }
    if(ko_producer_cpu_complete(&ko_loader_producer,cpu)) ko_loader_failed=1;
}
static void ko_loader_gate(uint64_t idt,unsigned vector,uint64_t entry,unsigned offset,unsigned ist) {
    uint64_t expected=0, gate[2]={0};
    uint64_t address=idt+vector*16;
    if(ko_loader_read(0,entry+offset,&expected,8) || ko_loader_read(0,address,gate,sizeof(gate))) {
        ko_loader_failed=1; return;
    }
    uint64_t target=(gate[0]&0xffff) | ((gate[0]>>48)<<16) | ((gate[1]&0xffffffff)<<32);
    if(target!=expected || ((gate[0]>>32)&7)!=ist || !(gate[0]&(UINT64_C(1)<<47))) {
        ko_loader_failed=1; return;
    }
    ko_loader_add_check(address,gate[0]); ko_loader_add_check(address+8,gate[1]);
}
static int ko_loader_commit(uint64_t idt,uint64_t entry,int have_int3) {
    ko_loader_gate(idt,13,entry,0,3); ko_loader_gate(idt,1,entry,16,4);
    if(have_int3) ko_loader_gate(idt,3,entry,32,7);
    ko_loader_add_check(ko_loader_pmap+0x20,ko_loader_pml4);
    ko_loader_add_check(ko_loader_pmap+0x28,ko_loader_producer.record.cr3);
    if(!have_int3 || ko_loader_image.check_count!=56 || ko_loader_failed
        || ko_producer_finish(&ko_loader_producer,0,0,0,0)) {
        ko_loader_producer.record.state=KO_FAILED;
        ko_loader_producer.record.capabilities=0;
        ko_loader_producer.record.active_hooks=1;
        ko_loader_failed=1;
    }
    ko_loader_image.reply=ko_loader_producer.record;
    if(ko_resident_publish(ko_loader_address,&ko_loader_image,ko_loader_read,ko_loader_write,0)) return -1;
    return ko_loader_failed ? -1 : 0;
}
#endif
