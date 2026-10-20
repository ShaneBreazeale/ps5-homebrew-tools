/* SPDX-License-Identifier: GPL-3.0-or-later
 * Native service/loader simulation. No syscall, resident hook or console.
 */
#include <assert.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#define K UINT64_C(0xffff800000000000)
#define STORE (K+0x1000)
#define PMAP (K+0x2000)
#define ENTRY (K+0x3000)
#define IDT (K+0x4000)
#define TSS (K+0x5000)
static _Alignas(8) unsigned char kernel[0x10000];
static ssize_t copyout(void *out, uint64_t address, size_t size) {
    if(address<K || address-K>sizeof(kernel) || size>sizeof(kernel)-(address-K)) return -1;
    memcpy(out,kernel+(address-K),size); return (ssize_t)size;
}
static ssize_t copyin(uint64_t address, const void *in, size_t size) {
    if(address<K || address-K>sizeof(kernel) || size>sizeof(kernel)-(address-K)) return -1;
    memcpy(kernel+(address-K),in,size); return (ssize_t)size;
}
#include "../residents/readiness/loader.h"
static struct ko_ready_request request;
static struct ko_ready_reply response;
static int kernel_reads, deny_user;
static int service_read(void *ctx, uint64_t address, void *out, size_t size) {
    (void)ctx;
    if(address==0x1000 && size==sizeof(request)) { memcpy(out,&request,size); return 0; }
    kernel_reads++;
    return copyout(out,address,size)==(ssize_t)size ? 0 : -1;
}
static int service_write(void *ctx, uint64_t address, const void *in, size_t size) {
    (void)ctx;
    if(address!=0x2000 || size!=sizeof(response)) return -1;
    memcpy(&response,in,size); return 0;
}
static int service_user(void *ctx, uint64_t address, size_t size, int writing) {
    (void)ctx;
    return deny_user || address!=(writing ? 0x2000u : 0x1000u)
        || size!=(writing ? sizeof(response) : sizeof(request));
}
static void word(uint64_t address,uint64_t value) { assert(copyin(address,&value,8)==8); }
static void gate(unsigned vector,uint64_t handler,unsigned ist) {
    uint64_t first=(handler&0xffff) | (UINT64_C(0x8)<<16) | ((uint64_t)ist<<32)
        | (UINT64_C(0x8e)<<40) | (((handler>>16)&0xffff)<<48);
    word(IDT+vector*16,first); word(IDT+vector*16+8,handler>>32);
}
static struct ko_resident_store *setup(void) {
    memset(kernel,0,sizeof(kernel));
    memset(&ko_loader_producer,0,sizeof(ko_loader_producer));
    memset(&ko_loader_image,0,sizeof(ko_loader_image));
    memset(ko_loader_session,0x31,sizeof(ko_loader_session));
    ko_loader_failed=0; ko_loader_soc=0x840fd0;
    deny_user=kernel_reads=0;
    word(PMAP+0x20,K+0x7000); word(PMAP+0x28,0x2000);
    for(unsigned i=0;i<3;i++) {
        word(ENTRY+i*16,K+0x8000+i*16);
        word(ENTRY+i*16+8,K+0x9000+i*16);
    }
    gate(13,K+0x8000,3); gate(1,K+0x8010,4); gate(3,K+0x8020,7);
    assert(ko_loader_begin(STORE,K+0xcc0000,0x13600000,PMAP)==0);
    const unsigned offsets[]={0x34,0x3c,0x54};
    for(unsigned cpu=0;cpu<16;cpu++) {
        for(unsigned i=0;i<3;i++) word(TSS+cpu*0x100+offsets[i],K+0x9000+i*16);
        ko_loader_cpu(cpu,ENTRY,TSS+cpu*0x100,1);
        assert(!ko_loader_failed);
    }
    assert(ko_loader_image.check_count==48);
    assert(ko_loader_commit(IDT,ENTRY,1)==0);
    assert(ko_loader_image.check_count==56);
    struct ko_resident_store *store=(void*)(kernel+0x1000);
    struct ko_resident_image image;
    assert(ko_resident_snapshot(store,&image)==0);
    assert(image.reply.state==KO_READY && image.reply.completed_cpus==KO_CPU_MASK);
    memset(&request,0,sizeof(request));
    request.abi_version=KO_READY_ABI; request.record_size=sizeof(request);
    request.text=image.reply.text; request.data=image.reply.data;
    request.firmware=image.reply.firmware; request.soc=image.reply.soc;
    memset(request.challenge,0x42,sizeof(request.challenge));
    return store;
}
int main(void) {
    (void)ko_loader_prepare; /* Entropy/SoC acquisition is outside this mock. */
    struct ko_resident_io io={NULL,service_read,service_write,service_user};
    struct ko_resident_store *store=setup();
    assert(ko_resident_handle(store,&io,0x1000,sizeof(request),0x2000,sizeof(response),0)==0);
    assert(response.state==KO_READY && response.capabilities==KO_CAP_INSPECT);
    assert(kernel_reads==56 && !memcmp(response.challenge,request.challenge,sizeof(request.challenge)));
    /* A packed IST field changing must permanently revoke this publication. */
    word(TSS+0x34,0);
    assert(ko_resident_handle(store,&io,0x1000,sizeof(request),0x2000,sizeof(response),0)==0);
    assert(response.state==KO_FAILED && !response.capabilities && store->revoked);
    word(TSS+0x34,K+0x9000);
    assert(ko_resident_handle(store,&io,0x1000,sizeof(request),0x2000,sizeof(response),0)==0);
    assert(response.state==KO_FAILED);
    store=setup(); deny_user=1;
    assert(ko_resident_handle(store,&io,0x1000,sizeof(request),0x2000,sizeof(response),0)==EFAULT);
    assert(!kernel_reads);
    deny_user=0; store->sequence|=1;
    assert(ko_resident_handle(store,&io,0x1000,sizeof(request),0x2000,sizeof(response),0)==EAGAIN);
    store=setup();
    unsigned count=ko_loader_image.check_count;
    assert(ko_loader_add_check(UINT64_MAX-3,0)==-1 && ko_loader_failed);
    assert(ko_loader_image.check_count==count);
    assert(ko_loader_add_check(0x1000,0)==-1);
    /* Service also refuses a wraparound check without reading it. */
    ko_loader_image.checks[0].address=UINT64_MAX-3;
    assert(ko_resident_publish(STORE,&ko_loader_image,ko_loader_read,ko_loader_write,0)==0);
    kernel_reads=0;
    assert(ko_resident_handle(store,&io,0x1000,sizeof(request),0x2000,sizeof(response),0)==0);
    assert(response.state==KO_FAILED && !kernel_reads);
    puts("draft resident packed TSS/publication/revocation assertions passed");
    return 0;
}
