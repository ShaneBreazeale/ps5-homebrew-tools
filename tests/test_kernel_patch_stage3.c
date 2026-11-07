/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <assert.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <unistd.h>
#include "../residents/patch/stage3_client.h"
#define K UINT64_C(0xffffffff80000000)
#define STORE (K+0x2000000)
#define PMAP (K+0x1800000)
#define PML4 (K+0x3000000)
static struct { struct kp_stage2_store p; struct kp_stage3_store s; } server;
static uint64_t live_cr3;
static unsigned fail_copy, writes, revoke_after_write;
static ssize_t copyout(void *out,uint64_t address,size_t length) {
    if(address>=STORE && address-STORE<=sizeof(server) && length<=sizeof(server)-(address-STORE)) {
        memcpy(out,(unsigned char *)&server+(address-STORE),length); return (ssize_t)length;
    }
    if(revoke_after_write && server.s.value==KP_STAGE3_AFTER) live_cr3=0x2000;
    uint64_t word;
    if(address==PMAP+0x20 && length==8) word=PML4;
    else if(address==PMAP+0x28 && length==8) word=live_cr3;
    else if(address==K+0x38fc12 && length==7) { memcpy(out,"\x4c\x8d\x2d\xf7\xc6\x58\x03",7); return 7; }
    else return -1;
    memcpy(out,&word,8); return 8;
}
static ssize_t copyin(uint64_t address,const void *in,size_t length) {
    if(fail_copy || address<STORE || address-STORE>sizeof(server) || length>sizeof(server)-(address-STORE)) return -1;
    ++writes; memcpy((unsigned char *)&server+(address-STORE),in,length); return (ssize_t)length;
}
static int soc(void) { return 0x840fd0; }
static void *fake_dlsym(void *handle,const char *name) { (void)handle;(void)name;return (void *)soc; }
#define dlsym fake_dlsym
#include "../residents/patch/stage3_loader.h"
#undef dlsym
static int read_live(void *unused,uint64_t address,void *out,size_t length) {
    (void)unused; return copyout(out,address,length)==(ssize_t)length?0:-1;
}
static void setup(void) {
    memset(&server,0,sizeof(server)); live_cr3=0x1000; fail_copy=writes=revoke_after_write=0;
    (void)kp_s2_cpu_complete; assert(!kp_s2_prepare()); kp_s2_completed=0xffff;
    assert(!kp_s3_publish(STORE,K+0xcc0000,0x13600000,PMAP));
    assert(server.s.value==KP_STAGE3_BEFORE && !server.s.engine.initialized);
    assert(sizeof(server.s)<8192);
}
static struct kp_stage3_context context(void) {
    return (struct kp_stage3_context){&server.p,&server.s,read_live,NULL,
        STORE+sizeof(struct kp_stage2_store)+offsetof(struct kp_stage3_store,value)};
}
static unsigned lost_reply, deny, bad_token, calls, mutations, fail_recovery;
static int access_user(void *unused,uint64_t a,size_t n,int writing) { (void)unused;(void)a;(void)n;(void)writing;return deny; }
static int read_user(void *unused,uint64_t a,void *out,size_t n) {
    (void)unused;memcpy(out,(void *)(uintptr_t)a,n);
    if(bad_token) ((struct kp_bridge_request *)out)->token[31]^=1;
    return 0;
}
static int write_user(void *unused,uint64_t a,const void *in,size_t n) {
    (void)unused;
    if((lost_reply && n==sizeof(struct kp_result)) || (fail_recovery && mutations && n==sizeof(struct kp_probe_reply))) return -1;
    memcpy((void *)(uintptr_t)a,in,n); return 0;
}
#define KPS3_TRANSPORT_TEST
#include "../residents/patch/stage3_client.c"
struct kp_s3_call_result kp_s3_call(uint64_t q,uint64_t n,uint64_t r,uint64_t m,uint64_t reserved,uint64_t nr) {
    uint32_t selector=(uint32_t)(nr>>32);
    assert(!reserved && (uint32_t)nr==0x27);
    assert((selector==KP_STAGE3_QUERY_SELECTOR && n==104 && m==720)
        || (selector==KP_STAGE3_EXERCISE_SELECTOR && n==360 && m==248));
    ++calls;
    if(selector==KP_STAGE3_EXERCISE_SELECTOR) ++mutations;
    struct kp_stage3_io io={.user={NULL,access_user,read_user,write_user,NULL},.service=context()};
    int error=kp_stage3_bridge(&io,selector,q,n,r,m,reserved);
    return (struct kp_s3_call_result){(uint64_t)error,error!=0};
}
static enum kp_s3_status exercise(struct kp_s3_observation *o) {
    const unsigned char challenges[3][16]={{4},{5},{6}};
    return kp_s3_exercise(&kp_stage3_provider,0x13600000,0x840fd0,K,K+0xcc0000,challenges,o);
}
static void reset(void) { setup();lost_reply=deny=bad_token=calls=mutations=fail_recovery=0; }
static void transactions(void) {
    struct kp_s3_observation o;
    reset(); assert(exercise(&o)==KPS3_RESTORED && calls==4 && mutations==1);
    unsigned before_inspection=mutations;
    struct kp_s3_observation recovered;
    const unsigned char challenge[16]={7};
    assert(kp_s3_inspect(&kp_stage3_provider,0x13600000,0x840fd0,K,K+0xcc0000,challenge,&recovered)==KPS3_CACHED);
    assert(!recovered.command_attempted && mutations==before_inspection);
    assert(server.s.value==KP_STAGE3_BEFORE && !server.s.lease && !server.s.quarantined);
    assert(!kp_nonzero((const unsigned char *)&server.s.engine.adapter,sizeof(server.s.engine.adapter)));
    for(unsigned i=0;i<3;++i) {
        assert(server.s.journal[i].valid && server.s.journal[i].stage==i+1);
        assert(!memcmp(&server.s.journal[i].request,&o.command,sizeof(o.command)));
    }
    assert(server.s.journal[0].result.preimage[0]==(KP_STAGE3_BEFORE&255));
    assert(server.s.journal[1].result.flags & KP_RESTORED_VERIFIED);
    assert(exercise(&o)==KPS3_HISTORY && mutations==1);
    reset(); lost_reply=1;
    assert(exercise(&o)==KPS3_RECOVERED && mutations==1 && calls==4 && !o.command_transport_ok);
    assert(o.replies[2].last_result.state==KP_RESTORED && server.s.value==KP_STAGE3_BEFORE);
    reset(); lost_reply=fail_recovery=1;
    assert(exercise(&o)==KPS3_UNVERIFIED && mutations==1 && server.s.engine.sequence==1);
    reset();
    assert(kp_s3_inspect(&kp_stage3_provider,0x13600000,0x840fd0,K,K+0xcc0000,challenge,&recovered)==KPS3_QUERY_CHECKED);
    assert(!mutations && server.s.value==KP_STAGE3_BEFORE);
    reset();bad_token=1;assert(exercise(&o)==KPS3_TRANSPORT && !mutations && !server.s.engine.initialized);
    reset();deny=1;assert(exercise(&o)==KPS3_TRANSPORT && !mutations);
    reset();revoke_after_write=1;
    assert(exercise(&o)==KPS3_UNVERIFIED && mutations==1 && server.s.quarantined && server.s.engine.poisoned);
    assert(server.s.value==KP_STAGE3_AFTER && o.replies[2].last_result.state==KP_UNKNOWN && o.replies[2].poisoned);
    live_cr3=0x1000;revoke_after_write=0;
    assert(exercise(&o)==KPS3_REFUSED && mutations==1); /* sticky; no rearm */
    reset(); unsigned before=writes;
    assert(kp_s3_publish(STORE,K+0xcc0000,0x13600000,PMAP) && writes==before);
    reset();server.p.gate=1;
    assert(exercise(&o)==KPS3_TRANSPORT && !mutations && !server.s.engine.initialized);
}
static void policy_and_replay(void) {
    reset();struct kp_stage3_context c=context();
    struct kp_probe_request q={.abi=1,.size=sizeof(q),.operation=1,.challenge={1},.build=KPS2_BUILD_BYTES};
    struct kp_probe_reply probe;
    assert(!kp_stage3_service(&c,&q,NULL,&probe,NULL));
    struct kp_request command; kp_s3_request(&probe.identity,&command);
    struct kp_result result;
    command.operation=KP_APPLY;
    assert(!kp_stage3_service(&c,NULL,&command,NULL,&result) && result.status==KP_POLICY);
    assert(!server.s.engine.sequence && server.s.value==KP_STAGE3_BEFORE);
    kp_s3_request(&probe.identity,&command);command.offset=8;
    assert(!kp_stage3_service(&c,NULL,&command,NULL,&result) && result.status==KP_POLICY);
    kp_s3_request(&probe.identity,&command);command.session[0]^=1;
    assert(!kp_stage3_service(&c,NULL,&command,NULL,&result) && result.status==KP_POLICY);
    kp_s3_request(&probe.identity,&command);
    assert(!kp_stage3_service(&c,NULL,&command,NULL,&result) && result.status==KP_OK);
    struct kp_result cached=result;server.s.value=0x1234;
    assert(!kp_stage3_service(&c,NULL,&command,NULL,&result) && !memcmp(&cached,&result,sizeof(result)));
    assert(server.s.value==0x1234); /* exact replay never writes */
    command.sequence=2;
    assert(!kp_stage3_service(&c,NULL,&command,NULL,&result) && result.status==KP_POLICY && server.s.engine.sequence==1);
    q.build[0]^=1;
    assert(!kp_stage3_service(&c,&q,NULL,&probe,NULL) && probe.status==KP_STALE && !probe.sequence);
}
static void bridge_refusals(void) {
    reset(); struct kp_stage3_io io={.user={NULL,access_user,read_user,write_user,NULL},.service=context()};
    struct kp_stage3_envelope q={.abi=KP_ABI,.size=sizeof(q)};
    memcpy(q.token,server.p.token,32);
    struct kp_identity id=server.p.identity; id.capabilities=3;id.resident_base=context().address;
    kp_s3_request(&id,&q.command);
    struct kp_result r={0};
    uint64_t a=(uint64_t)(uintptr_t)&q,b=(uint64_t)(uintptr_t)&r;
    assert(kp_stage3_bridge(&io,KP_STAGE3_EXERCISE_SELECTOR,a,sizeof(q),b,sizeof(r),1)==EINVAL);
    assert(kp_stage3_bridge(&io,KP_STAGE3_EXERCISE_SELECTOR,a,sizeof(q)-1,b,sizeof(r),0)==EINVAL);
    assert(kp_stage3_bridge(&io,KP_STAGE3_EXERCISE_SELECTOR,a,sizeof(q),a,sizeof(r),0)==EINVAL);
    assert(kp_stage3_bridge(&io,KP_STAGE3_EXERCISE_SELECTOR,K,sizeof(q),b,sizeof(r),0)==EINVAL);
    assert(kp_stage3_bridge(&io,KP_STAGE3_EXERCISE_SELECTOR,a,sizeof(q),b,sizeof(r)-1,0)==EINVAL);
    q.token[0]^=1;
    assert(kp_stage3_bridge(&io,KP_STAGE3_EXERCISE_SELECTOR,a,sizeof(q),b,sizeof(r),0)==EACCES);
    assert(!server.s.engine.initialized && server.s.value==KP_STAGE3_BEFORE);
    memcpy(q.token,server.p.token,32); q.abi=2;
    assert(kp_stage3_bridge(&io,KP_STAGE3_EXERCISE_SELECTOR,a,sizeof(q),b,sizeof(r),0)==EINVAL);
}
static struct kp_request parallel_command;
static void *worker(void *unused) {
    (void)unused;
    struct kp_stage3_context c=context(); struct kp_result result;
    int rc=kp_stage3_service(&c,NULL,&parallel_command,NULL,&result);
    assert(rc==KP_BUSY || (rc==KP_OK && result.status==KP_OK && result.state==KP_RESTORED));
    return NULL;
}
static void concurrency(void) {
    reset();struct kp_identity id=server.p.identity;
    id.capabilities=3;id.resident_base=context().address;
    kp_s3_request(&id,&parallel_command);
    pthread_t threads[16];
    for(unsigned i=0;i<16;++i) assert(!pthread_create(&threads[i],NULL,worker,NULL));
    for(unsigned i=0;i<16;++i) assert(!pthread_join(threads[i],NULL));
    assert(server.s.engine.sequence==1 && server.s.value==KP_STAGE3_BEFORE && !server.p.gate && !server.s.lease);
}
uint32_t kernel_get_fw_version(void) { return 0x13600000; }
int sceKernelGetMainSocId(void) { return 0x840fd0; }
const intptr_t KERNEL_ADDRESS_TEXT_BASE=(intptr_t)K;
const intptr_t KERNEL_ADDRESS_DATA_BASE=(intptr_t)(K+0xcc0000);
#define KERNEL_PATCH_STAGE3_HAS_PROVIDER 1
#define main stage3_payload_main
#include "../payloads/kernel-patch-stage3/main.c"
#undef main
int main(int argc,char **argv) {
    if(argc==2) { reset();if(!strcmp(argv[1],"lost")) lost_reply=1;
        if(!strcmp(argv[1],"query-cached")) { struct kp_s3_observation o; assert(exercise(&o)==KPS3_RESTORED); }
        return stage3_payload_main(); }
    transactions();policy_and_replay();bridge_refusals();concurrency();
    printf("stage 3 owned-cell, journal, lost reply and concurrency checks passed; store=%zu\n",sizeof(server.s));
    return 0;
}
