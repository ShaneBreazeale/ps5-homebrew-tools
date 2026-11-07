/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <ps5/kernel.h>
#include <fcntl.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>
#include "../../residents/patch/stage3_client.h"
int sceKernelGetMainSocId(void);
#ifdef KERNEL_PATCH_STAGE3_HAS_PROVIDER
extern const struct kp_stage3_provider kp_stage3_provider;
#endif
static void hex(const void *p,size_t n) {
    const unsigned char *bytes=p;
    for(size_t i=0;i<n;++i) printf("%02x",bytes[i]);
}
int main(void) {
    setvbuf(stdout,NULL,_IONBF,0);
    const struct kp_stage3_provider *provider=NULL;
#ifdef KERNEL_PATCH_STAGE3_HAS_PROVIDER
    provider=&kp_stage3_provider;
#endif
    struct kp_s3_observation observation={0};
    unsigned char challenges[3][16]={{0}};
    uint32_t fw=kernel_get_fw_version(),soc=(uint32_t)sceKernelGetMainSocId();
    uint64_t text=KERNEL_ADDRESS_TEXT_BASE,data=KERNEL_ADDRESS_DATA_BASE;
    int random_ok=1;
    if(provider) {
        int fd=open("/dev/urandom",O_RDONLY);
        if(fd<0) random_ok=0;
        else { ssize_t n=read(fd,challenges,sizeof(challenges)); int error=close(fd); random_ok=n==sizeof(challenges) && !error; }
    }
    if(!random_ok) observation.status=KPS3_CHALLENGE;
    else {
#ifdef KERNEL_PATCH_STAGE3_QUERY_ONLY
        kp_s3_inspect(provider,fw,soc,text,data,challenges[0],&observation);
#else
        kp_s3_exercise(provider,fw,soc,text,data,challenges,&observation);
#endif
    }
    printf("KP_STAGE3_JSON={\"schema\":1,\"pid\":%d,\"observed_at_unix\":%lld,\"firmware\":\"0x%x\","
        "\"soc\":\"0x%x\",\"text_base\":\"0x%llx\",\"data_base\":\"0x%llx\",\"status\":\"%s\",\"queries\":[",
        getpid(),(long long)time(NULL),fw,soc,(unsigned long long)text,(unsigned long long)data,kp_s3_status_name(observation.status));
    for(unsigned i=0;i<observation.count;++i) {
        if(i) putchar(',');
        printf("{\"transport_ok\":%s,\"request\":\"",observation.transport_ok[i]?"true":"false");
        hex(&observation.requests[i],sizeof(struct kp_probe_request)); printf("\",\"reply\":\"");
        hex(&observation.replies[i],sizeof(struct kp_probe_reply)); printf("\"}");
    }
    printf("],\"command_attempted\":%s,\"command_transport_ok\":%s,\"command\":\"",
        observation.command_attempted?"true":"false",observation.command_transport_ok?"true":"false");
    hex(&observation.command,sizeof(observation.command)); printf("\",\"result\":\"");
    hex(&observation.result,sizeof(observation.result)); puts("\"}");
    return observation.status==KPS3_RESTORED || observation.status==KPS3_RECOVERED
        || observation.status==KPS3_QUERY_CHECKED || observation.status==KPS3_CACHED ? 0 : 1;
}
