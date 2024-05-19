
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <stdio.h>
#include <errno.h>
#include <time.h>
#include <stdlib.h>
#include <unistd.h>

#define MAX_ENTRY 1000000
#define SEED 1234

struct map_val_t {
        __u32 ts_val_s;
        __u32 delta;
};

struct key {
    uint8_t buf[12];
}__attribute__((packed));


struct key keys[MAX_ENTRY];
struct map_val_t vals[MAX_ENTRY];



int main(int argc, char** argv){
    if (argc != 2){
        printf("Usage: %s <Connections>\n",argv[0]);
        return -1;
    }

    int connection_num = atoi(argv[1]);
    if (connection_num > MAX_ENTRY){
        printf("Maximum connections are %d\n",MAX_ENTRY);
        return -1;
    }

    srand(SEED);
    int fd = bpf_obj_get("/sys/fs/bpf/xdp/globals/conntrack_map");
    if(fd < 0 ){
        fprintf(stderr,"WARN: Failed to open bpf map file: conntrack_map err(%d):%s\n", errno, strerror(errno));
        exit(EXIT_FAILURE);
        
    }
  
    for(int i =0 ;i< connection_num;i++){
        for(int j=0;j<3;j++){
            int temp = rand();
            memcpy (&(keys[i]) + (j*4), &temp, 4);
        }
        // if(i == 7){
        //     printf("%d\n", ((keys[i].buf[0]) << 24) + ((keys[i].buf[1]) << 16) + ((keys[i].buf[2]) << 8) + (keys[i].buf[3]));
        // }
        // printf("%d\n",i);
        vals[i].delta = 1;
        vals[i].ts_val_s = 15;
    }
    bpf_map_update_batch(fd,&keys,&vals,&connection_num,BPF_ANY);
    return 0 ;
}