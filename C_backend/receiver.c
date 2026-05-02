// receiver.c v2 — robust TCP file receiver
// Protocol: [u64_be size][raw bytes]
// Build: gcc -O2 -Wall -Wextra -o receiver receiver.c
// Run:   sudo ip netns exec nsB ./receiver 40000 out/received.bin

#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>
#include <fcntl.h>
static void die_sys(const char *m){ perror(m); exit(1); }

static uint64_t get_be64(const uint8_t b[8]){
  uint64_t v=0; for(int i=0;i<8;i++) v=(v<<8)|(uint64_t)b[i]; return v;
}

static int recv_all_blocking(int fd, void *buf, size_t len){
  uint8_t *p=(uint8_t*)buf;
  size_t off=0;
  while(off<len){
    ssize_t n = recv(fd, p+off, len-off, 0);
    if(n<0){
      if(errno==EINTR) continue;
      if(errno==EAGAIN || errno==EWOULDBLOCK) continue; // just wait more
      return -1;
    }
    if(n==0) return -1;
    off += (size_t)n;
  }
  return 0;
}

static uint64_t now_ms(void){
  struct timespec ts; clock_gettime(CLOCK_MONOTONIC, &ts);
  return (uint64_t)ts.tv_sec*1000ull + (uint64_t)ts.tv_nsec/1000000ull;
}

int main(int argc, char **argv){
  if(argc!=3){
    fprintf(stderr,"usage: %s <port> <out_file>\n", argv[0]);
    return 2;
  }
  int port = atoi(argv[1]);
  const char *out_path = argv[2];

  int l = socket(AF_INET, SOCK_STREAM, 0);
  if(l<0) die_sys("socket");

  int one=1;
  int mss = 1300;
  setsockopt(l, SOL_SOCKET, SO_REUSEADDR, &mss, sizeof(one));

  struct sockaddr_in addr; memset(&addr,0,sizeof(addr));
  addr.sin_family=AF_INET;
  addr.sin_port=htons((uint16_t)port);
  addr.sin_addr.s_addr = htonl(INADDR_ANY);

  if(bind(l, (struct sockaddr*)&addr, sizeof(addr))!=0) die_sys("bind");
  if(listen(l, 16)!=0) die_sys("listen");

  fprintf(stderr,"[R] listening on 0.0.0.0:%d\n", port);

  for(;;){
    int c = accept(l, NULL, NULL);
    if(c<0){ if(errno==EINTR) continue; die_sys("accept"); }

    // IMPORTANT: no SO_RCVTIMEO here (avoid EAGAIN timeouts)
    uint8_t hdr[8];
    if(recv_all_blocking(c, hdr, 8)!=0){
      fprintf(stderr,"[R] failed to read size\n");
      close(c);
      continue;
    }
    uint64_t fsz = get_be64(hdr);
    fprintf(stderr,"[R] incoming file size: %llu bytes\n", (unsigned long long)fsz);

    int out = open(out_path, O_CREAT|O_TRUNC|O_WRONLY, 0644);
    if(out<0) die_sys("open(out)");

    uint8_t buf[1<<20];
    uint64_t got=0;
    uint64_t t0=now_ms(), last=t0;

    while(got < fsz){
      size_t want = (fsz-got > sizeof(buf)) ? sizeof(buf) : (size_t)(fsz-got);
      ssize_t n = recv(c, buf, want, 0);
      if(n<0){
        if(errno==EINTR) continue;
        if(errno==EAGAIN || errno==EWOULDBLOCK) continue; // wait more
        die_sys("recv(data)");
      }
      if(n==0){
        fprintf(stderr,"[R] EOF early: got=%llu expected=%llu\n",
                (unsigned long long)got, (unsigned long long)fsz);
        break;
      }

      size_t off=0;
      while(off<(size_t)n){
        ssize_t w = write(out, buf+off, (size_t)n-off);
        if(w<0){
          if(errno==EINTR) continue;
          die_sys("write");
        }
        off += (size_t)w;
      }
      got += (uint64_t)n;

      uint64_t t=now_ms();
      if(t-last >= 500){
        double mib = (double)got/(1024.0*1024.0);
        double mib_total = (double)fsz/(1024.0*1024.0);
        double mbps = (got*8.0)/((t-t0)/1000.0)/1e6;
        fprintf(stderr,"[R] got %.1f / %.1f MiB (%.1f Mbps)\n", mib, mib_total, mbps);
        last=t;
      }
    }

    fsync(out);
    close(out);
    close(c);

    uint64_t t1=now_ms();
    double sec=(t1-t0)/1000.0;
    double mbps=(got*8.0)/(sec>0?sec:1.0)/1e6;
    fprintf(stderr,"[R] done: %llu bytes in %.2f s (%.1f Mbps)\n",
            (unsigned long long)got, sec, mbps);
  }
}
