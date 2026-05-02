// sender.c — TCP file sender (big files ok)
// Protocol: [u64_be size][raw bytes]
//
// Build: gcc -O2 -Wall -Wextra -o sender sender.c
// Run:   sudo ip netns exec nsA ./sender 10.10.10.2 40000 1g.bin

#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/sendfile.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

static void die_sys(const char *m){ perror(m); exit(1); }

static void put_be64(uint8_t out[8], uint64_t v){
  for(int i=7;i>=0;i--){ out[i]=(uint8_t)(v&0xFF); v>>=8; }
}

static int send_all(int fd, const void *buf, size_t len){
  const uint8_t *p=(const uint8_t*)buf;
  size_t off=0;
  while(off<len){
    ssize_t n = send(fd, p+off, len-off, 0);
    if(n<0){
      if(errno==EINTR) continue;
      if(errno==EAGAIN || errno==EWOULDBLOCK) continue;
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

// Works for BOTH blocking and non-blocking sockets.
// If connect returns EINPROGRESS, wait for writability and check SO_ERROR.
static int connect_timeout(int s, const struct sockaddr *sa, socklen_t slen, int timeout_ms){
  int rc = connect(s, sa, slen);
  if(rc == 0) return 0;

  if(rc < 0 && errno != EINPROGRESS) return -1;

  struct pollfd pfd;
  memset(&pfd, 0, sizeof(pfd));
  pfd.fd = s;
  pfd.events = POLLOUT;

  rc = poll(&pfd, 1, timeout_ms);
  if(rc < 0) return -1;
  if(rc == 0){ errno = ETIMEDOUT; return -1; }

  int soerr = 0;
  socklen_t len = sizeof(soerr);
  if(getsockopt(s, SOL_SOCKET, SO_ERROR, &soerr, &len) < 0) return -1;
  if(soerr != 0){ errno = soerr; return -1; }

  return 0;
}

int main(int argc, char **argv){
  if(argc!=4){
    fprintf(stderr,"usage: %s <dst_ip> <port> <file>\n", argv[0]);
    return 2;
  }
  const char *ip = argv[1];
  int port = atoi(argv[2]);
  const char *path = argv[3];

  int f = open(path, O_RDONLY);
  if(f<0) die_sys("open(file)");

  struct stat st;
  if(fstat(f, &st)!=0) die_sys("fstat");
  if(!S_ISREG(st.st_mode)){
    fprintf(stderr,"not a regular file\n");
    return 2;
  }
  uint64_t fsz = (uint64_t)st.st_size;

  int s = socket(AF_INET, SOCK_STREAM, 0);
  if(s<0) die_sys("socket");

  int mss = 1200;
  if(setsockopt(s, IPPROTO_TCP, TCP_MAXSEG, &mss, sizeof(mss)) != 0){
      perror("setsockopt(TCP_MAXSEG)");
  }

  // Optional: avoid “forever hang” on send/recv if something breaks
  struct timeval tv; tv.tv_sec=10; tv.tv_usec=0;
  setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
  setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

  struct sockaddr_in dst; memset(&dst,0,sizeof(dst));
  dst.sin_family=AF_INET;
  dst.sin_port=htons((uint16_t)port);
  if(inet_pton(AF_INET, ip, &dst.sin_addr)!=1){
    fprintf(stderr,"bad ip\n");
    return 2;
  }

  if(connect_timeout(s, (struct sockaddr*)&dst, sizeof(dst), 5000)!=0)
    die_sys("connect");

  fprintf(stderr,"[S] connected to %s:%d, file=%s (%llu bytes)\n",
          ip, port, path, (unsigned long long)fsz);

  // Send header: u64 size
  uint8_t hdr[8]; put_be64(hdr, fsz);
  if(send_all(s, hdr, sizeof(hdr))!=0) die_sys("send(size)");

  // Send file content (sendfile on Linux)
  uint64_t sent_total = 0;
  uint64_t t0 = now_ms();
  uint64_t last_print = t0;

#ifdef __linux__
  off_t off = 0;
  while((uint64_t)off < fsz){
    ssize_t n = sendfile(s, f, &off, 1<<20); // 1 MiB per step
    if(n<0){
      if(errno==EINTR) continue;
      if(errno==EAGAIN || errno==EWOULDBLOCK) continue;
      die_sys("sendfile");
    }
    if(n==0) break;
    sent_total = (uint64_t)off;

    uint64_t t = now_ms();
    if(t - last_print >= 500){
      double mib = (double)sent_total / (1024.0*1024.0);
      double mib_total = (double)fsz / (1024.0*1024.0);
      double mbps = (sent_total*8.0) / ((t - t0)/1000.0) / 1e6;
      fprintf(stderr,"[S] sent %.1f / %.1f MiB (%.1f Mbps)\n", mib, mib_total, mbps);
      last_print = t;
    }
  }
#else
  uint8_t buf[1<<20];
  while(sent_total < fsz){
    ssize_t r = read(f, buf, sizeof(buf));
    if(r<0){ if(errno==EINTR) continue; die_sys("read"); }
    if(r==0) break;
    if(send_all(s, buf, (size_t)r)!=0) die_sys("send(data)");
    sent_total += (uint64_t)r;
  }
#endif

  shutdown(s, SHUT_WR);

  uint64_t t1 = now_ms();
  double sec = (t1 - t0)/1000.0;
  double mbps = (sent_total*8.0) / (sec>0?sec:1.0) / 1e6;
  fprintf(stderr,"[S] done: %llu bytes in %.2f s (%.1f Mbps)\n",
          (unsigned long long)sent_total, sec, mbps);

  close(f);
  close(s);
  return 0;
}
