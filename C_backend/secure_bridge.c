// dev_common.c (v5) — WORKING symmetric FINISH + no handshake spam after established
//
// Build:
//   gcc -O2 -Wall -Wextra -DROLE=1 -o dev1_bin dev_common.c -lcrypto
//   gcc -O2 -Wall -Wextra -DROLE=2 -o dev2_bin dev_common.c -lcrypto
//
// Run order (as you want):
//   sudo ip netns exec nsB ./receiver 40000 out
//   sudo ip netns exec nsD1 ./dev1_bin
//   sudo ip netns exec nsD2 ./dev2_bin
//   (wait until BOTH print "session established")
//   sudo ip netns exec nsA ./sender 10.10.10.2 40000 1g.bin
//
// ARP check (only after both established):
//   sudo ip netns exec nsA ip neigh flush dev vA
//   sudo ip netns exec nsA ping -c 2 10.10.10.2
//   sudo ip netns exec nsA ip neigh
#ifndef ROLE
#define ROLE 0 
#endif

#if ROLE == 0 && !defined(__INTELLISENSE__)
#error "ROLE must be defined as 1 (dev1) or 2 (dev2) via -DROLE=n"
#endif
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <linux/if.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/kdf.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#ifndef ROLE
#error "ROLE must be defined as 1 (dev1) or 2 (dev2)"
#endif

#if ROLE == 1
static const char *IF_LEFT  = "vD1L";
static const char *IF_RIGHT = "vD1R";
static const char *KEY_DIR  = "dev1_keys";
#else
static const char *IF_LEFT  = "vD2L";
static const char *IF_RIGHT = "vD2R";
static const char *KEY_DIR  = "dev2_keys";
#endif

#define SC_ETHERTYPE 0x88B5
#define SC_MAGIC "SC1G"
#define SC_VER   1

typedef enum { SC_CTRL=1, SC_DATA=2 } sc_kind_t;
typedef enum { HS_HELLO=1, HS_REPLY=2, HS_FINISH=3 } hs_type_t;

#define MAX_FRAME 4096
#define HDR_LEN 28
#define TAG_LEN 16
#define SIG_LEN 64
#define CTRL_MSG_LEN (1+1+32+32)         // hs_type, role, xpub, thash
#define CTRL_TOTAL_LEN (CTRL_MSG_LEN+SIG_LEN)

static void die_crypto(const char *m){
  fprintf(stderr, "%s\n", m);
  ERR_print_errors_fp(stderr);
  exit(1);
}
static void die_sys(const char *m){
  perror(m);
  exit(1);
}

static void put_be64(uint8_t o[8], uint64_t v){
  for(int i=7;i>=0;i--){ o[i]=(uint8_t)(v&0xFF); v>>=8; }
}
static uint64_t get_be64(const uint8_t b[8]){
  uint64_t v=0; for(int i=0;i<8;i++) v=(v<<8)|(uint64_t)b[i]; return v;
}
static uint64_t rand_u64_nonzero(void){
  uint64_t x=0;
  if(RAND_bytes((unsigned char*)&x, sizeof(x))!=1) die_crypto("RAND_bytes");
  if(x==0) x=1;
  return x;
}

static int if_index(int fd, const char *ifname){
  struct ifreq ifr; memset(&ifr,0,sizeof(ifr));
  strncpy(ifr.ifr_name, ifname, IFNAMSIZ-1);
  if(ioctl(fd, SIOCGIFINDEX, &ifr)!=0) return -1;
  return ifr.ifr_ifindex;
}
static int if_hwaddr(int fd, const char *ifname, uint8_t mac[6]){
  struct ifreq ifr; memset(&ifr,0,sizeof(ifr));
  strncpy(ifr.ifr_name, ifname, IFNAMSIZ-1);
  if(ioctl(fd, SIOCGIFHWADDR, &ifr)!=0) return -1;
  memcpy(mac, ifr.ifr_hwaddr.sa_data, 6);
  return 0;
}
static int set_promisc(int fd, const char *ifname, int enable){
  struct ifreq ifr; memset(&ifr,0,sizeof(ifr));
  strncpy(ifr.ifr_name, ifname, IFNAMSIZ-1);
  if(ioctl(fd, SIOCGIFFLAGS, &ifr)!=0) return -1;
  if(enable) ifr.ifr_flags |= IFF_PROMISC;
  else       ifr.ifr_flags &= ~IFF_PROMISC;
  if(ioctl(fd, SIOCSIFFLAGS, &ifr)!=0) return -1;
  return 0;
}

// ===== PEM load =====
static EVP_PKEY* load_priv(const char *path){
  FILE *f=fopen(path,"rb");
  if(!f) return NULL;
  EVP_PKEY *p=PEM_read_PrivateKey(f,NULL,NULL,NULL);
  fclose(f);
  return p;
}
static EVP_PKEY* load_pub(const char *path){
  FILE *f=fopen(path,"rb");
  if(!f) return NULL;
  EVP_PKEY *p=PEM_read_PUBKEY(f,NULL,NULL,NULL);
  fclose(f);
  return p;
}

// ===== Ed25519 sign/verify =====
static int ed25519_sign(EVP_PKEY *priv, const uint8_t *msg, size_t msg_len, uint8_t sig[64]){
  size_t siglen=64;
  EVP_MD_CTX *ctx=EVP_MD_CTX_new();
  if(!ctx) return -1;
  if(EVP_DigestSignInit(ctx,NULL,NULL,NULL,priv)!=1){ EVP_MD_CTX_free(ctx); return -1; }
  if(EVP_DigestSign(ctx,sig,&siglen,msg,msg_len)!=1){ EVP_MD_CTX_free(ctx); return -1; }
  EVP_MD_CTX_free(ctx);
  return (siglen==64)?0:-1;
}
static int ed25519_verify(EVP_PKEY *pub, const uint8_t *msg, size_t msg_len, const uint8_t sig[64]){
  EVP_MD_CTX *ctx=EVP_MD_CTX_new();
  if(!ctx) return -1;
  if(EVP_DigestVerifyInit(ctx,NULL,NULL,NULL,pub)!=1){ EVP_MD_CTX_free(ctx); return -1; }
  int ok = EVP_DigestVerify(ctx,sig,64,msg,msg_len);
  EVP_MD_CTX_free(ctx);
  return (ok==1)?0:-1;
}

// ===== X25519 =====
static EVP_PKEY* x25519_gen(void){
  EVP_PKEY_CTX *kctx=EVP_PKEY_CTX_new_id(EVP_PKEY_X25519,NULL);
  if(!kctx) return NULL;
  EVP_PKEY *k=NULL;
  if(EVP_PKEY_keygen_init(kctx)!=1){ EVP_PKEY_CTX_free(kctx); return NULL; }
  if(EVP_PKEY_keygen(kctx,&k)!=1){ EVP_PKEY_CTX_free(kctx); return NULL; }
  EVP_PKEY_CTX_free(kctx);
  return k;
}
static int x25519_pub(EVP_PKEY *k, uint8_t out[32]){
  size_t len=32;
  if(EVP_PKEY_get_raw_public_key(k,out,&len)!=1) return -1;
  return (len==32)?0:-1;
}
static int x25519_derive(EVP_PKEY *my_priv, const uint8_t peer_pub[32], uint8_t shared[32]){
  EVP_PKEY *peer=EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519,NULL,peer_pub,32);
  if(!peer) return -1;
  EVP_PKEY_CTX *ctx=EVP_PKEY_CTX_new(my_priv,NULL);
  if(!ctx){ EVP_PKEY_free(peer); return -1; }
  size_t outlen=32;
  if(EVP_PKEY_derive_init(ctx)!=1) goto fail;
  if(EVP_PKEY_derive_set_peer(ctx,peer)!=1) goto fail;
  if(EVP_PKEY_derive(ctx,shared,&outlen)!=1) goto fail;
  EVP_PKEY_CTX_free(ctx);
  EVP_PKEY_free(peer);
  return (outlen==32)?0:-1;
fail:
  EVP_PKEY_CTX_free(ctx);
  EVP_PKEY_free(peer);
  return -1;
}

// ===== HKDF-SHA256 =====
static int hkdf_sha256(const uint8_t *ikm, size_t ikm_len,
                       const uint8_t *salt, size_t salt_len,
                       const uint8_t *info, size_t info_len,
                       uint8_t *out, size_t out_len){
  EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
  if(!pctx) return -1;
  if(EVP_PKEY_derive_init(pctx)!=1) { EVP_PKEY_CTX_free(pctx); return -1; }
  if(EVP_PKEY_CTX_set_hkdf_md(pctx, EVP_sha256())!=1){ EVP_PKEY_CTX_free(pctx); return -1; }
  if(EVP_PKEY_CTX_set1_hkdf_salt(pctx, salt, (int)salt_len)!=1){ EVP_PKEY_CTX_free(pctx); return -1; }
  if(EVP_PKEY_CTX_set1_hkdf_key(pctx, ikm, (int)ikm_len)!=1){ EVP_PKEY_CTX_free(pctx); return -1; }
  if(EVP_PKEY_CTX_add1_hkdf_info(pctx, info, (int)info_len)!=1){ EVP_PKEY_CTX_free(pctx); return -1; }
  size_t L = out_len;
  if(EVP_PKEY_derive(pctx, out, &L)!=1){ EVP_PKEY_CTX_free(pctx); return -1; }
  EVP_PKEY_CTX_free(pctx);
  return (L==out_len)?0:-1;
}

// ===== AES-256-GCM =====
static int aead_gcm_encrypt(const uint8_t key[32], const uint8_t nonce[12],
                            const uint8_t *aad, size_t aad_len,
                            const uint8_t *pt, size_t pt_len,
                            uint8_t *ct, uint8_t tag[16]){
  EVP_CIPHER_CTX *ctx=EVP_CIPHER_CTX_new();
  if(!ctx) return -1;
  int len=0, outlen=0;
  if(EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL)!=1) goto err;
  if(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL)!=1) goto err;
  if(EVP_EncryptInit_ex(ctx, NULL, NULL, key, nonce)!=1) goto err;
  if(aad && aad_len){
    if(EVP_EncryptUpdate(ctx, NULL, &len, aad, (int)aad_len)!=1) goto err;
  }
  if(pt_len){
    if(EVP_EncryptUpdate(ctx, ct, &len, pt, (int)pt_len)!=1) goto err;
    outlen = len;
  }
  if(EVP_EncryptFinal_ex(ctx, ct + outlen, &len)!=1) goto err;
  outlen += len;
  if(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag)!=1) goto err;
  EVP_CIPHER_CTX_free(ctx);
  return outlen==(int)pt_len ? 0 : -1;
err:
  EVP_CIPHER_CTX_free(ctx);
  return -1;
}

static int aead_gcm_decrypt(const uint8_t key[32], const uint8_t nonce[12],
                            const uint8_t *aad, size_t aad_len,
                            const uint8_t *ct, size_t ct_len,
                            const uint8_t tag[16],
                            uint8_t *pt){
  EVP_CIPHER_CTX *ctx=EVP_CIPHER_CTX_new();
  if(!ctx) return -1;
  int len=0, outlen=0;
  if(EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL)!=1) goto err;
  if(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL)!=1) goto err;
  if(EVP_DecryptInit_ex(ctx, NULL, NULL, key, nonce)!=1) goto err;
  if(aad && aad_len){
    if(EVP_DecryptUpdate(ctx, NULL, &len, aad, (int)aad_len)!=1) goto err;
  }
  if(ct_len){
    if(EVP_DecryptUpdate(ctx, pt, &len, ct, (int)ct_len)!=1) goto err;
    outlen = len;
  }
  if(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, (void*)tag)!=1) goto err;
  if(EVP_DecryptFinal_ex(ctx, pt + outlen, &len)!=1) goto err;
  outlen += len;
  EVP_CIPHER_CTX_free(ctx);
  return outlen==(int)ct_len ? 0 : -1;
err:
  EVP_CIPHER_CTX_free(ctx);
  return -1;
}

// ===== Canonical transcript hash =====
static int transcript_hash(uint8_t out[32],
                           uint8_t role_a, const uint8_t xpub_a[32],
                           uint8_t role_b, const uint8_t xpub_b[32]){
  uint8_t r1, r2;
  const uint8_t *k1, *k2;
  if(role_a < role_b){
    r1 = role_a; k1 = xpub_a;
    r2 = role_b; k2 = xpub_b;
  } else {
    r1 = role_b; k1 = xpub_b;
    r2 = role_a; k2 = xpub_a;
  }
  static const uint8_t label[] = "SC1G-HS-v1";
  EVP_MD_CTX *ctx = EVP_MD_CTX_new();
  if(!ctx) return -1;
  unsigned int outlen=0;
  if(EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1) goto err;
  if(EVP_DigestUpdate(ctx, label, sizeof(label)-1) != 1) goto err;
  if(EVP_DigestUpdate(ctx, &r1, 1) != 1) goto err;
  if(EVP_DigestUpdate(ctx, k1, 32) != 1) goto err;
  if(EVP_DigestUpdate(ctx, &r2, 1) != 1) goto err;
  if(EVP_DigestUpdate(ctx, k2, 32) != 1) goto err;
  if(EVP_DigestFinal_ex(ctx, out, &outlen) != 1) goto err;
  EVP_MD_CTX_free(ctx);
  return (outlen==32)?0:-1;
err:
  EVP_MD_CTX_free(ctx);
  return -1;
}

// ===== Wire header/nonce =====
static void fill_hdr(uint8_t *p, uint8_t kind, uint8_t dir, uint64_t seq, const uint8_t nonce[12]){
  memcpy(p, SC_MAGIC, 4);
  p[4]=SC_VER;
  p[5]=kind;
  p[6]=dir;
  p[7]=0;
  uint8_t be[8]; put_be64(be, seq);
  memcpy(p+8, be, 8);
  memcpy(p+16, nonce, 12);
}
static void make_nonce(uint8_t nonce[12], const uint8_t salt4[4], uint64_t seq){
  uint8_t be[8]; put_be64(be, seq);
  memcpy(nonce, salt4, 4);
  memcpy(nonce+4, be, 8);
}

static int send_raw_on_if(int s, int ifidx, const uint8_t *frame, size_t len, const uint8_t dst_mac[6]){
  struct sockaddr_ll to; memset(&to,0,sizeof(to));
  to.sll_family=AF_PACKET;
  to.sll_ifindex=ifidx;
  to.sll_halen=ETH_ALEN;
  memcpy(to.sll_addr, dst_mac, 6);
  return (sendto(s, frame, len, 0, (struct sockaddr*)&to, sizeof(to))<0) ? -1 : 0;
}

static int is_secure_frame(const uint8_t *buf, size_t n){
  if(n < sizeof(struct ethhdr) + HDR_LEN) return 0;
  const struct ethhdr *eh=(const struct ethhdr*)buf;
  if(ntohs(eh->h_proto)!=SC_ETHERTYPE) return 0;
  const uint8_t *p = buf + sizeof(struct ethhdr);
  return memcmp(p, SC_MAGIC, 4)==0 && p[4]==SC_VER;
}

// ctrl builder: ALWAYS includes xpub + thash
static int build_ctrl(uint8_t hs_type, uint8_t role,
                      const uint8_t xpub[32],
                      const uint8_t thash[32],
                      EVP_PKEY *id_priv,
                      uint8_t out[CTRL_TOTAL_LEN]){
  out[0]=hs_type;
  out[1]=role;
  memcpy(out+2, xpub, 32);
  memcpy(out+34, thash, 32);
  if(ed25519_sign(id_priv, out, CTRL_MSG_LEN, out+CTRL_MSG_LEN)!=0) return -1;
  return 0;
}
static int verify_ctrl(const uint8_t in[CTRL_TOTAL_LEN], EVP_PKEY *peer_pub){
  return ed25519_verify(peer_pub, in, CTRL_MSG_LEN, in+CTRL_MSG_LEN);
}

static int send_ctrl_frame(int s, int out_ifidx, const uint8_t out_src_mac[6], const uint8_t out_dst_mac[6],
                           uint8_t dir, const uint8_t ctrl[CTRL_TOTAL_LEN]){
  uint8_t frame[MAX_FRAME];
  struct ethhdr *eh=(struct ethhdr*)frame;
  memcpy(eh->h_dest, out_dst_mac, 6);
  memcpy(eh->h_source, out_src_mac, 6);
  eh->h_proto = htons(SC_ETHERTYPE);

  uint8_t *p = frame + sizeof(struct ethhdr);
  uint8_t nonce[12]={0};
  fill_hdr(p, SC_CTRL, dir, 0, nonce);
  memcpy(p + HDR_LEN, ctrl, CTRL_TOTAL_LEN);

  size_t len = sizeof(struct ethhdr) + HDR_LEN + CTRL_TOTAL_LEN;
  return send_raw_on_if(s, out_ifidx, frame, len, out_dst_mac);
}

// ===== State =====
typedef struct {
  uint8_t session_key[32];
  uint8_t salt_lr[4];
  uint8_t salt_rl[4];
  uint64_t send_seq_lr;
  uint64_t send_seq_rl;
  uint64_t last_recv_lr;
  uint64_t last_recv_rl;
  int established;
} sc_state_t;

typedef struct {
  EVP_PKEY *id_priv;
  EVP_PKEY *peer_id_pub;
  EVP_PKEY *eph;
  uint8_t my_xpub[32];

  uint8_t peer_xpub[32];
  uint8_t peer_role;
  int have_peer_xpub;

  int sent_finish;
} hs_ctx_t;

static int hs_init(hs_ctx_t *h, EVP_PKEY *id_priv, EVP_PKEY *peer_id_pub){
  memset(h,0,sizeof(*h));
  h->id_priv=id_priv;
  h->peer_id_pub=peer_id_pub;
  h->eph=x25519_gen();
  if(!h->eph) return -1;
  if(x25519_pub(h->eph, h->my_xpub)!=0) return -1;
  return 0;
}

static int derive_session(sc_state_t *st, hs_ctx_t *h){
  uint8_t shared[32];
  if(x25519_derive(h->eph, h->peer_xpub, shared)!=0) return -1;

  uint8_t th[32];
  if(transcript_hash(th, (uint8_t)ROLE, h->my_xpub, h->peer_role, h->peer_xpub)!=0) return -1;

  uint8_t okm[32+8];
  const uint8_t info[]="SC1G-DATA-v1";
  if(hkdf_sha256(shared,32, th,32, info,sizeof(info)-1, okm,sizeof(okm))!=0) return -1;

  memcpy(st->session_key, okm, 32);
  memcpy(st->salt_lr, okm+32, 4);
  memcpy(st->salt_rl, okm+36, 4);

  st->send_seq_lr = rand_u64_nonzero();
  st->send_seq_rl = rand_u64_nonzero();
  st->last_recv_lr = 0;
  st->last_recv_rl = 0;
  st->established = 1;

  fprintf(stderr,"[DEV%u] session established; salts lr=%02x%02x%02x%02x rl=%02x%02x%02x%02x\n",
          (unsigned)ROLE,
          st->salt_lr[0],st->salt_lr[1],st->salt_lr[2],st->salt_lr[3],
          st->salt_rl[0],st->salt_rl[1],st->salt_rl[2],st->salt_rl[3]);
  return 0;
}

typedef struct {
  uint8_t peer_left[6];
  uint8_t peer_right[6];
  int have_peer_left;
  int have_peer_right;
} peers_t;

static void print_mac(const char *lbl, const uint8_t m[6]){
  fprintf(stderr,"%s%02x:%02x:%02x:%02x:%02x:%02x\n", lbl,
          m[0],m[1],m[2],m[3],m[4],m[5]);
}

// symmetric FINISH sender (called on HELLO or REPLY)
static void maybe_send_finish(int s,
                              hs_ctx_t *hs,
                              int in_is_left, int in_is_right,
                              int ifL, int ifR,
                              const uint8_t macL[6], const uint8_t macR[6],
                              const uint8_t dst_mac[6],
                              uint8_t dir)
{
  if(hs->sent_finish) return;
  if(!hs->have_peer_xpub) return;

  uint8_t th[32];
  if(transcript_hash(th, (uint8_t)ROLE, hs->my_xpub, hs->peer_role, hs->peer_xpub)!=0) return;

  uint8_t outctrl[CTRL_TOTAL_LEN];
  if(build_ctrl(HS_FINISH, (uint8_t)ROLE, hs->my_xpub, th, hs->id_priv, outctrl)!=0) return;

  if(in_is_left)  (void)send_ctrl_frame(s, ifL, macL, dst_mac, dir, outctrl);
  if(in_is_right) (void)send_ctrl_frame(s, ifR, macR, dst_mac, dir, outctrl);

  hs->sent_finish = 1;
  fprintf(stderr,"[DEV%u] sent FINISH\n", (unsigned)ROLE);
}

// ===== Data plane =====
static int send_data(sc_state_t *st, int s, int out_ifidx, const uint8_t out_src_mac[6], const uint8_t out_dst_mac[6],
                     uint8_t dir, const uint8_t *orig_frame, size_t orig_len){
  uint8_t frame[MAX_FRAME];
  if(sizeof(frame) < sizeof(struct ethhdr) + HDR_LEN + orig_len + TAG_LEN) return -1;

  struct ethhdr *eh=(struct ethhdr*)frame;
  memcpy(eh->h_dest, out_dst_mac, 6);
  memcpy(eh->h_source, out_src_mac, 6);
  eh->h_proto = htons(SC_ETHERTYPE);

  uint8_t *p = frame + sizeof(struct ethhdr);

  uint64_t seq = (dir==0) ? st->send_seq_lr++ : st->send_seq_rl++;
  uint8_t nonce[12];
  make_nonce(nonce, (dir==0)?st->salt_lr:st->salt_rl, seq);

  fill_hdr(p, SC_DATA, dir, seq, nonce);

  const uint8_t *aad = p;
  const size_t aad_len = HDR_LEN;

  uint8_t *ct = p + HDR_LEN;
  uint8_t tag[16];
  if(aead_gcm_encrypt(st->session_key, nonce, aad, aad_len, orig_frame, orig_len, ct, tag)!=0) return -1;
  memcpy(ct + orig_len, tag, 16);
  
  fprintf(stderr, "ENTROPY_DATA: ");
  for(size_t i = 0; i < orig_len && i < 16; i++) { fprintf(stderr, "%02x", ct[i]); }
  fprintf(stderr, "\n");

  size_t len = sizeof(struct ethhdr) + HDR_LEN + orig_len + 16;
  return send_raw_on_if(s, out_ifidx, frame, len, out_dst_mac);
}

static int decrypt_data(sc_state_t *st, const uint8_t *in, size_t in_len,
                        uint8_t *out_frame, size_t *out_len){
  if(in_len < sizeof(struct ethhdr) + HDR_LEN + TAG_LEN) return -1;
  const uint8_t *p = in + sizeof(struct ethhdr);
  if(p[5] != SC_DATA) return -1;

  uint8_t dir = p[6];
  uint64_t seq = get_be64(p+8);
  const uint8_t *nonce = p+16;

  if(dir==0){
    if(seq <= st->last_recv_lr) return -1;
  } else {
    if(seq <= st->last_recv_rl) return -1;
  }

  size_t ct_len = in_len - sizeof(struct ethhdr) - HDR_LEN - 16;
  const uint8_t *ct = p + HDR_LEN;
  const uint8_t *tag = ct + ct_len;

  if(ct_len > MAX_FRAME) return -1;
  if(aead_gcm_decrypt(st->session_key, nonce, p, HDR_LEN, ct, ct_len, tag, out_frame)!=0) return -1;

  *out_len = ct_len;
  if(dir==0) st->last_recv_lr = seq;
  else       st->last_recv_rl = seq;
  return 0;
}

int main(void){
  OpenSSL_add_all_algorithms();
  ERR_load_crypto_strings();

  char priv_path[512], peer_pub_path[512];
  snprintf(priv_path, sizeof(priv_path), "%s/identity_priv.pem", KEY_DIR);
  snprintf(peer_pub_path, sizeof(peer_pub_path), "%s/peer_identity_pub.pem", KEY_DIR);

  EVP_PKEY *id_priv = load_priv(priv_path);
  if(!id_priv){
    fprintf(stderr,"[DEV%u] cannot load %s\n",(unsigned)ROLE, priv_path);
    die_sys("load identity_priv.pem");
  }
  EVP_PKEY *peer_pub = load_pub(peer_pub_path);
  if(!peer_pub){
    fprintf(stderr,"[DEV%u] Cannot load %s. Did you copy peer identity pub?\n", (unsigned)ROLE, peer_pub_path);
    return 1;
  }

  hs_ctx_t hs;
  if(hs_init(&hs, id_priv, peer_pub)!=0) die_crypto("hs_init");

  sc_state_t st; memset(&st,0,sizeof(st));
  peers_t peers; memset(&peers,0,sizeof(peers));

  int s = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
  if(s<0) die_sys("socket(AF_PACKET)");

  int flags = fcntl(s, F_GETFL, 0);
  if(flags < 0) die_sys("fcntl F_GETFL");
  if(fcntl(s, F_SETFL, flags | O_NONBLOCK) < 0) die_sys("fcntl F_SETFL O_NONBLOCK");

  int ifL = if_index(s, IF_LEFT);
  int ifR = if_index(s, IF_RIGHT);
  if(ifL<0 || ifR<0) die_sys("if_index");

  if(set_promisc(s, IF_LEFT, 1)!=0) die_sys("promisc left");
  if(set_promisc(s, IF_RIGHT, 1)!=0) die_sys("promisc right");

  uint8_t macL[6], macR[6];
  if(if_hwaddr(s, IF_LEFT, macL)!=0) die_sys("if_hwaddr left");
  if(if_hwaddr(s, IF_RIGHT, macR)!=0) die_sys("if_hwaddr right");

  fprintf(stderr,"[DEV%u] up. left=%s right=%s keydir=%s\n", (unsigned)ROLE, IF_LEFT, IF_RIGHT, KEY_DIR);
  print_mac("[DEV] macL=", macL);
  print_mac("[DEV] macR=", macR);

  uint8_t buf[MAX_FRAME];
  uint8_t plain[MAX_FRAME];
  time_t last_hello = 0;

  for(;;){
    time_t now = time(NULL);
    if(!st.established && now != last_hello){
      last_hello = now;
      uint8_t zth[32]={0};
      uint8_t ctrl[CTRL_TOTAL_LEN];
      if(build_ctrl(HS_HELLO, (uint8_t)ROLE, hs.my_xpub, zth, hs.id_priv, ctrl)==0){
        uint8_t bcast[6]={0xff,0xff,0xff,0xff,0xff,0xff};
        (void)send_ctrl_frame(s, ifR, macR, bcast, 0, ctrl);
        (void)send_ctrl_frame(s, ifL, macL, bcast, 1, ctrl);
        fprintf(stderr,"[DEV%u] sent broadcast HELLO\n", (unsigned)ROLE);
      }
    }

    struct sockaddr_ll from; socklen_t flen=sizeof(from);
    ssize_t n = recvfrom(s, buf, sizeof(buf), 0, (struct sockaddr*)&from, &flen);
    if(n < 0){
      if(errno == EINTR) continue;
      if(errno == EAGAIN || errno == EWOULDBLOCK){
          //mamikon
        usleep(1000);
        continue;
      }
      die_sys("recvfrom");
    }
    if(n < (ssize_t)sizeof(struct ethhdr)) continue;

    int in_if = from.sll_ifindex;
    int in_is_left = (in_if == ifL);
    int in_is_right = (in_if == ifR);
    if(!in_is_left && !in_is_right) continue;

    struct ethhdr *eh=(struct ethhdr*)buf;

    // secure frames?
    if(ntohs(eh->h_proto)==SC_ETHERTYPE && is_secure_frame(buf,(size_t)n)){
      const uint8_t *p = buf + sizeof(struct ethhdr);
      uint8_t kind = p[5];
      uint8_t dir  = p[6];

      if(in_is_left && !peers.have_peer_left){
        memcpy(peers.peer_left, eh->h_source, 6);
        peers.have_peer_left=1;
        fprintf(stderr,"[DEV%u] learned peer_left\n",(unsigned)ROLE);
        print_mac("  peer_left=", peers.peer_left);
      }
      if(in_is_right && !peers.have_peer_right){
        memcpy(peers.peer_right, eh->h_source, 6);
        peers.have_peer_right=1;
        fprintf(stderr,"[DEV%u] learned peer_right\n",(unsigned)ROLE);
        print_mac("  peer_right=", peers.peer_right);
      }

      if(kind == SC_CTRL){
        if((size_t)n < sizeof(struct ethhdr)+HDR_LEN+CTRL_TOTAL_LEN) continue;
        const uint8_t *ctrl = p + HDR_LEN;

        if(verify_ctrl(ctrl, hs.peer_id_pub)!=0){
          fprintf(stderr,"[DEV%u] ctrl signature verify failed (drop)\n",(unsigned)ROLE);
          continue;
        }

        // if already established, ignore handshake chatter
        if(st.established) continue;

        uint8_t hs_type = ctrl[0];
        uint8_t peer_role = ctrl[1];
        const uint8_t *peer_xpub = ctrl+2;
        const uint8_t *peer_th   = ctrl+34;

        if(peer_role == ROLE) continue;

        hs.peer_role = peer_role;
        memcpy(hs.peer_xpub, peer_xpub, 32);
        hs.have_peer_xpub = 1;

        if(hs_type == HS_HELLO){
          uint8_t zth[32]={0};
          uint8_t outctrl[CTRL_TOTAL_LEN];
          if(build_ctrl(HS_REPLY, (uint8_t)ROLE, hs.my_xpub, zth, hs.id_priv, outctrl)==0){
            const uint8_t *dst = eh->h_source;
            if(in_is_left)  (void)send_ctrl_frame(s, ifL, macL, dst, dir, outctrl);
            if(in_is_right) (void)send_ctrl_frame(s, ifR, macR, dst, dir, outctrl);
            fprintf(stderr,"[DEV%u] replied REPLY\n",(unsigned)ROLE);
          }
          maybe_send_finish(s, &hs, in_is_left, in_is_right, ifL, ifR, macL, macR, eh->h_source, dir);
        } else if(hs_type == HS_REPLY){
          maybe_send_finish(s, &hs, in_is_left, in_is_right, ifL, ifR, macL, macR, eh->h_source, dir);
        } else if(hs_type == HS_FINISH){
          uint8_t th[32];
          if(transcript_hash(th, (uint8_t)ROLE, hs.my_xpub, hs.peer_role, hs.peer_xpub)!=0) continue;

          if(memcmp(peer_th, th, 32)!=0){
            fprintf(stderr,"[DEV%u] FINISH transcript mismatch drop\n",(unsigned)ROLE);
            continue;
          }
          fprintf(stderr,"[DEV%u] got FINISH (ok)\n",(unsigned)ROLE);

          if(!st.established && hs.have_peer_xpub){
            if(derive_session(&st, &hs)!=0) die_crypto("derive_session");
          }
        }
        continue;
      }

      if(kind == SC_DATA){
        if(!st.established) continue;

        size_t out_len=0;
        if(decrypt_data(&st, buf, (size_t)n, plain, &out_len)!=0){
          continue;
        }

        int out_if = in_is_left ? ifR : ifL;

        struct sockaddr_ll to; memset(&to,0,sizeof(to));
        to.sll_family=AF_PACKET;
        to.sll_ifindex=out_if;
        to.sll_halen=ETH_ALEN;

        struct ethhdr *peh=(struct ethhdr*)plain;
        memcpy(to.sll_addr, peh->h_dest, 6);

        (void)sendto(s, plain, out_len, 0, (struct sockaddr*)&to, sizeof(to));
        continue;
      }

      continue;
    }

    // plaintext frames
    if(!st.established) continue;

    if(in_is_left){
      uint8_t dst[6];
      if(peers.have_peer_right) memcpy(dst, peers.peer_right, 6);
      else memset(dst, 0xff, 6);
      (void)send_data(&st, s, ifR, macR, dst, 0, buf, (size_t)n);
    } else if(in_is_right){
      uint8_t dst[6];
      if(peers.have_peer_left) memcpy(dst, peers.peer_left, 6);
      else memset(dst, 0xff, 6);
      (void)send_data(&st, s, ifL, macL, dst, 1, buf, (size_t)n);
    }
  }
}
