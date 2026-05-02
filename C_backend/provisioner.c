// provisioner.c
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <sys/stat.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>

static void die(const char *m){
    fprintf(stderr, "%s\n", m);
    ERR_print_errors_fp(stderr);
    exit(1);
}
static void mkdir_p(const char *dir){
    if(mkdir(dir, 0700) != 0){
        if(errno == EEXIST) return;
        perror("mkdir");
        exit(1);
    }
}

static void write_priv_pem(const char *path, EVP_PKEY *pkey){
    FILE *f = fopen(path, "wb");
    if(!f){ perror("fopen priv"); exit(1); }
    if(PEM_write_PrivateKey(f, pkey, NULL, NULL, 0, NULL, NULL) != 1) die("PEM_write_PrivateKey");
    fclose(f);
}

static void write_pub_pem(const char *path, EVP_PKEY *pkey){
    FILE *f = fopen(path, "wb");
    if(!f){ perror("fopen pub"); exit(1); }
    if(PEM_write_PUBKEY(f, pkey) != 1) die("PEM_write_PUBKEY");
    fclose(f);
}

int main(int argc, char **argv){
    if(argc != 2){
        fprintf(stderr, "Usage: %s <out_dir>\n", argv[0]);
        return 2;
    }
    const char *outdir = argv[1];

    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    mkdir_p(outdir);

    EVP_PKEY_CTX *kctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, NULL);
    if(!kctx) die("EVP_PKEY_CTX_new_id(ED25519)");
    EVP_PKEY *id = NULL;
    if(EVP_PKEY_keygen_init(kctx) != 1) die("keygen_init");
    if(EVP_PKEY_keygen(kctx, &id) != 1) die("keygen");
    EVP_PKEY_CTX_free(kctx);

    char priv_path[512], pub_path[512], peer_pub_path[512];
    snprintf(priv_path, sizeof(priv_path), "%s/identity_priv.pem", outdir);
    snprintf(pub_path, sizeof(pub_path), "%s/identity_pub.pem", outdir);
    snprintf(peer_pub_path, sizeof(peer_pub_path), "%s/peer_identity_pub.pem", outdir);

    write_priv_pem(priv_path, id);
    write_pub_pem(pub_path, id);

    // placeholder peer pub
    FILE *pf = fopen(peer_pub_path, "wb");
    if(!pf){ perror("fopen peer placeholder"); exit(1); }
    fputs("-----BEGIN PUBLIC KEY-----\n", pf);
    fputs("REPLACE_THIS_WITH_PEER_PUBLIC_KEY\n", pf);
    fputs("-----END PUBLIC KEY-----\n", pf);
    fclose(pf);

    EVP_PKEY_free(id);

    printf("Wrote:\n  %s\n  %s\n  %s (placeholder)\n",
           priv_path, pub_path, peer_pub_path);
    printf("Next: copy identity_pub.pem across into peer_identity_pub.pem on the other side.\n");
    return 0;
}

