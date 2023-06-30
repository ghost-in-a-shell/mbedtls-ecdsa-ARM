#define MBEDTLS_AES_C
#define MBEDTLS_SHA256_C
#define MBEDTLS_ENTROPY_C
#define MBEDTLS_CTR_DRBG_C
#define MBEDTLS_MD_C
#define MBEDTLS_BIGNUM_C
#define MBEDTLS_ECP_C      
#define MBEDTLS_ASN1_PARSE_C   
#define MBEDTLS_ASN1_WRITE_C  
#define MBEDTLS_ECDSA_C        
#define MBEDTLS_ECP_DP_SECP256R1_ENABLED  
#define MBEDTLS_ECP_DP_SECP256K1_ENABLED  
#define MBEDTLS_ECP_DP_SECP384R1_ENABLED  
#define MBEDTLS_AES_ROM_TABLES
#define MBEDTLS_PLATFORM_PRINTF_MACRO printf

#include<time.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>

#include <stdint.h>


#include <unistd.h>
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/md.h"
#include "mbedtls/ecdsa.h"
#include "mbedtls/platform.h"
#include "mbedtls/timing.h"

#define assert_exit(cond, ret) \
    do { if (!(cond)) { \
        printf("  !. assert: failed [line: %d, error: -0x%04X]\n", __LINE__, -ret); \
        goto cleanup; \
    } } while (0)

static void dump_buf(char *info, uint8_t *buf, uint32_t len)
{
    mbedtls_printf("%s", info);
    for (int i = 0; i < len; i++) {
        mbedtls_printf("%s%02X%s", i % 16 == 0 ? "\n     ":" ", 
                        buf[i], i == len - 1 ? "\n":"");
    }
}

    unsigned long long reth1;
    unsigned long long retl0;

/*
unsigned long long get_cpu_cycle()
{
	__asm__ __volatile__(
		"rdtsc" :
		"=d" (reth1),
		"=a" (retl0)
	);
	return ((reth1 << 32)|(retl0));
}
*/



int main(void)
{
	unsigned long long timer = mbedtls_timing_hardclock();
	printf("%llu",timer);
	clock_t start, end; double time_used;
    //unsigned long long tsc0 = get_cpu_cycle();
    //printf("%llu",tsc0);
    int ret = 0;
    char buf[97];
    uint8_t hash[32], msg[100];
    uint8_t *pers = "simple_ecdsa1";
    size_t rlen, slen, qlen, dlen;
    memset(msg, 0x12, sizeof(msg));
    
    //mbedtls_platform_set_printf(printf);

    mbedtls_mpi r, s;
    mbedtls_ecdsa_context ctx;
    mbedtls_md_context_t md_ctx;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;

    mbedtls_mpi_init(&r);
    mbedtls_mpi_init(&s);
    mbedtls_ecdsa_init(&ctx);  //初始化ECDSA结构体
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    /*
    mbedtls_entropy_add_source(&entropy, entropy_source, NULL,
                   MBEDTLS_ENTROPY_MAX_GATHER, MBEDTLS_ENTROPY_SOURCE_STRONG);*/
    ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, 
                                (const uint8_t *) pers, strlen(pers));
    assert_exit(ret == 0, ret);
    mbedtls_printf("\n  . setup rng ... ok\n\n");

    mbedtls_md_init(&md_ctx);
    mbedtls_md(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), msg, sizeof(msg), hash);
    mbedtls_printf("  1. hash msg ... ok\n");//计算出msg的hash值
    //产生ECDSA密钥对
    ret = mbedtls_ecdsa_genkey(&ctx, MBEDTLS_ECP_DP_SECP256K1,//选择SECP256R1
                              mbedtls_ctr_drbg_random, &ctr_drbg);
    assert_exit(ret == 0, ret);
    mbedtls_ecp_point_write_binary(&ctx.grp, &ctx.Q, 
                            MBEDTLS_ECP_PF_UNCOMPRESSED, &qlen, buf, sizeof(buf));
    dlen = mbedtls_mpi_size(&ctx.d);
    mbedtls_mpi_write_binary(&ctx.d, buf + qlen, dlen);
    dump_buf("  2. ecdsa generate keypair:", buf, qlen + dlen);
    //ECDSA签名，得到r , s
	//unsigned long long tsc1 = get_cpu_cycle();
	start = clock();

	unsigned long long timer1 = mbedtls_timing_hardclock();
    ret = mbedtls_ecdsa_sign(&ctx.grp, &r, &s, &ctx.d, 
                        hash, sizeof(hash), mbedtls_ctr_drbg_random, &ctr_drbg);
	unsigned long long timer2 = mbedtls_timing_hardclock();

	end = clock();
	time_used = ((double) (end - start)) / CLOCKS_PER_SEC;
	printf("Time used: %f\n", time_used);
	//printf("\n%llu",timer2-timer1);


	//unsigned long long tsc2 = get_cpu_cycle();
    assert_exit(ret == 0, ret);
    rlen = mbedtls_mpi_size(&r);
    slen = mbedtls_mpi_size(&s);
    mbedtls_mpi_write_binary(&r, buf, rlen);
    mbedtls_mpi_write_binary(&s, buf + rlen, slen);
    dump_buf("  3. ecdsa generate signature:", buf, rlen + slen);
	//ECDSA验签，返回0表示验证成功
	//unsigned long long tsc3 = get_cpu_cycle();
	start = clock();
	unsigned long long timer3 = mbedtls_timing_hardclock();
    ret = mbedtls_ecdsa_verify(&ctx.grp, hash, sizeof(hash), &ctx.Q, &r, &s);
	unsigned long long timer4 = mbedtls_timing_hardclock();
	end = clock();
	time_used = ((double) (end - start)) / CLOCKS_PER_SEC;
	printf("Time used: %f\n", time_used);
	//printf("\n%llu",timer4-timer3);
	//unsigned long long tsc4 = get_cpu_cycle();
    assert_exit(ret == 0, ret);
    mbedtls_printf("  4. ecdsa verify signature ... ok\n\n");
	//printf("\n%llu",tsc2-tsc1);
	//printf("\n%llu",tsc4-tsc3);
	timer = mbedtls_timing_hardclock();
	printf("%llu",timer);
	printf("\n签名性能(CPU cycles):%llu",timer2-timer1);
	printf("\n验签性能(CPU cycles):%llu\n",timer4-timer3);
cleanup:
    mbedtls_mpi_free(&r);
    mbedtls_mpi_free(&s);
    mbedtls_md_free(&md_ctx);
    mbedtls_ecdsa_free(&ctx);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);

    return(ret != 0);
}
//gcc -o ecdsa testecdsa.c -I ./mbedtls/include -L ./mbedtls/lib -lmbedtls -lmbedcrypto -lmbedx509
//arm-linux-gnueabi-gcc -o ecdsa21 testecdsa.c -I ./install1/include -L ./install1/lib -lmbedtls -lmbedcrypto -lmbedx509 -static -march=armv7-a


