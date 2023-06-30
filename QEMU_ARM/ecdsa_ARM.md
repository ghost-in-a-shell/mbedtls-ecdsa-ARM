# Mbed-TLS中ECDSA算法在ARM架构上的性能测试

## 一、结果

### 1.使用曲线secp256r1

**签名性能：22694.1 cycles**

**验签性能：77037.7 cycles**

|                       | **平均** | 1     | 2     | 3     | 4     | 5     | 6     | 7     | 8     | 9     | 10    | 11    | 12    |
| --------------------- | -------- | ----- | ----- | ----- | ----- | ----- | ----- | ----- | ----- | ----- | ----- | ----- | ----- |
| 签名性能（CPUcycles） | 22694.1  | 23555 | 22663 | 23091 | 22375 | 22056 | 22898 | 22221 | 22063 | 22035 | 22166 | 23211 | 23995 |
| 验签性能（CPUcycles） | 77037.7  | 85121 | 76477 | 76473 | 78947 | 75992 | 75129 | 75285 | 74920 | 75132 | 75343 | 78629 | 77004 |

### 2.使用曲线secp384r1

**签名性能：49213.2 cycles**

**验签性能：164329.9 cycles**

|                       | **平均** | 1      | 2      | 3      | 4      | 5      | 6      | 7      | 8      | 9      | 10     | 11     | 12     |
| --------------------- | -------- | ------ | ------ | ------ | ------ | ------ | ------ | ------ | ------ | ------ | ------ | ------ | ------ |
| 签名性能（CPUcycles） | 49213.2  | 51044  | 47815  | 47932  | 47914  | 49323  | 49220  | 48358  | 48980  | 49382  | 51638  | 50063  | 48889  |
| 验签性能（CPUcycles） | 164329.9 | 167357 | 244551 | 154623 | 155806 | 155787 | 155419 | 156549 | 153895 | 154200 | 161620 | 155390 | 156762 |

### 3.使用曲线secp256k1

**签名性能：21187.9 cycles**

**验签性能：67489.7 cycles**

|                       | **平均** | 1     | 2     | 3     | 4     | 5     | 6     | 7     | 8     | 9     | 10    | 11    | 12    |
| --------------------- | -------- | ----- | ----- | ----- | ----- | ----- | ----- | ----- | ----- | ----- | ----- | ----- | ----- |
| 签名性能（CPUcycles） | 21187.9  | 22697 | 22983 | 20965 | 20258 | 20622 | 22151 | 20527 | 20657 | 21580 | 20156 | 21103 | 20556 |
| 验签性能（CPUcycles） | 67489.7  | 74695 | 71006 | 66123 | 65922 | 65380 | 67939 | 66148 | 65031 | 69162 | 67202 | 65034 | 66234 |

--注：代码位置：https://github.com/ghost-in-a-shell/mbedtls-ecdsa-ARM

--注：效林学长之前在NXP LPC55S69上的测定结果：签名：23655 cycles 验签：50595 cycles ，供参考

## 二、测试环境及方法

**物理机系统：ubuntu18.04** 

**物理机架构：x86_64**

**虚拟机平台：qemu**

**虚拟机架构：armv7（vexpress a9）**

**虚拟机系统：linux，内核版本4.1.14**

**MbedTLS版本：2.28.3**

**交叉编译工具链：arm-linux-gnueabi-gcc**



**mbedtls库中的timing.h提供了如下函数可以记录cpu cycle计数**

| unsigned long | mbedtls_timing_hardclock           |
| ------------- | ---------------------------------- |
|               | Return the CPU cycle counter value |

签名和验签调用mbedtls提供的mbedtls_ecdsa_sign函数和mbedtls_ecdsa_verify函数

完整测试代码：

```c
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

```



## 三、环境配置流程

### 1. mbedtls的交叉编译

需要使用和代码同一个交叉编译工具链，如arm-linux-gnueabi-gcc

```
mkdir build && cd build
CC=arm-linux-gnueabihf-gcc cmake -D CMAKE_INSTALL_PREFIX=$(pwd)/../../install 
```

生成的文件夹中有三个.a文件，为静态链接库，编译时要加上-static选项

```
arm-linux-gnueabi-gcc -o ecdsa25 testecdsa.c -I ./install1/include -L ./install1/lib -lmbedtls -lmbedcrypto -lmbedx509 -static -march=armv7-a
```

静态链接了-lmbedtls -lmbedcrypto -lmbedx509

### 2.qemu环境配置

首先下载qemu

之后下载一个linux内核

交叉编译linux内核

```
make CROSS_COMPILE=arm-linux-gnueabi- ARCH=arm vexpress_defconfig
make menuconfig
make CROSS_COMPILE=arm-linux-gnueabi- ARCH=arm
```

制作根文件系统-使用busybox

编译busybox生成_install文件夹，之后

```
mkdir -p rootfs/{dev,etc/init.d,lib}
cp busybox-1.20.2/_install/* -r rootfs/
sudo cp -P /usr/arm-linux-gnueabi/lib/* rootfs/lib/
qemu-img create -f raw disk.img 512M
mkfs -t ext4 ./disk.img
mkdir tmpfs 
sudo mount -o loop ./disk.img tmpfs/  
sudo cp -r rootfs/* tmpfs/
sudo umount tmpfs
```

要根据需要在etc中加rcS文件，还要根据报错提升增加tty文件等

之后尝试运行虚拟机，使用monitor监视

```
taskset -c 0 qemu-system-arm -M vexpress-a9 -m 512M -smp 1,cores=1,threads=1 -kernel ./Downloads/linux-4.14.212/arch/arm/boot/zImage -dtb  ./Downloads/linux-4.14.212/arch/arm/boot/dts/vexpress-v2p-ca9.dtb -nographic -append "root=/dev/mmcblk0 rw console=ttyAMA0" -sd disk.img -monitor  telnet:127.0.0.1:5555,server 

telnet 127.0.0.1 5555
```

新增文件流程：

```
wyx@wyxpc:~$ sudo mount -o loop ./disk.img tmpfs/ 
wyx@wyxpc:~$ sudo cp ./Downloads/armmbed/ecdsa25 tmpfs/ 
wyx@wyxpc:~$ sudo umount tmpfs
```

