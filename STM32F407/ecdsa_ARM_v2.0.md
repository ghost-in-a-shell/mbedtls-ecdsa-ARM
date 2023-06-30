# Mbed-TLS中ECDSA算法在ARM架构开发板子STM32F407上的性能测试

## 一、前言

本笔记源代码位置https://github.com/ghost-in-a-shell/mbedtls-ecdsa-ARM/tree/main/STM32F407

在进行虚拟机测试的时候有如下的疑问：签名包括哪些操作？哈希的部分算签名吗？为了解决这些疑问，本次实验采取了更详细的记录方式。将ECDSA签名到验签的生命周期分为六个阶段：初始化阶段、随机数初始化阶段、哈希阶段、密钥生成阶段、签名阶段和验签阶段。具体而言，初始化阶段为初始化签名所需的一些结构体，例如ecdsa_context等，此阶段不包含嵌入式开发板的配置过程。随机数初始化阶段使用开发板的RNG外设作为硬件熵源，生成伪随机数生成器。哈希阶段计算消息都哈希值。密钥生成阶段为使用mbedtls_ecdsa_genkey函数生成公私钥对的过程。签名阶段为使用mbedtls_ecdsa_sign函数的调用过程。验签阶段为使用mbedtls_ecdsa_verify函数的验签过程。

## 二、结果

### 使用曲线secp256r1

### 2.1 性能一览：

**初始化性能：589 cycles  0.000037s **

**随机数初始化性能：106595.6 cycles  0.006662s**

**哈希性能：5062 cycles  0.000316s**

**密钥生成性能：35590177.9 cycles  2.230677s**

**签名性能：36792916.3 cycles  2.299557s**

**验签性能：73783890.2 cycles  4.611493s**



注：和虚拟机版本性能（几万cycles量级）出入较大，原因未知。

### 2.2 详细数据：

| Init cycles = 589<br/>Init time = 0.000037 s<br/>drbg cycles = 106593<br/>drbg time = 0.006662 s<br/>hash cycles = 5062<br/>hash time = 0.000316 s<br/>keygen cycles = 35508978<br/>keygen time = 2.219311 s<br/>sign cycles = 37012022<br/>sign time = 2.313251 s<br/>verify cycles = 73818996<br/>verify time = 4.613687 s | Init cycles = 589<br/>Init time = 0.000037 s<br/>drbg cycles = 106592<br/>drbg time = 0.006662 s<br/>hash cycles = 5062<br/>hash time = 0.000316 s<br/>keygen cycles = 35665772<br/>keygen time = 2.229111 s<br/>sign cycles = 36832207<br/>sign time = 2.302013 s<br/>verify cycles = 73612539<br/>verify time = 4.600784 s | Init cycles = 589<br/>Init time = 0.000037 s<br/>drbg cycles = 106599<br/>drbg time = 0.006662 s<br/>hash cycles = 5062<br/>hash time = 0.000316 s<br/>keygen cycles = 35362972<br/>keygen time = 2.210186 s<br/>sign cycles = 36842266<br/>sign time = 2.302642 s<br/>verify cycles = 73669092<br/>verify time = 4.604318 s |
| ------------------------------------------------------------ | ------------------------------------------------------------ | ------------------------------------------------------------ |
| **Init cycles = 589<br/>Init time = 0.000037 s<br/>drbg cycles = 106603<br/>drbg time = 0.006663 s<br/>hash cycles = 5062<br/>hash time = 0.000316 s<br/>keygen cycles = 35541719<br/>keygen time = 2.221357 s<br/>sign cycles = 36979184<br/>sign time = 2.311199 s<br/>verify cycles = 73528574<br/>verify time = 4.595536 s** | **Init cycles = 589<br/>Init time = 0.000037 s<br/>drbg cycles = 106592<br/>drbg time = 0.006662 s<br/>hash cycles = 5062<br/>hash time = 0.000316 s<br/>keygen cycles = 35747666<br/>keygen time = 2.234229 s<br/>sign cycles = 36708853<br/>sign time = 2.294303 s<br/>verify cycles = 73534018<br/>verify time = 4.595876 s** | **Init cycles = 589<br/>Init time = 0.000037 s<br/>drbg cycles = 106589<br/>drbg time = 0.006662 s<br/>hash cycles = 5062<br/>hash time = 0.000316 s<br/>keygen cycles = 35498877<br/>keygen time = 2.218680 s<br/>sign cycles = 36957156<br/>sign time = 2.309822 s<br/>verify cycles = 74323602<br/>verify time = 4.645225 s** |
| **Init cycles = 589<br/>Init time = 0.000037 s<br/>drbg cycles = 106599<br/>drbg time = 0.006662 s<br/>hash cycles = 5062<br/>hash time = 0.000316 s<br/>keygen cycles = 35503179<br/>keygen time = 2.218949 s<br/>sign cycles = 36759013<br/>sign time = 2.297438 s<br/>verify cycles = 73542428<br/>verify time = 4.596402 s** | **Init cycles = 589<br/>Init time = 0.000037 s<br/>drbg cycles = 106597<br/>drbg time = 0.006662 s<br/>hash cycles = 5062<br/>hash time = 0.000316 s<br/>keygen cycles = 35728505<br/>keygen time = 2.233032 s<br/>sign cycles = 36774274<br/>sign time = 2.298392 s<br/>verify cycles = 74400493<br/>verify time = 4.650031 s** | **Init cycles = 589<br/>Init time = 0.000037 s<br/>drbg cycles = 106591<br/>drbg time = 0.006662 s<br/>hash cycles = 5062<br/>hash time = 0.000316 s<br/>keygen cycles = 35645831<br/>keygen time = 2.227864 s<br/>sign cycles = 36881711<br/>sign time = 2.305107 s<br/>verify cycles = 73702747<br/>verify time = 4.606422 s** |
| **Init cycles = 589<br/>Init time = 0.000037 s<br/>drbg cycles = 106600<br/>drbg time = 0.006663 s<br/>hash cycles = 5062<br/>hash time = 0.000316 s<br/>keygen cycles = 35519527<br/>keygen time = 2.219970 s<br/>sign cycles = 36727304<br/>sign time = 2.295456 s<br/>verify cycles = 73690504<br/>verify time = 4.605657 s** | **Init cycles = 589<br/>Init time = 0.000037 s<br/>drbg cycles = 106598<br/>drbg time = 0.006662 s<br/>hash cycles = 5062<br/>hash time = 0.000316 s<br/>keygen cycles = 35656919<br/>keygen time = 2.228557 s<br/>sign cycles = 36935212<br/>sign time = 2.308451 s<br/>verify cycles = 73801897<br/>verify time = 4.612619 s** | **Init cycles = 589<br/>Init time = 0.000037 s<br/>drbg cycles = 106594<br/>drbg time = 0.006662 s<br/>hash cycles = 5062<br/>hash time = 0.000316 s<br/>keygen cycles = 35702190<br/>keygen time = 2.231387 s<br/>sign cycles = 36865794<br/>sign time = 2.304112 s<br/>verify cycles = 73782332<br/>verify time = 4.611396 s** |

## 三、测试环境及方法

### 3.1 环境

**开发板：野火霸天虎 STM32F407ZGT6**

**物理机系统：Windows10** 

**物理机架构：x86_64**

**MbedTLS版本：2.16.2**

**ARM MDK版本：keil5.15**

### 3.2 如何移植Mbedtls

总体而言，经过几天的踩坑，移植mbedtls有三种方法：

其一，使用开源代码编译。这种方法最容易想到，也是在虚拟机版本使用的方法。然而在真实的开发板上，兼容问题使得编译困难重重，版本问题产生了大量的宏定义不匹配、头文件找不到的情况。非常不建议使用。

其二，使用ARM官方的SPL库实现。这种方法沿用嵌入式开发固件库编程的思想，在编译上问题小很多，然而一些与硬件相关的宏会出问题，例如要开启硬件RNG就不是很方便。

其三，使用官方的HAL库编程，推荐使用该方法。STM32官方提供了生成函数模板的实用工具CubeMX，该攻击可以使用可视化的方法配置一些引脚设置。最好的一点是在本实验中，mbedtls可以在CubeMX中作为middleware进行配置。**本方法也是实验最终采取的方法。**

### 3.3 与虚拟机版本的主要区别

首先，mbedtls库的一些文件和函数是基于操作系统实现的，常见的要求是基于Unix系列系统和Windows系列系统。例如timing.h中的cpu cycle计数，新的实现方法是编写一个读取DWT-CYCCNT寄存器的函数来获取。

其次，随机数生成的熵源需要手动配置，要在CubeMX中开启RNG外设，并且编写对应的熵源函数，添加到mbedtls的默认函数中。

第三，实验信息的输出。原先在虚拟机上可以直接使用printf输出结果，而在开发板上需要使用串口通信。需要开启USART进行通信，并重写fputc函数，使得printf变为向串口发送信息的函数，这样就可以利用串口调试工具获得输出信息。

在开发板上运行，资源首先，要为程序分配较大的堆栈空间，否则会导致程序卡死而不报错。

