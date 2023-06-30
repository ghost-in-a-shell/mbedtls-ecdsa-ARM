/* USER CODE BEGIN Header */
/**
  ******************************************************************************
  * @file           : main.c
  * @brief          : Main program body
  ******************************************************************************
  * @attention
  *
  * Copyright (c) 2023 STMicroelectronics.
  * All rights reserved.
  *
  * This software is licensed under terms that can be found in the LICENSE file
  * in the root directory of this software component.
  * If no LICENSE file comes with this software, it is provided AS-IS.
  *
  ******************************************************************************
  */
/* USER CODE END Header */
/* Includes ------------------------------------------------------------------*/
#include "main.h"
#include "mbedtls.h"

/* Private includes ----------------------------------------------------------*/
/* USER CODE BEGIN Includes */

/* USER CODE END Includes */

/* Private typedef -----------------------------------------------------------*/
/* USER CODE BEGIN PTD */

/* USER CODE END PTD */

/* Private define ------------------------------------------------------------*/
/* USER CODE BEGIN PD */

/* USER CODE END PD */

/* Private macro -------------------------------------------------------------*/
/* USER CODE BEGIN PM */

/* USER CODE END PM */

/* Private variables ---------------------------------------------------------*/
RNG_HandleTypeDef hrng;

UART_HandleTypeDef huart1;

/* USER CODE BEGIN PV */

/* USER CODE END PV */

/* Private function prototypes -----------------------------------------------*/
void SystemClock_Config(void);
static void MX_GPIO_Init(void);
static void MX_RNG_Init(void);
static void MX_USART1_UART_Init(void);
/* USER CODE BEGIN PFP */

/* USER CODE END PFP */

/* Private user code ---------------------------------------------------------*/
/* USER CODE BEGIN 0 */





uint8_t buf[97];

static void dump_buf(uint8_t *buf, uint32_t len)
{
    int i;
    
    for (i = 0; i < len; i++) {
        printf("%s%02X%s", i % 16 == 0 ? "\r\n\t" : " ", 
                           buf[i], 
                           i == len - 1 ? "\r\n" : "");
    }
}


// ??DWT???
void enable_dwt(void)
{
    CoreDebug->DEMCR |= CoreDebug_DEMCR_TRCENA_Msk;
    DWT->CYCCNT = 0;
    DWT->CTRL |= DWT_CTRL_CYCCNTENA_Msk;
}

uint32_t get_cycle_count(void)
{
    return DWT->CYCCNT;
}



uint32_t get_cycle_count_frequency(void)
{
    return SystemCoreClock;
}
/* USER CODE END 0 */

/**
  * @brief  The application entry point.
  * @retval int
  */
int main(void)
{
  /* USER CODE BEGIN 1 */

  /* USER CODE END 1 */

  /* MCU Configuration--------------------------------------------------------*/

  /* Reset of all peripherals, Initializes the Flash interface and the Systick. */
  HAL_Init();

  /* USER CODE BEGIN Init */

  /* USER CODE END Init */

  /* Configure the system clock */
  SystemClock_Config();

  /* USER CODE BEGIN SysInit */

  /* USER CODE END SysInit */

  /* Initialize all configured peripherals */
  MX_GPIO_Init();
  MX_RNG_Init();
  MX_MBEDTLS_Init();
  MX_USART1_UART_Init();
  /* USER CODE BEGIN 2 */

printf("\nprogram start\n");
uint32_t start_init, end_init, start_drbg,end_drbg,start_hash,end_hash,start_keygen,end_keygen,start_sign,end_sign,start_verify,end_verify;
uint32_t test;
    enable_dwt();

		test=get_cycle_count_frequency();

		printf("cpu frequency = %u\n", test);

    start_init = get_cycle_count();
		//printf("start time = %u\n", start_init);



int ret;
    size_t qlen, dlen;
    size_t rlen, slen;
    uint8_t hash[32];
   
    const char *msg  = "HelloWorld";
    const char *pers = "ecdsa_test";
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_mpi r, s;
    mbedtls_ecdsa_context ctx;
    mbedtls_md_context_t md_ctx;
        
    /* 1. init structure */
    mbedtls_md_init(&md_ctx);
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_mpi_init(&r);
    mbedtls_mpi_init(&s);
    mbedtls_ecdsa_init(&ctx);  //???ECDSA???
		
	end_init = get_cycle_count();	

		
    /* 2. update seed with we own interface ported */
    printf( "\n  . Seeding the random number generator..." );

start_drbg = get_cycle_count();
    ret = mbedtls_ctr_drbg_seed( &ctr_drbg, mbedtls_entropy_func, &entropy,
                               (const unsigned char *) pers,
                               strlen(pers));
end_drbg = get_cycle_count();

    if(ret != 0) {
        printf( " failed\n  ! mbedtls_ctr_drbg_seed returned %d(-0x%04x)\n", ret, -ret);
        goto exit;
    }
		
    printf( " ok\n" );
    
		
    /* 3. hash message */
    printf( "\n  . Hash message..." );

 start_hash = get_cycle_count();   
    ret = mbedtls_md(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), (uint8_t *)msg, strlen(msg), hash);
end_hash = get_cycle_count();

    if(ret != 0) {
        printf( " failed\n  ! mbedtls_md returned %d(-0x%04x)\n", ret, -ret);
        goto exit;
    }
    printf( " ok\n" );
    
    /* show hash */
    dump_buf(hash, sizeof(hash));
    
	
		
		
		
    /* 4. generate keypair */
    printf( "\n  . Generate ecdsa keypair..." );
   
 start_keygen = get_cycle_count();   
    ret = mbedtls_ecdsa_genkey(&ctx, MBEDTLS_ECP_DP_SECP256R1, mbedtls_ctr_drbg_random, &ctr_drbg);
end_keygen = get_cycle_count();
 
    if(ret != 0) {
        printf( " failed\n  ! mbedtls_ecdsa_genkey returned %d(-0x%04x)\n", ret, -ret);
        goto exit;
    }
    printf( " ok\n" );
    
    /* show keypair */
    mbedtls_ecp_point_write_binary(&ctx.grp, &ctx.Q, MBEDTLS_ECP_PF_UNCOMPRESSED, &qlen, buf, sizeof(buf));
    dlen = mbedtls_mpi_size(&ctx.d);
    mbedtls_mpi_write_binary(&ctx.d, buf + qlen, dlen);
    dump_buf(buf, qlen + dlen);
    
    /* 5. ecdsa sign */
    printf( "\n  . ECDSA sign..." );
 
 start_sign = get_cycle_count();    
    ret = mbedtls_ecdsa_sign(&ctx.grp, &r, &s, &ctx.d, hash, sizeof(hash), mbedtls_ctr_drbg_random, &ctr_drbg);
end_sign = get_cycle_count();
	
    if(ret != 0) {
        printf( " failed\n  ! mbedtls_ecdsa_sign returned %d(-0x%04x)\n", ret, -ret);
        goto exit;
    }
    printf( " ok\n" );
    
    /* show sign */
    rlen = mbedtls_mpi_size(&r);
    slen = mbedtls_mpi_size(&s);
    mbedtls_mpi_write_binary(&r, buf, rlen);
    mbedtls_mpi_write_binary(&s, buf + rlen, slen);
    dump_buf(buf, rlen + slen);
    
    /* 6. ecdsa verify */
    printf( "\n  . ECDSA verify..." );

  start_verify = get_cycle_count();    
    ret = mbedtls_ecdsa_verify(&ctx.grp, hash, sizeof(hash), &ctx.Q, &r, &s);
	end_verify = get_cycle_count(); 

    if(ret != 0) {
        printf( " failed\n  ! mbedtls_ecdsa_verify returned %d(-0x%04x)\n", ret, -ret);
        goto exit;
    }
    printf( " ok\n" );

		printf("Init cycles = %u\n", end_init-start_init);
		printf("Init time = %lf s\n", (double)(end_init - start_init) / (double)test);
		printf("drbg cycles = %u\n", end_drbg-start_drbg);
		printf("drbg time = %lf s\n", (double)(end_drbg-start_drbg) / (double)test);
		printf("hash cycles = %u\n", end_hash-start_hash);
		printf("hash time = %lf s\n", (double)(end_hash-start_hash) / (double)test);
		printf("keygen cycles = %u\n", end_keygen-start_keygen);
		printf("keygen time = %lf s\n", (double)(end_keygen-start_keygen) / (double)test);
		printf("sign cycles = %u\n", end_sign-start_sign);
		printf("sign time = %lf s\n", (double)(end_sign-start_sign) / (double)test);
		printf("verify cycles = %u\n", end_verify-start_verify);
		printf("verify time = %lf s\n", (double)(end_verify-start_verify) / (double)test);
    exit:
    
    /* 7. release structure */
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
    mbedtls_mpi_free(&r);
    mbedtls_mpi_free(&s);
    mbedtls_md_free(&md_ctx);
    mbedtls_ecdsa_free(&ctx);
    
    return ret;





  /* USER CODE END 2 */

  /* Infinite loop */
  /* USER CODE BEGIN WHILE */
  while (1)
  {
    /* USER CODE END WHILE */

    /* USER CODE BEGIN 3 */
  }
  /* USER CODE END 3 */
}

/**
  * @brief System Clock Configuration
  * @retval None
  */
void SystemClock_Config(void)
{
  RCC_OscInitTypeDef RCC_OscInitStruct = {0};
  RCC_ClkInitTypeDef RCC_ClkInitStruct = {0};

  /** Configure the main internal regulator output voltage
  */
  __HAL_RCC_PWR_CLK_ENABLE();
  __HAL_PWR_VOLTAGESCALING_CONFIG(PWR_REGULATOR_VOLTAGE_SCALE1);

  /** Initializes the RCC Oscillators according to the specified parameters
  * in the RCC_OscInitTypeDef structure.
  */
  RCC_OscInitStruct.OscillatorType = RCC_OSCILLATORTYPE_HSI;
  RCC_OscInitStruct.HSIState = RCC_HSI_ON;
  RCC_OscInitStruct.HSICalibrationValue = RCC_HSICALIBRATION_DEFAULT;
  RCC_OscInitStruct.PLL.PLLState = RCC_PLL_ON;
  RCC_OscInitStruct.PLL.PLLSource = RCC_PLLSOURCE_HSI;
  RCC_OscInitStruct.PLL.PLLM = 16;
  RCC_OscInitStruct.PLL.PLLN = 192;
  RCC_OscInitStruct.PLL.PLLP = RCC_PLLP_DIV2;
  RCC_OscInitStruct.PLL.PLLQ = 4;
  if (HAL_RCC_OscConfig(&RCC_OscInitStruct) != HAL_OK)
  {
    Error_Handler();
  }

  /** Initializes the CPU, AHB and APB buses clocks
  */
  RCC_ClkInitStruct.ClockType = RCC_CLOCKTYPE_HCLK|RCC_CLOCKTYPE_SYSCLK
                              |RCC_CLOCKTYPE_PCLK1|RCC_CLOCKTYPE_PCLK2;
  RCC_ClkInitStruct.SYSCLKSource = RCC_SYSCLKSOURCE_HSI;
  RCC_ClkInitStruct.AHBCLKDivider = RCC_SYSCLK_DIV1;
  RCC_ClkInitStruct.APB1CLKDivider = RCC_HCLK_DIV1;
  RCC_ClkInitStruct.APB2CLKDivider = RCC_HCLK_DIV1;

  if (HAL_RCC_ClockConfig(&RCC_ClkInitStruct, FLASH_LATENCY_0) != HAL_OK)
  {
    Error_Handler();
  }
}

/**
  * @brief RNG Initialization Function
  * @param None
  * @retval None
  */
static void MX_RNG_Init(void)
{

  /* USER CODE BEGIN RNG_Init 0 */

  /* USER CODE END RNG_Init 0 */

  /* USER CODE BEGIN RNG_Init 1 */

  /* USER CODE END RNG_Init 1 */
  hrng.Instance = RNG;
  if (HAL_RNG_Init(&hrng) != HAL_OK)
  {
    Error_Handler();
  }
  /* USER CODE BEGIN RNG_Init 2 */

  /* USER CODE END RNG_Init 2 */

}

/**
  * @brief USART1 Initialization Function
  * @param None
  * @retval None
  */
static void MX_USART1_UART_Init(void)
{

  /* USER CODE BEGIN USART1_Init 0 */

  /* USER CODE END USART1_Init 0 */

  /* USER CODE BEGIN USART1_Init 1 */

  /* USER CODE END USART1_Init 1 */
  huart1.Instance = USART1;
  huart1.Init.BaudRate = 115200;
  huart1.Init.WordLength = UART_WORDLENGTH_8B;
  huart1.Init.StopBits = UART_STOPBITS_1;
  huart1.Init.Parity = UART_PARITY_NONE;
  huart1.Init.Mode = UART_MODE_TX_RX;
  huart1.Init.HwFlowCtl = UART_HWCONTROL_NONE;
  huart1.Init.OverSampling = UART_OVERSAMPLING_16;
  if (HAL_UART_Init(&huart1) != HAL_OK)
  {
    Error_Handler();
  }
  /* USER CODE BEGIN USART1_Init 2 */

  /* USER CODE END USART1_Init 2 */

}

/**
  * @brief GPIO Initialization Function
  * @param None
  * @retval None
  */
static void MX_GPIO_Init(void)
{
/* USER CODE BEGIN MX_GPIO_Init_1 */
/* USER CODE END MX_GPIO_Init_1 */

  /* GPIO Ports Clock Enable */
  __HAL_RCC_GPIOH_CLK_ENABLE();
  __HAL_RCC_GPIOA_CLK_ENABLE();

/* USER CODE BEGIN MX_GPIO_Init_2 */
/* USER CODE END MX_GPIO_Init_2 */
}

/* USER CODE BEGIN 4 */

/* USER CODE END 4 */

/**
  * @brief  This function is executed in case of error occurrence.
  * @retval None
  */
void Error_Handler(void)
{
  /* USER CODE BEGIN Error_Handler_Debug */
  /* User can add his own implementation to report the HAL error return state */
  __disable_irq();
  while (1)
  {
  }
  /* USER CODE END Error_Handler_Debug */
}

#ifdef  USE_FULL_ASSERT
/**
  * @brief  Reports the name of the source file and the source line number
  *         where the assert_param error has occurred.
  * @param  file: pointer to the source file name
  * @param  line: assert_param error line source number
  * @retval None
  */
void assert_failed(uint8_t *file, uint32_t line)
{
  /* USER CODE BEGIN 6 */
  /* User can add his own implementation to report the file name and line number,
     ex: printf("Wrong parameters value: file %s on line %d\r\n", file, line) */
  /* USER CODE END 6 */
}
#endif /* USE_FULL_ASSERT */
