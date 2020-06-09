/*********************************************************************************

Copyright(c) 2013-2016 Analog Devices, Inc. All Rights Reserved.

This software is proprietary and confidential.  By using this software you agree
to the terms of the associated Analog Devices License Agreement.

*********************************************************************************/
/*!
 * @file      crypto_example.c
 * @brief     Example to demonstrate CRYPTO Driver
 *
 * @details
 *            This is the primary source file for the CRYPTO example demonstrating
 *            encryption and decryption
 *
 */

/*=============  I N C L U D E S   =============*/

/* CRYPTO example include */
#include "crypto_example.h"

/* Managed drivers and/or services include */
#include <drivers/crypto/adi_crypto.h>
#include <drivers/general/adi_drivers_general.h>    
#include <assert.h>
#include <common.h>
#include <drivers/pwr/adi_pwr.h>

/*=============  D A T A  =============*/

/* Memory Required for crypto driver */
ADI_ALIGNED_PRAGMA(4)
static uint8_t DeviceMemory          [ADI_CRYPTO_MEMORY_SIZE] ADI_ALIGNED_ATTRIBUTE(4);

/* ECB Message and other buffers */
ADI_ALIGNED_PRAGMA(4)
static uint8_t ecbComputedCipher     [ECB_BUFF_SIZE] ADI_ALIGNED_ATTRIBUTE(4);
ADI_ALIGNED_PRAGMA(4)
static uint8_t ecbDecryptedText      [ECB_BUFF_SIZE] ADI_ALIGNED_ATTRIBUTE(4);

/* CBC Message and other buffers */
ADI_ALIGNED_PRAGMA(4)
static uint8_t cbcComputedCipher     [ECB_BUFF_SIZE] ADI_ALIGNED_ATTRIBUTE(4);
ADI_ALIGNED_PRAGMA(4)
static uint8_t cbcDecryptedText      [ECB_BUFF_SIZE] ADI_ALIGNED_ATTRIBUTE(4);

/* CCM Message and other buffers */
ADI_ALIGNED_PRAGMA(4)
static uint8_t ccmAuthenticationText [CCM_AUTH_BUFF_SIZE] ADI_ALIGNED_ATTRIBUTE(4);
ADI_ALIGNED_PRAGMA(4)
static uint8_t ccmPlainText          [CCM_PAYLOAD_BUFF_SIZE] ADI_ALIGNED_ATTRIBUTE(4);
ADI_ALIGNED_PRAGMA(4)
static uint8_t ccmComputedCipher     [CCM_PAYLOAD_BUFF_SIZE + CCM_DIGEST_SIZE] ADI_ALIGNED_ATTRIBUTE(4);
ADI_ALIGNED_PRAGMA(4)
static uint8_t ccmDecryptedText      [CCM_PAYLOAD_BUFF_SIZE + CCM_DIGEST_SIZE] ADI_ALIGNED_ATTRIBUTE(4);


/* The SHA test vectors are from http://www.di-mgt.com.au/sha_testvectors.html */

/* SHA test1 Buffers */
ADI_ALIGNED_PRAGMA(4)
static uint8_t Sha1_Message          [4] ADI_ALIGNED_ATTRIBUTE(4)= "abc" ;		
ADI_ALIGNED_PRAGMA(4)
static uint8_t Sha1_ComputedHash     [ADI_CRYPTO_SHA_HASH_BYTES] ADI_ALIGNED_ATTRIBUTE(4);
ADI_ALIGNED_PRAGMA(4)
static uint32_t Sha1_ExpectedHash    [] ADI_ALIGNED_ATTRIBUTE(4)= {
    /* ba7816bf 8f01cfea 414140de 5dae2223 b00361a3 96177a9c b410ff61 f20015ad */
    0xba7816bf, 0x8f01cfea, 0x414140de, 0x5dae2223,
    0xb00361a3, 0x96177a9c, 0xb410ff61, 0xf20015ad
} ;			

/* SHA test2 Buffers */
ADI_ALIGNED_PRAGMA(4)
static uint8_t  Sha2_Message         [56] ADI_ALIGNED_ATTRIBUTE(4)= "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq" ;
ADI_ALIGNED_PRAGMA(4)
static uint8_t  Sha2_ComputedHash    [ADI_CRYPTO_SHA_HASH_BYTES] ADI_ALIGNED_ATTRIBUTE(4);
ADI_ALIGNED_PRAGMA(4)
static uint32_t Sha2_ExpectedHash    [] ADI_ALIGNED_ATTRIBUTE(4)= {
    /* 248d6a61 d20638b8 e5c02693 0c3e6039 a33ce459 64ff2167 f6ecedd4 19db06c1 */
    0x248d6a61, 0xd20638b8, 0xe5c02693, 0x0c3e6039,
    0xa33ce459, 0x64ff2167, 0xf6ecedd4, 0x19db06c1
} ;

/* SHA test3 Buffers */
/* note: this vector checks 64-byte AES driver chunking (hardware only takes 512 bits at a time) */
ADI_ALIGNED_PRAGMA(4)
static uint8_t Sha3_Message          [112] ADI_ALIGNED_ATTRIBUTE(4)= "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu" ;
ADI_ALIGNED_PRAGMA(4)
static uint8_t Sha3_ComputedHash     [ADI_CRYPTO_SHA_HASH_BYTES] ADI_ALIGNED_ATTRIBUTE(4);
ADI_ALIGNED_PRAGMA(4)
static uint32_t Sha3_ExpectedHash    [] ADI_ALIGNED_ATTRIBUTE(4)= {
    /* "cf5b16a7 78af8380 036ce59e 7b049237 0b249b11 e8f07a51 afac4503 7afee9d1" */
    0xcf5b16a7, 0x78af8380, 0x036ce59e, 0x7b049237,
    0x0b249b11, 0xe8f07a51, 0xafac4503, 0x7afee9d1
} ;

/* Crypto test vectors are from: National Institute of Standards and Technology Special Publication 800-38A 2001 ED */
/* vectors are modified in-place, so reinitialize on stack for each test... */

/* define four 128-bit blocks (4 x 16-bytes) of test data for each test */
#define TEST_BYTES 64

ADI_ALIGNED_PRAGMA(4)
static uint8_t initial_vector[] ADI_ALIGNED_ATTRIBUTE(4)= { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f } ;

/* Initial data - 4 x 16 from NIST. Used by many of the crypto ciphers */
ADI_ALIGNED_PRAGMA(4)
static uint8_t plainText [TEST_BYTES] ADI_ALIGNED_ATTRIBUTE(4)= {
  0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
  0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
  0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11, 0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef,
  0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17, 0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10
} ;

/*#define USE_256*/    /* uncomment to use 256 bit key */
#ifndef USE_256
#define AES_KEY_LEN ADI_CRYPTO_AES_KEY_LEN_128_BIT
/* AES128.Encrypt. Same key used by many of the crypto ciphers */
ADI_ALIGNED_PRAGMA(4)
static uint8_t Key[] ADI_ALIGNED_ATTRIBUTE(4) = {
  0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
} ;

/* Encrypted data from NIST */
ADI_ALIGNED_PRAGMA(4)
static uint8_t ecbExpectedCipher[TEST_BYTES] ADI_ALIGNED_ATTRIBUTE(4)= {
  0x3a, 0xd7, 0x7b, 0xb4, 0x0d, 0x7a, 0x36, 0x60, 0xa8, 0x9e, 0xca, 0xf3, 0x24, 0x66, 0xef, 0x97,
  0xf5, 0xd3, 0xd5, 0x85, 0x03, 0xb9, 0x69, 0x9d, 0xe7, 0x85, 0x89, 0x5a, 0x96, 0xfd, 0xba, 0xaf,
  0x43, 0xb1, 0xcd, 0x7f, 0x59, 0x8e, 0xce, 0x23, 0x88, 0x1b, 0x00, 0xe3, 0xed, 0x03, 0x06, 0x88,
  0x7b, 0x0c, 0x78, 0x5e, 0x27, 0xe8, 0xad, 0x3f, 0x82, 0x23, 0x20, 0x71, 0x04, 0x72, 0x5d, 0xd4
} ;

ADI_ALIGNED_PRAGMA(4)
static uint8_t cbcExpectedCipher[TEST_BYTES] ADI_ALIGNED_ATTRIBUTE(4) = {
  0x76, 0x49, 0xab, 0xac, 0x81, 0x19, 0xb2, 0x46, 0xce, 0xe9, 0x8e, 0x9b, 0x12, 0xe9, 0x19, 0x7d,
  0x50, 0x86, 0xcb, 0x9b, 0x50, 0x72, 0x19, 0xee, 0x95, 0xdb, 0x11, 0x3a, 0x91, 0x76, 0x78, 0xb2,
  0x73, 0xbe, 0xd6, 0xb8, 0xe3, 0xc1, 0x74, 0x3b, 0x71, 0x16, 0xe6, 0x9e, 0x22, 0x22, 0x95, 0x16,
  0x3f, 0xf1, 0xca, 0xa1, 0x68, 0x1f, 0xac, 0x09, 0x12, 0x0e, 0xca, 0x30, 0x75, 0x86, 0xe1, 0xa7
} ;

#else
#define AES_KEY_LEN ADI_CRYPTO_AES_KEY_LEN_256_BIT

/* AES256.Encrypt. Same key used by many of the crypto ciphers */
ADI_ALIGNED_PRAGMA(4)
static uint8_t Key[] ADI_ALIGNED_ATTRIBUTE(4)= {
  0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
  0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4
} ;

ADI_ALIGNED_PRAGMA(4)
static uint8_t ecbExpectedCipher[TEST_BYTES] ADI_ALIGNED_ATTRIBUTE(4)= {
  0xf3, 0xee, 0xd1, 0xbd, 0xb5, 0xd2, 0xa0, 0x3c, 0x06, 0x4b, 0x5a, 0x7e, 0x3d, 0xb1, 0x81, 0xf8,
  0x59, 0x1c, 0xcb, 0x10, 0xd4, 0x10, 0xed, 0x26, 0xdc, 0x5b, 0xa7, 0x4a, 0x31, 0x36, 0x28, 0x70,
  0xb6, 0xed, 0x21, 0xb9, 0x9c, 0xa6, 0xf4, 0xf9, 0xf1, 0x53, 0xe7, 0xb1, 0xbe, 0xaf, 0xed, 0x1d,
  0x23, 0x30, 0x4b, 0x7a, 0x39, 0xf9, 0xf3, 0xff, 0x06, 0x7d, 0x8d, 0x8f, 0x9e, 0x24, 0xec, 0xc7
} ;

ADI_ALIGNED_PRAGMA(4)
static uint8_t cbcExpectedCipher[TEST_BYTES] ADI_ALIGNED_ATTRIBUTE(4)= {
  0xf5, 0x8c, 0x4c, 0x04, 0xd6, 0xe5, 0xf1, 0xba, 0x77, 0x9e, 0xab, 0xfb, 0x5f, 0x7b, 0xfb, 0xd6,
  0x9c, 0xfc, 0x4e, 0x96, 0x7e, 0xdb, 0x80, 0x8d, 0x67, 0x9f, 0x77, 0x7b, 0xc6, 0x70, 0x2c, 0x7d,
  0x39, 0xf2, 0x33, 0x69, 0xa9, 0xd9, 0xba, 0xcf, 0xa5, 0x30, 0xe2, 0x63, 0x04, 0x23, 0x14, 0x61,
  0xb2, 0xeb, 0x05, 0xe2, 0xc3, 0x9b, 0xe9, 0xfc, 0xda, 0x6c, 0x19, 0x07, 0x8c, 0x6a, 0x9d, 0x1b
} ;
#endif


#ifdef CRYPTO_ENABLE_CALLBACK
static volatile int numBuffersReturned = 0;
#endif

/*=============  L O C A L    F U N C T I O N S  =============*/

static void InitBuffers(void);
static bool VerifyBuffers (void);

/*=============  C O D E  =============*/

/* IF (Callback mode enabled) */
#ifdef CRYPTO_ENABLE_CALLBACK

ADI_CRYPTO_TRANSACTION *pcbReturnedBuffer;

/* Callback from the device */
static void CryptoCallback(void *pCBParam, uint32_t Event, void *pArg)
{
    /* process callback event */
    switch (Event) {

        /* success events */
        case ADI_CRYPTO_EVENT_STATUS_CBC_DONE:
        case ADI_CRYPTO_EVENT_STATUS_CCM_DONE:
        case ADI_CRYPTO_EVENT_STATUS_CMAC_DONE:
        case ADI_CRYPTO_EVENT_STATUS_CTR_DONE:
        case ADI_CRYPTO_EVENT_STATUS_ECB_DONE:
        case ADI_CRYPTO_EVENT_STATUS_HMAC_DONE:
        case ADI_CRYPTO_EVENT_STATUS_SHA_DONE:
            pcbReturnedBuffer = pArg;
            numBuffersReturned++;
            break;

        /* other events */
        case ADI_CRYPTO_EVENT_DMA_BUS_ERROR:
        case ADI_CRYPTO_EVENT_DMA_DESCRIPTOR_ERROR:
        case ADI_CRYPTO_EVENT_DMA_UNKNOWN_ERROR:
        case ADI_CRYPTO_EVENT_STATUS_INPUT_OVERFLOW:
        case ADI_CRYPTO_EVENT_STATUS_UNKNOWN:
            printf("Non-success callback event 0x%04lx\n", Event);
            //exit(0);
            break;

        /* UNDEFINED */
        default:
            printf("Undefined callback event\n");
            //exit(0);
            break;
        }
}
#else
static ADI_CRYPTO_TRANSACTION *pGottenBuffer;
#endif /* CRYPTO_ENABLE_CALLBACK */



void SHA_Compute(void)
{
    ADI_CRYPTO_HANDLE hDevice;
    ADI_CRYPTO_RESULT eResult = ADI_CRYPTO_SUCCESS;
    ADI_CRYPTO_TRANSACTION Buffer1;
    ADI_CRYPTO_TRANSACTION Buffer2;
    ADI_CRYPTO_TRANSACTION Buffer3;

    /* Open the crypto device */
    eResult = adi_crypto_Open(CRYPTO_DEV_NUM, DeviceMemory, sizeof(DeviceMemory), &hDevice);
    DEBUG_RESULT("Failed to open crypto device", eResult, ADI_CRYPTO_SUCCESS);

#ifdef CRYPTO_ENABLE_CALLBACK
    /* Register Callback */
    eResult = adi_crypto_RegisterCallback (hDevice, CryptoCallback, NULL);
#endif


/****************************************BUFFER1****************************************/

    /* prepair submit */
    memset( &Buffer1, 0, sizeof(ADI_CRYPTO_TRANSACTION) );

    Buffer1.eCipherMode    = ADI_CRYPTO_MODE_SHA;
    Buffer1.eCodingMode    = ADI_CRYPTO_ENCODE;
    Buffer1.eShaByteSwap   = ADI_CRYPTO_SHA_BIG_ENDIAN;
    Buffer1.pInputData     = (uint32_t*)&Sha1_Message[0];
    Buffer1.numInputBytes  = sizeof(Sha1_Message);
    Buffer1.numShaBits     = (strlen((const char *)Sha1_Message)*8);
    Buffer1.pOutputData    = (uint32_t*)&Sha1_ComputedHash[0];
    Buffer1.numOutputBytes = ADI_CRYPTO_SHA_HASH_BYTES;

    /* Submit the buffer for SHA hashing */
    eResult = adi_crypto_SubmitBuffer (hDevice, &Buffer1);
    DEBUG_RESULT("Failed to submit SHA buffer 1 to crypto device", eResult, ADI_CRYPTO_SUCCESS);

#ifdef CRYPTO_ENABLE_CALLBACK
    /* reset callback counter */
    numBuffersReturned = 0;
#endif

    /* Enable the device */
    eResult =  adi_crypto_Enable (hDevice, true);
    DEBUG_RESULT("Failed to enable crypto device", eResult, ADI_CRYPTO_SUCCESS);

#ifndef CRYPTO_ENABLE_CALLBACK
    /* retrieve the submitted buffer from the driver */
    eResult =  adi_crypto_GetBuffer (hDevice, &pGottenBuffer);
    DEBUG_RESULT("Failed to get buffer from the crypto device", eResult, ADI_CRYPTO_SUCCESS);
    if (&Buffer1 != pGottenBuffer) {
        DEBUG_RESULT("Returned buffer from callback mismatch", eResult, ADI_CRYPTO_ERR_BAD_BUFFER);
    }
#else
    /* await the callback */
    while (0 == numBuffersReturned)
        ;
    if (&Buffer1 != pcbReturnedBuffer) {
        DEBUG_RESULT("Returned buffer from callback mismatch", eResult, ADI_CRYPTO_ERR_BAD_BUFFER);
    }
#endif

    /* Disable the device */
    eResult =  adi_crypto_Enable (hDevice, false);
    DEBUG_RESULT("Failed to disable crypto device", eResult, ADI_CRYPTO_SUCCESS);


/****************************************BUFFER2****************************************/

    /* prepare submit */
    memset( &Buffer2, 0, sizeof(ADI_CRYPTO_TRANSACTION) );

    Buffer2.eCipherMode    = ADI_CRYPTO_MODE_SHA;
    Buffer2.eCodingMode    = ADI_CRYPTO_ENCODE;
    Buffer2.eShaByteSwap   = ADI_CRYPTO_SHA_BIG_ENDIAN;
    Buffer2.pInputData     = (uint32_t*)&Sha2_Message[0];
    Buffer2.numInputBytes  = sizeof(Sha2_Message);
    Buffer2.numShaBits     = sizeof(Sha2_Message)*8u;
    Buffer2.pOutputData    = (uint32_t*)&Sha2_ComputedHash[0];
    Buffer2.numOutputBytes = ADI_CRYPTO_SHA_HASH_BYTES;

    /* Submit the buffer for SHA hashing */
    eResult = adi_crypto_SubmitBuffer (hDevice, &Buffer2);
    DEBUG_RESULT("Failed to submit SHA buffer 2 to crypto device", eResult, ADI_CRYPTO_SUCCESS);

#ifdef CRYPTO_ENABLE_CALLBACK
    /* reset callback counter */
    numBuffersReturned = 0;
#endif

    /* Enable the device */
    eResult =  adi_crypto_Enable (hDevice, true);
    DEBUG_RESULT("Failed to enable crypto device", eResult, ADI_CRYPTO_SUCCESS);

#ifndef CRYPTO_ENABLE_CALLBACK
    /* retrieve the submitted buffer from the driver */
    eResult =  adi_crypto_GetBuffer (hDevice, &pGottenBuffer);
    DEBUG_RESULT("Failed to get buffer from the crypto device", eResult, ADI_CRYPTO_SUCCESS);
    if (&Buffer2 != pGottenBuffer) {
        DEBUG_RESULT("Returned buffer from callback mismatch", eResult, ADI_CRYPTO_ERR_BAD_BUFFER);
    }
#else
    /* await the callback */
    while (0 == numBuffersReturned)
        ;
    if (&Buffer2 != pcbReturnedBuffer) {
        DEBUG_RESULT("Returned buffer from callback mismatch", eResult, ADI_CRYPTO_ERR_BAD_BUFFER);
    }
#endif

    /* Disable the device */
    eResult =  adi_crypto_Enable (hDevice, false);
    DEBUG_RESULT("Failed to disable crypto device", eResult, ADI_CRYPTO_SUCCESS);


/****************************************BUFFER3****************************************/

    /* prepare submit */
    memset( &Buffer3, 0, sizeof(ADI_CRYPTO_TRANSACTION) );

    Buffer3.eCipherMode    = ADI_CRYPTO_MODE_SHA;
    Buffer3.eCodingMode    = ADI_CRYPTO_ENCODE;
    Buffer3.eShaByteSwap   = ADI_CRYPTO_SHA_BIG_ENDIAN;
    Buffer3.pInputData     = (uint32_t*)&Sha3_Message[0];
    Buffer3.numInputBytes  = sizeof(Sha3_Message);
    Buffer3.numShaBits     = sizeof(Sha3_Message)*8u;
    Buffer3.pOutputData    = (uint32_t*)&Sha3_ComputedHash[0];
    Buffer3.numOutputBytes = ADI_CRYPTO_SHA_HASH_BYTES;

    /* Submit the buffer for SHA hashing */
    eResult = adi_crypto_SubmitBuffer (hDevice, &Buffer3);
    DEBUG_RESULT("Failed to submit SHA buffer 2 to crypto device", eResult, ADI_CRYPTO_SUCCESS);

#ifdef CRYPTO_ENABLE_CALLBACK
    /* reset callback counter */
    numBuffersReturned = 0;
#endif

    /* Enable the device */
    eResult =  adi_crypto_Enable (hDevice, true);
    DEBUG_RESULT("Failed to enable crypto device", eResult, ADI_CRYPTO_SUCCESS);

#ifndef CRYPTO_ENABLE_CALLBACK
    /* retrieve the submitted buffer from the driver */
    eResult =  adi_crypto_GetBuffer (hDevice, &pGottenBuffer);
    DEBUG_RESULT("Failed to get buffer from the crypto device", eResult, ADI_CRYPTO_SUCCESS);
    if (&Buffer3 != pGottenBuffer) {
        DEBUG_RESULT("Returned buffer from callback mismatch", eResult, ADI_CRYPTO_ERR_BAD_BUFFER);
    }
#else
    /* await the callback */
    while (0 == numBuffersReturned)
        ;
    if (&Buffer3 != pcbReturnedBuffer) {
        DEBUG_RESULT("Returned buffer from callback mismatch", eResult, ADI_CRYPTO_ERR_BAD_BUFFER);
    }
#endif

    /* Disable the device */
    eResult =  adi_crypto_Enable (hDevice, false);
    DEBUG_RESULT("Failed to disable crypto device", eResult, ADI_CRYPTO_SUCCESS);


/***************************************************************************************/

    /* Close the crypto device */
    eResult =  adi_crypto_Close(hDevice);
    DEBUG_RESULT("Failed to close crypto device", eResult, ADI_CRYPTO_SUCCESS);
}


void ECB_Encrypt_Decrypt(void)
{
    ADI_CRYPTO_HANDLE      hDevice;
    ADI_CRYPTO_TRANSACTION Buffer;
    ADI_CRYPTO_RESULT      eResult = ADI_CRYPTO_SUCCESS;

    /* Open the crypto device */
    eResult = adi_crypto_Open(CRYPTO_DEV_NUM, DeviceMemory, sizeof(DeviceMemory), &hDevice);
    DEBUG_RESULT("Failed to open crypto device", eResult, ADI_CRYPTO_SUCCESS);

#ifdef CRYPTO_ENABLE_CALLBACK
    /* Register Callback */
    eResult = adi_crypto_RegisterCallback (hDevice, CryptoCallback, NULL);
#endif

    /* prepare encode submit */
    memset( &Buffer, 0, sizeof(ADI_CRYPTO_TRANSACTION) );

    Buffer.eCipherMode    = ADI_CRYPTO_MODE_ECB;
    Buffer.eCodingMode    = ADI_CRYPTO_ENCODE;
    Buffer.eAesByteSwap   = ADI_CRYPTO_AES_LITTLE_ENDIAN;
    Buffer.eAesKeyLen     = AES_KEY_LEN;
    Buffer.pKey           = &Key[0];
    Buffer.pInputData     = (uint32_t*)&plainText[0];
    Buffer.numInputBytes  = ECB_BUFF_SIZE;
    Buffer.pOutputData    = (uint32_t*)&ecbComputedCipher[0];
    Buffer.numOutputBytes = ECB_BUFF_SIZE;

    /* Submit the buffer for encryption */
    eResult = adi_crypto_SubmitBuffer (hDevice, &Buffer);
    DEBUG_RESULT("Failed to submit buffer to crypto device", eResult, ADI_CRYPTO_SUCCESS);

#ifdef CRYPTO_ENABLE_CALLBACK
    /* reset callback counter */
    numBuffersReturned = 0;
#endif

    /* Enable the device */
    eResult =  adi_crypto_Enable (hDevice, true);
    DEBUG_RESULT("Failed to enable crypto device", eResult, ADI_CRYPTO_SUCCESS);

#ifndef CRYPTO_ENABLE_CALLBACK
    /* Get ECB ComputedCipher */
    eResult =  adi_crypto_GetBuffer (hDevice, &pGottenBuffer);
    DEBUG_RESULT("Failed to get buffer from the crypto device", eResult, ADI_CRYPTO_SUCCESS);
    if (&Buffer != pGottenBuffer) {
        DEBUG_RESULT("Returned buffer from callback mismatch", eResult, ADI_CRYPTO_ERR_BAD_BUFFER);
    }
#else
    /* await any callback */
    while (numBuffersReturned == 0)
        ;
    if (&Buffer != pcbReturnedBuffer) {
        DEBUG_RESULT("Returned buffer from callback mismatch", eResult, ADI_CRYPTO_ERR_BAD_BUFFER);
    }
#endif

    /* Disable the device */
    eResult =  adi_crypto_Enable (hDevice, false);
    DEBUG_RESULT("Failed to disable crypto device", eResult, ADI_CRYPTO_SUCCESS);

    /* switch buffers for decode */
    Buffer.eCodingMode    = ADI_CRYPTO_DECODE;
    Buffer.pInputData     = (uint32_t*)&ecbComputedCipher[0];
    Buffer.pOutputData    = (uint32_t*)&ecbDecryptedText[0];

    /* Submit the buffer for decryption */
    eResult = adi_crypto_SubmitBuffer (hDevice, &Buffer);
    DEBUG_RESULT("Failed to submit buffer to crypto device", eResult, ADI_CRYPTO_SUCCESS);

#ifdef CRYPTO_ENABLE_CALLBACK
    /* reset callback counter */
    numBuffersReturned = 0;
#endif

    /* Enable the device */
    eResult =  adi_crypto_Enable (hDevice, true);
    DEBUG_RESULT("Failed to enable crypto device", eResult, ADI_CRYPTO_SUCCESS);

#ifndef CRYPTO_ENABLE_CALLBACK
    /* Get ECB plaintext */
    eResult =  adi_crypto_GetBuffer (hDevice, &pGottenBuffer);
    DEBUG_RESULT("Failed to get buffer from the crypto device", eResult, ADI_CRYPTO_SUCCESS);
    if (&Buffer != pGottenBuffer) {
        DEBUG_RESULT("Returned buffer from callback mismatch", eResult, ADI_CRYPTO_ERR_BAD_BUFFER);
    }
#else
    /* await any callback */
    while (numBuffersReturned == 0)
        ;
    if (&Buffer != pcbReturnedBuffer) {
        DEBUG_RESULT("Returned buffer from callback mismatch", eResult, ADI_CRYPTO_ERR_BAD_BUFFER);
    }
#endif

    /* Disable the device */
    eResult =  adi_crypto_Enable (hDevice, false);
    DEBUG_RESULT("Failed to disable crypto device", eResult, ADI_CRYPTO_SUCCESS);

    /* Close the crypto device */
    eResult =  adi_crypto_Close(hDevice);
    DEBUG_RESULT("Failed to close crypto device", eResult, ADI_CRYPTO_SUCCESS);
}

void CBC_Encrypt_Decrypt(void)
{
    ADI_CRYPTO_HANDLE      hDevice;
    ADI_CRYPTO_TRANSACTION Buffer;
    ADI_CRYPTO_RESULT      eResult = ADI_CRYPTO_SUCCESS;

    /* Open the crypto device */
    eResult = adi_crypto_Open(CRYPTO_DEV_NUM, DeviceMemory, sizeof(DeviceMemory), &hDevice);
    DEBUG_RESULT("Failed to open crypto device", eResult, ADI_CRYPTO_SUCCESS);

#ifdef CRYPTO_ENABLE_CALLBACK
    /* Register Callback */
    eResult = adi_crypto_RegisterCallback (hDevice, CryptoCallback, NULL);
#endif

    /* prepare encode submit */
    memset( &Buffer, 0, sizeof(ADI_CRYPTO_TRANSACTION) );

    Buffer.eCipherMode    = ADI_CRYPTO_MODE_CBC;
    Buffer.pNonceIV       = (uint8_t*)&initial_vector[0];
    Buffer.eCodingMode    = ADI_CRYPTO_ENCODE;
    Buffer.eAesByteSwap   = ADI_CRYPTO_AES_LITTLE_ENDIAN;
    Buffer.eAesKeyLen     = AES_KEY_LEN;
    Buffer.pKey           = &Key[0];
    Buffer.pInputData     = (uint32_t*)&plainText[0];
    Buffer.numInputBytes  = ECB_BUFF_SIZE;
    Buffer.pOutputData    = (uint32_t*)&cbcComputedCipher[0];
    Buffer.numOutputBytes = ECB_BUFF_SIZE;

    /* Submit the buffer for encryption */
    eResult = adi_crypto_SubmitBuffer (hDevice, &Buffer);
    DEBUG_RESULT("Failed to submit buffer to crypto device", eResult, ADI_CRYPTO_SUCCESS);

#ifdef CRYPTO_ENABLE_CALLBACK
    /* reset callback counter */
    numBuffersReturned = 0;
#endif

    /* Enable the device */
    eResult =  adi_crypto_Enable (hDevice, true);
    DEBUG_RESULT("Failed to enable crypto device", eResult, ADI_CRYPTO_SUCCESS);

#ifndef CRYPTO_ENABLE_CALLBACK
    /* Get ECB ComputedCipher */
    eResult =  adi_crypto_GetBuffer (hDevice, &pGottenBuffer);
    DEBUG_RESULT("Failed to get buffer from the crypto device", eResult, ADI_CRYPTO_SUCCESS);
    if (&Buffer != pGottenBuffer) {
        DEBUG_RESULT("Returned buffer from callback mismatch", eResult, ADI_CRYPTO_ERR_BAD_BUFFER);
    }
#else
    /* await any callback */
    while (numBuffersReturned == 0)
        ;
    if (&Buffer != pcbReturnedBuffer) {
        DEBUG_RESULT("Returned buffer from callback mismatch", eResult, ADI_CRYPTO_ERR_BAD_BUFFER);
    }
#endif

    /* Disable the device */
    eResult =  adi_crypto_Enable (hDevice, false);
    DEBUG_RESULT("Failed to disable crypto device", eResult, ADI_CRYPTO_SUCCESS);

    /* switch buffers for decode */
    Buffer.eCodingMode    = ADI_CRYPTO_DECODE;
    Buffer.pInputData     = (uint32_t*)&cbcComputedCipher[0];
    Buffer.pOutputData    = (uint32_t*)&cbcDecryptedText[0];

    /* Submit the buffer for decryption */
    eResult = adi_crypto_SubmitBuffer (hDevice, &Buffer);
    DEBUG_RESULT("Failed to submit buffer to crypto device", eResult, ADI_CRYPTO_SUCCESS);

#ifdef CRYPTO_ENABLE_CALLBACK
    /* reset callback counter */
    numBuffersReturned = 0;
#endif

    /* Enable the device */
    eResult =  adi_crypto_Enable (hDevice, true);
    DEBUG_RESULT("Failed to enable crypto device", eResult, ADI_CRYPTO_SUCCESS);

#ifndef CRYPTO_ENABLE_CALLBACK
    /* Get ECB plaintext */
    eResult =  adi_crypto_GetBuffer (hDevice, &pGottenBuffer);
    DEBUG_RESULT("Failed to get buffer from the crypto device", eResult, ADI_CRYPTO_SUCCESS);
    if (&Buffer != pGottenBuffer) {
        DEBUG_RESULT("Returned buffer from callback mismatch", eResult, ADI_CRYPTO_ERR_BAD_BUFFER);
    }
#else
    /* await any callback */
    while (numBuffersReturned == 0)
        ;
    if (&Buffer != pcbReturnedBuffer) {
        DEBUG_RESULT("Returned buffer from callback mismatch", eResult, ADI_CRYPTO_ERR_BAD_BUFFER);
    }
#endif

    /* Disable the device */
    eResult =  adi_crypto_Enable (hDevice, false);
    DEBUG_RESULT("Failed to disable crypto device", eResult, ADI_CRYPTO_SUCCESS);

    /* Close the crypto device */
    eResult =  adi_crypto_Close(hDevice);
    DEBUG_RESULT("Failed to close crypto device", eResult, ADI_CRYPTO_SUCCESS);
}

void CCM_Encrypt_Decrypt(void)
{
    ADI_CRYPTO_HANDLE     hDevice;
    ADI_CRYPTO_TRANSACTION Buffer;
    ADI_CRYPTO_RESULT     eResult = ADI_CRYPTO_SUCCESS;

    uint8_t nOnce[13] = {0,1,2,3,4,5,6,7,8,9,10,11,12};

    /* Open the crypto device */
    eResult = adi_crypto_Open(CRYPTO_DEV_NUM, DeviceMemory, sizeof(DeviceMemory), &hDevice);
    DEBUG_RESULT("Failed to open crypto device", eResult, ADI_CRYPTO_SUCCESS);

#ifdef CRYPTO_ENABLE_CALLBACK
    /* Register Callback */
    eResult = adi_crypto_RegisterCallback (hDevice, CryptoCallback, NULL);
#endif

    /* prepare submit */
    memset( &Buffer, 0, sizeof(ADI_CRYPTO_TRANSACTION) );

    Buffer.eCipherMode    = ADI_CRYPTO_MODE_CCM;
    Buffer.eCodingMode    = ADI_CRYPTO_ENCODE;
    Buffer.eAesByteSwap   = ADI_CRYPTO_AES_LITTLE_ENDIAN;
    Buffer.eAesKeyLen     = AES_KEY_LEN;
    Buffer.pKey           = &Key[0];
    Buffer.pAuthData      = (uint32_t*)&ccmAuthenticationText[0];
    Buffer.numAuthBytes   = CCM_AUTH_BUFF_SIZE;
    Buffer.pInputData     = (uint32_t*)&ccmPlainText[0];
    Buffer.numInputBytes  = CCM_PAYLOAD_BUFF_SIZE;
    Buffer.pOutputData    = (uint32_t*)&ccmComputedCipher[0];
    Buffer.numOutputBytes = CCM_PAYLOAD_BUFF_SIZE + CCM_DIGEST_SIZE;
    Buffer.pNonceIV       = &nOnce[0];
    Buffer.CounterInit    = 0u;
    Buffer.numValidBytes  = 16u;

    /* Submit the buffer for encryption */
    eResult = adi_crypto_SubmitBuffer (hDevice, &Buffer);
    DEBUG_RESULT("Failed to submit buffer to crypto device", eResult, ADI_CRYPTO_SUCCESS);

#ifdef CRYPTO_ENABLE_CALLBACK
    /* reset callback counter */
    numBuffersReturned = 0;
#endif

    /* Enable the device */
    eResult =  adi_crypto_Enable (hDevice, true);
    DEBUG_RESULT("Failed to enable crypto device", eResult, ADI_CRYPTO_SUCCESS);

#ifndef CRYPTO_ENABLE_CALLBACK
    /* Get CCM encoded Buffer */
    eResult =  adi_crypto_GetBuffer (hDevice, &pGottenBuffer);
    DEBUG_RESULT("Failed to get buffer from the crypto device", eResult, ADI_CRYPTO_SUCCESS);
    if (&Buffer != pGottenBuffer) {
        DEBUG_RESULT("Returned buffer from callback mismatch", eResult, ADI_CRYPTO_ERR_BAD_BUFFER);
    }
#else
    /* await any callback */
    while (numBuffersReturned == 0)
        ;
    if (&Buffer != pcbReturnedBuffer) {
        DEBUG_RESULT("Returned buffer from callback mismatch", eResult, ADI_CRYPTO_ERR_BAD_BUFFER);
    }
#endif

    /* Disable the device */
    eResult =  adi_crypto_Enable (hDevice, false);
    DEBUG_RESULT("Failed to disable crypto device", eResult, ADI_CRYPTO_SUCCESS);

    /* swich buffers for decode */
    Buffer.eCodingMode    = ADI_CRYPTO_DECODE;
    Buffer.pInputData     = (uint32_t*)&ccmComputedCipher[0];
    Buffer.pOutputData    = (uint32_t*)&ccmDecryptedText[0];

    /* Submit the buffer for decryption */
    eResult = adi_crypto_SubmitBuffer (hDevice, &Buffer);
    DEBUG_RESULT("Failed to submit buffer to crypto device", eResult, ADI_CRYPTO_SUCCESS);

#ifdef CRYPTO_ENABLE_CALLBACK
    /* reset callback counter */
    numBuffersReturned = 0;
#endif

    /* Enable the device */
    eResult =  adi_crypto_Enable (hDevice, true);
    DEBUG_RESULT("Failed to enable crypto device", eResult, ADI_CRYPTO_SUCCESS);

#ifndef CRYPTO_ENABLE_CALLBACK
    /* Get CCM decoded Buffer */
    eResult =  adi_crypto_GetBuffer (hDevice, &pGottenBuffer);
    DEBUG_RESULT("Failed to get buffer from the crypto device", eResult, ADI_CRYPTO_SUCCESS);
    if (&Buffer != pGottenBuffer) {
        DEBUG_RESULT("Returned buffer from callback mismatch", eResult, ADI_CRYPTO_ERR_BAD_BUFFER);
    }
#else
    /* await any callback */
    while (numBuffersReturned == 0)
        ;
    if (&Buffer != pcbReturnedBuffer) {
        DEBUG_RESULT("Returned buffer from callback mismatch", eResult, ADI_CRYPTO_ERR_BAD_BUFFER);
    }
#endif

    /* Disable the device */
    eResult =  adi_crypto_Enable (hDevice, false);
    DEBUG_RESULT("Failed to disable crypto device", eResult, ADI_CRYPTO_SUCCESS);


    /* Close the crypto device */
    eResult =  adi_crypto_Close(hDevice);
    DEBUG_RESULT("Failed to close crypto device", eResult, ADI_CRYPTO_SUCCESS);
}


/*********************************************************************
*
*   Function:   main
*
*********************************************************************/
int main (void)
{
    /* test system initialization */
    common_Init();

    if(adi_pwr_Init()!= ADI_PWR_SUCCESS) {
        DEBUG_MESSAGE("\n Failed to intialize the power service \n");
    }

    if(ADI_PWR_SUCCESS != adi_pwr_SetClockDivider(ADI_CLOCK_HCLK,1)) {
        DEBUG_MESSAGE("Failed to intialize the power service\n");
    }

    if(ADI_PWR_SUCCESS != adi_pwr_SetClockDivider(ADI_CLOCK_PCLK,1))
    {
        DEBUG_MESSAGE("Failed to intialize the power service\n");
    }

    /* Init the buffers */
    InitBuffers();

    /* Do a ECB Encryption and Decryption */
    ECB_Encrypt_Decrypt();

    /* Do a CBC Encryption and Decryption */
    CBC_Encrypt_Decrypt();

    /* Do a CCM Encryption and Decryption */
    CCM_Encrypt_Decrypt();

    /* SHA */
    SHA_Compute();

    /* Verify the transfer */
    if (VerifyBuffers())
    {
        DEBUG_MESSAGE("All done! Crypto example completed successfully");
    }
}


static void InitBuffers(void)
{
    /* ECB zero out ComputedCipher/decryptedtext */
    for (int x = 0; x < ECB_BUFF_SIZE; x++) {
      ecbComputedCipher[x] = 0;
      ecbDecryptedText[x] = 0;
    }

    /* CBC zero out ComputedCipher/decryptedtext */
    for (int x = 0; x < ECB_BUFF_SIZE; x++) {
      cbcComputedCipher[x] = 0;
      cbcDecryptedText[x] = 0;
    }

    /* initialize the CCM authentication data */
    for (int x = 0; x < CCM_AUTH_BUFF_SIZE; x++) {
        ccmAuthenticationText[x] = rand() % 256;
    }

    /* initialize CCM plaintext and zero out ComputedCipher/decryptedtext */
    for (int x = 0; x < CCM_PAYLOAD_BUFF_SIZE; x++)
    {
        ccmPlainText[x]     = rand() % 256;
        ccmComputedCipher[x] = 0;
        ccmDecryptedText[x] = 0;
    }

    /* zero out CCM authentication tags (digest) in both output buffers */
    for (int x = CCM_PAYLOAD_BUFF_SIZE; x < (CCM_PAYLOAD_BUFF_SIZE + CCM_DIGEST_SIZE); x++) {
        ccmComputedCipher[x] = 0;
        ccmDecryptedText[x] = 0;
    }
}


static bool VerifyBuffers (void)
{
    int bufferIndex, hashIndex;
    
    /* verify ECB decrypted data */
    for (bufferIndex = 0; bufferIndex < ECB_BUFF_SIZE; bufferIndex++) {
        if (plainText[bufferIndex] != ecbDecryptedText[bufferIndex]){
            DEBUG_MESSAGE("ECB mismatch at index %d\n", bufferIndex);
            return false;
        }
        /* Check encrypted data against NIST values */
        if (ecbComputedCipher[bufferIndex] != ecbExpectedCipher[bufferIndex]){
            DEBUG_MESSAGE("ECB encryped mismatch at index %d\n", bufferIndex);
            return false;
        }
    }

    /* verify CBC decrypted data */
    for (bufferIndex = 0; bufferIndex < ECB_BUFF_SIZE; bufferIndex++) {
        if (plainText[bufferIndex] != cbcDecryptedText[bufferIndex]){
            DEBUG_MESSAGE("CBC mismatch at index %d\n", bufferIndex);
            return false;
        }
        /* Check encrypted data against NIST values */
        if (cbcComputedCipher[bufferIndex] != cbcExpectedCipher[bufferIndex]){
            DEBUG_MESSAGE("CBC encryped mismatch at index %d\n", bufferIndex);
            return false;
        }
    }

    /* verify CCM decrypted plaintext against origional plaintext */
    for (bufferIndex = 0; bufferIndex < CCM_PAYLOAD_BUFF_SIZE; bufferIndex++) {
        if (ccmPlainText[bufferIndex] != ccmDecryptedText[bufferIndex]){
            DEBUG_MESSAGE("CCM mismatch at index %d\n", bufferIndex);
            return false;
        }
    }

    /* compare CCM authentication digests (tags) of cyphertext and recovered decrypted text */
    for (bufferIndex = CCM_PAYLOAD_BUFF_SIZE; bufferIndex < (CCM_PAYLOAD_BUFF_SIZE + CCM_DIGEST_SIZE); bufferIndex++) {
        if (ccmComputedCipher[bufferIndex] != ccmDecryptedText[bufferIndex]){
            DEBUG_MESSAGE("MAC mismatch at index %d\n", bufferIndex);
            return false;
        }
    }

    /* Verify SHA results */
    uint8_t expectedByte;  /* unpack bytes from 32-bit words */
    for (hashIndex = 0; hashIndex < ADI_CRYPTO_SHA_HASH_BYTES; hashIndex++) {

        expectedByte = Sha1_ExpectedHash[hashIndex/4] >> (24 - ((hashIndex%4)*8));
        if (Sha1_ComputedHash[hashIndex] != expectedByte) {
            DEBUG_MESSAGE("SHA hash1 mismatch at index %d\n", hashIndex);
            return false;
        }

        expectedByte = Sha2_ExpectedHash[hashIndex/4] >> (24 - ((hashIndex%4)*8));
        if (Sha2_ComputedHash[hashIndex] != expectedByte) {
            DEBUG_MESSAGE("SHA hash2 mismatch at index %d\n", hashIndex);
            return false;
        }

        expectedByte = Sha3_ExpectedHash[hashIndex/4] >> (24 - ((hashIndex%4)*8));
        if (Sha3_ComputedHash[hashIndex] != expectedByte) {
            DEBUG_MESSAGE("SHA hash3 mismatch at index %d\n", hashIndex);
            return false;
        }
    }

    return true;
}

/*****/
