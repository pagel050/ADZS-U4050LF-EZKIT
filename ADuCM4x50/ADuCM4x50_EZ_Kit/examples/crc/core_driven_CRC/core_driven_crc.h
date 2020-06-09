/*********************************************************************************
Copyright(c) 2016 Analog Devices, Inc. All Rights Reserved.

This software is proprietary and confidential.  By using this software you agree
to the terms of the associated Analog Devices License Agreement.

*********************************************************************************/
/*!
 * @file        core_driven_crc.h
 * @brief       Example to demonstrate core-driven CRC operations.
 * @details     This is the primary include file for the CRC example that shows
 *              how to use the CRC hardware engine to compute CRC
 *
 */
#ifndef CORE_DRIVEN_CRC_H
#define CORE_DRIVEN_CRC_H

/*=============  I N C L U D E S   =============*/

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/*=============  D E F I N E S  =============*/

/* CRC Device number to work on */
#define	CRC_DEV_NUM                     (0u)

/* 32-bit data used to define the CRC polynome value */
#define CRC32_POLYNOMIAL_BE             (0x04C11DB7)
#define CRC32_POLYNOMIAL_LE             (0xEDB88320)

/* 32-bit data used to define the CRC seed value */
#define CRC32_SEED_VALUE                (0xFFFFFFFF)

/* Number of data in CRC Buffer used for testing (requires multiple DMA requests) */
#define CRC_BUF_NUM_DATA                (2048)

#endif /* CORE_DRIVEN_CRC_H */
