/*
 *****************************************************************************
 * @file:    uart_loop_back.h
 * @brief:   File which contain "main" for testing UART Device Driver.
 *****************************************************************************

Copyright(c) 2016 Analog Devices, Inc. All Rights Reserved.

This software is proprietary and confidential.  By using this software you agree
to the terms of the associated Analog Devices License Agreement.

*********************************************************************************/
/*!
* @file      uart_loop_back.h
*
* @brief     This is a header file for uart_loop_back.c
*
*/

#ifndef UART_LOOPBACK_H
#define UART_LOOPBACK_H


/* Memory required by the driver for bidirectional mode of operation. */
#define ADI_UART_MEMORY_SIZE    (ADI_UART_BIDIR_MEMORY_SIZE)

/* Size of the data buffers that will be processed. */
#define SIZE_OF_BUFFER  26u

/* UART device number. There are 2 devices, so this can be 0 or 1. */
#define UART_DEVICE_NUM 1u

/* Timeout value for receiving data. */
#define UART_GET_BUFFER_TIMEOUT 1000000u

#endif /* UART_LOOPBACK_H */
