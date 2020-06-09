/*
 *****************************************************************************
 * @file:    uart_callback.h
 * @brief:   Header file for uart_callback.c
 *****************************************************************************

Copyright(c) 2016 Analog Devices, Inc. All Rights Reserved.

This software is proprietary and confidential.  By using this software you agree
to the terms of the associated Analog Devices License Agreement.

*********************************************************************************/
/*!
* @file      uart_callback.h
*
* @brief     This is a header file for uart_callback.c
*
*/
#ifndef UART_CALLBACK_H
#define UART_CALLBACK_H

static void UARTCallback(void        *pAppHandle,
                         uint32_t     nEvent,
                         void        *pArg);

/* Memory required by the driver for bidirectional mode of operation. */
#define ADI_UART_MEMORY_SIZE    (ADI_UART_BIDIR_MEMORY_SIZE)

/* Size of the data buffers that will be processed. */
#define SIZE_OF_BUFFER  26u

/* UART device number. There are 2 devices, so this can be 0 or 1. */
#define UART_DEVICE_NUM 1u

/* Timeout value for receiving data. */
#define UART_GET_BUFFER_TIMEOUT 1000000u

#endif /* UART_CALLBACK_H */
