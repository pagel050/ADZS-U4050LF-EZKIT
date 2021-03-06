/*
    FreeRTOS V8.2.1 - Copyright (C) 2015 Real Time Engineers Ltd.
    All rights reserved

    VISIT http://www.FreeRTOS.org TO ENSURE YOU ARE USING THE LATEST VERSION.

    This file is part of the FreeRTOS distribution.

    FreeRTOS is free software; you can redistribute it and/or modify it under
    the terms of the GNU General Public License (version 2) as published by the
    Free Software Foundation >>!AND MODIFIED BY!<< the FreeRTOS exception.

    ***************************************************************************
    >>!   NOTE: The modification to the GPL is included to allow you to     !<<
    >>!   distribute a combined work that includes FreeRTOS without being   !<<
    >>!   obliged to provide the source code for proprietary components     !<<
    >>!   outside of the FreeRTOS kernel.                                   !<<
    ***************************************************************************

    FreeRTOS is distributed in the hope that it will be useful, but WITHOUT ANY
    WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
    FOR A PARTICULAR PURPOSE.  Full license text is available on the following
    link: http://www.freertos.org/a00114.html

    ***************************************************************************
     *                                                                       *
     *    FreeRTOS provides completely free yet professionally developed,    *
     *    robust, strictly quality controlled, supported, and cross          *
     *    platform software that is more than just the market leader, it     *
     *    is the industry's de facto standard.                               *
     *                                                                       *
     *    Help yourself get started quickly while simultaneously helping     *
     *    to support the FreeRTOS project by purchasing a FreeRTOS           *
     *    tutorial book, reference manual, or both:                          *
     *    http://www.FreeRTOS.org/Documentation                              *
     *                                                                       *
    ***************************************************************************

    http://www.FreeRTOS.org/FAQHelp.html - Having a problem?  Start by reading
    the FAQ page "My application does not run, what could be wrong?".  Have you
    defined configASSERT()?

    http://www.FreeRTOS.org/support - In return for receiving this top quality
    embedded software for free we request you assist our global community by
    participating in the support forum.

    http://www.FreeRTOS.org/training - Investing in training allows your team to
    be as productive as possible as early as possible.  Now you can receive
    FreeRTOS training directly from Richard Barry, CEO of Real Time Engineers
    Ltd, and the world's leading authority on the world's leading RTOS.

    http://www.FreeRTOS.org/plus - A selection of FreeRTOS ecosystem products,
    including FreeRTOS+Trace - an indispensable productivity tool, a DOS
    compatible FAT file system, and our tiny thread aware UDP/IP stack.

    http://www.FreeRTOS.org/labs - Where new FreeRTOS products go to incubate.
    Come and try FreeRTOS+TCP, our new open source TCP/IP stack for FreeRTOS.

    http://www.OpenRTOS.com - Real Time Engineers ltd. license FreeRTOS to High
    Integrity Systems ltd. to sell under the OpenRTOS brand.  Low cost OpenRTOS
    licenses offer ticketed support, indemnification and commercial middleware.

    http://www.SafeRTOS.com - High Integrity Systems also provide a safety
    engineered and independently SIL3 certified version for use in safety and
    mission critical applications that require provable dependability.

    1 tab == 4 spaces!
*/

#ifndef FREERTOS_CONFIG_H
#define FREERTOS_CONFIG_H

/*-----------------------------------------------------------
 * Application specific definitions.
 *
 * These definitions should be adjusted for your particular hardware and
 * application requirements.
 *
 * THESE PARAMETERS ARE DESCRIBED WITHIN THE 'CONFIGURATION' SECTION OF THE
 * FreeRTOS API DOCUMENTATION AVAILABLE ON THE FreeRTOS.org WEB SITE. 
 *
 * See http://www.freertos.org/a00110.html.
 *----------------------------------------------------------*/

#define configUSE_TRACE_FACILITY 0

/*
 * @brief   RTOS Scheduler Type 
 * 
 * @details 0 = Cooperative Scheduler
 *          1 = Preemptive Scheduler
 */
#define configUSE_PREEMPTION                    (1)

/*
 * @brief   Scheduler Optimization 
 * 
 * @details 0 = Generic C implementation 
 *          1 = Assembly implementation (might not be availalbe for your hardware)
 */
#define configUSE_PORT_OPTIMISED_TASK_SELECTION (1)

/*
 * @brief   Tickless Idle Task (Dynamic Ticks?)
 * 
 * @details 0 = Disable (tick interrupt keeps running in idle) 
 *          1 = Enable (might not be available for your hardware)
 */
#define configUSE_TICKLESS_IDLE                 (0)

/*
 * @brief  CPU Clock Frequency (Hz) 
 */
#define configCPU_CLOCK_HZ                      (26000000u)


/*
 * @brief   RTOS Tick Frequency (Hz)
 */
#define configTICK_RATE_HZ                      (1000u)

/*
 * @brief   Number of Application Priorities
 * 
 * @details Tasks can share prioirities, and each priority level consumes memory
 * 
 */
#define configMAX_PRIORITIES                    (15)

/*
 * @brief   Idle Task Stack Size (words)
 * 
 * @details FreeRTOS advises against changing this value from the default (128)
 *
 */
#define configMINIMAL_STACK_SIZE                (128u)

/*
 * @brief   Maximum Task Name Length (chars)
 *
 */
#define configMAX_TASK_NAME_LEN                 (16)

/*
 * @brief   Size of TickType_t
 *
 * @details 0 = 32-bit (longer maximum delay) 
 *          1 = 16-bit (improves performance on 8-bit and 16-bit architectures)
 *
 */
#define configUSE_16_BIT_TICKS                  (0)

/*
 * @brief   Idle Task Yield
 *
 * @details 0 = Idle task will not yield to other tasks at same priority
 *          1 = Idle task will yield to other tasks at same priority
 *
 */
#define configIDLE_SHOULD_YIELD                 (1)

/*
 * @brief   Use Task Notifications (like task messaging but more lightweight)
 *
 * @details 0 = Turn off task notifications (saves memory)
 *          1 = Turn on task notifications to use this feature
 *
 */
#define configUSE_TASK_NOTIFICATIONS            (1)

/*
 * @brief   Use Mutex Semaphores
 *
 * @details 0 = Disable mutex semaphore related code
 *          1 = Enable mutex semaphore related code
 *
 */
#define configUSE_MUTEXES                       (1)

/*
 * @brief   Use Recursive (i.e. reentrant) Mutexes
 *
 * @details 0 = Disable
 *          1 = Enable
 *
 */
#define configUSE_RECURSIVE_MUTEXES             (0)

/*
 * @brief   Use Counting Semaphores
 *
 * @details 0 = Disable 
 *          1 = Enable
 *
 */
#define configUSE_COUNTING_SEMAPHORES           (0)

/*
 * @brief   Use Legacy Queue Functions  
 *
 * @details 0 = Omit functions (all new designs)
 *          1 = Include functions
 * 
 * @note    Deprecated
 *
 */
#define configUSE_ALTERNATIVE_API               (0)

/*
 * @brief   Maximum number of queues and semaphores that can be registered
 *
 * @details The queue registry is for debugging purposes and allows a name
 *          to be associated with a queue and debug infomration about the queue
 *
 */
#define configQUEUE_REGISTRY_SIZE               (10)

/*
 * @brief   Use Queue Set Functionaliy
 *
 * @details 0 = Disable
 *          1 = Enable
 *
 */
#define configUSE_QUEUE_SETS                    (0)

/*
 * @brief   Use Time Slicing
 *
 * @details 0 = Scheduler will not switch between tasks of equal priority (if they are ready)
 *          1 = Scheduler will switch between tasks of equal priority every tick interrupt (if they are ready)
 *
 */
#define configUSE_TIME_SLICING                  (0)

/*
 * @brief   Use Newlib
 *
 * @details 0 = Do not use newlib
 *          1 = Allocate a "newlib reent" data structure for each task
 *
 */
#define configUSE_NEWLIB_REENTRANT              (0)

/*
 * @brief   FreeRTOS.h Macro Configuration 
 *
 * @details 0 = Using version 8.0.0 or above
 *          1 = Using an older version of FreeRTOS 
 *
 */
#define configENABLE_BACKWARD_COMPATIBILITY     (0)

/*
 * @brief   Thread Local Storage (TLS) Pointers
 *
 * @details TLS allows the user to store values inside the task control block
 *          as an array of void pointers, this value determines the size of 
 *          that array
 *
 */
#define configNUM_THREAD_LOCAL_STORAGE_POINTERS (5u)

/***************** MEMORY ALLOCATION *****************/

/*
 * @brief   Static RTOS Memory Allocation
 *
 * @details 0 = RTOS memory allocated using RAM from FreeRTOS heap
 *          1 = RTOS memory allocated statically by user
 *
 * @note    If set 1, the application must provide a function called
 *          vApplicationGetIdleTaskMemory() to provide memory for 
 *          the Idle Task
 *
 */
#define configSUPPORT_STATIC_ALLOCATION         (1) 

/*
 * @brief   Dynamic RTOS Memory Allocation
 *
 * @details 0 = RTOS memory allocated statically by user
 *          1 = RTOS memory allocated using RAM from FreeRTOS heap (default)
 *
 */
#define configSUPPORT_DYNAMIC_ALLOCATION        (0)

/*
 * @brief   FreeRTOS Heap Size
 *
 * @details Total amount of memory available in the FreeRTOS heap   
 *
 */
#define configTOTAL_HEAP_SIZE                   (0x1000)

/*
 * @brief   Heap Declaration
 *
 * @details 0 = FreeRTOS declares the heap and placed by linker
 *          1 = Heap declared and placed by user
 *
 */
#define configAPPLICATION_ALLOCATED_HEAP        (0) 

/****************** HOOK FUNCTIONS ******************/

/*
 * @brief   Idle Task Hook Function
 *
 * @details 0 = No Idle Task hook function
 *          1 = Must define a function called vApplicationIdleHook
 *
 */
#define configUSE_IDLE_HOOK                     (0)

/*
 * @brief   Tick Hook Function
 *
 * @details 0 = No tick hook function
 *          1 = Must define a function called vApplicationTickHook
 *
 */
#define configUSE_TICK_HOOK                     (0)

/*
 * @brief   Stack Overflow Hook Function
 *
 * @details 0 = No stack overflow hook function
 *          1 = Must define a function called vApplicationStackOverflowHook
 *
 */
#define configCHECK_FOR_STACK_OVERFLOW          (0)

/*
 * @brief   Memory Allocation Failure Hook
 *
 * @details 0 = No memory allocation failure hook function
 *          1 = Must define a function called vApplicationMallocFailedHook
 *
 */
#define configUSE_MALLOC_FAILED_HOOK            (0)

/*
 * @brief   Timer Task Initial Execution Hook Function
 *
 * @details 0 = No timer service task hook function
 *          1 = Must define a function called vApplicationDaemonStartupHook
 *
 * @note    This is only relevent if configUSE_TIMERS is set to 1
 *
 */
#define configUSE_DAEMON_TASK_STARTUP_HOOK      (0)

/******************* CO-ROUTINES *******************/

/*
 * @brief   Enable Co-Routines
 *
 * @details 0 = No co-routines in build
 *          1 = Co-routine functionality is included in build, the file
 *          croutine.c must be included in the build
 *
 */
#define configUSE_CO_ROUTINES 		           (0)

/*
 * @brief   Co-Routine Priorities
 *
 * @details Number of possible priorities available to a set of co-routines
 *
 */
#define configMAX_CO_ROUTINE_PRIORITIES        (2)

/********************** TIMERS *********************/

/*
 * @brief   Enable Timer Functionality
 *
 * @details 0 = No software timer functionality in build
 *          1 = Software timer functionality included in build
 *
 */
#define configUSE_TIMERS                        (0)

/*
 * @brief   Timer Task Priority
 *
 * @details Priority of the timer task, this is the task that handles
 *          and dispatches the software timers
 *
 */
#define configTIMER_TASK_PRIORITY               (3)

/*
 * @brief   Timer Queue Length
 *
 */
#define configTIMER_QUEUE_LENGTH                (10)

/*
 * @brief   Timer Task Stack Size
 *
 */
#define configTIMER_TASK_STACK_DEPTH            configMINIMAL_STACK_SIZE

/***************** PROCESSOR DEPENDENT *****************/

/*
 * @brief   Lowest Possible Processor Priority
 *
 */
#define configKERNEL_INTERRUPT_PRIORITY         (7)

/*
 * @brief    Highest Priority Interrupt FreeRTOS API Calls 
 *
 * @details  The previous macro sets the priority level of the 
 *           RTOS itself. This macro determines the highest 
 *           interrupt priority from which interrupt safe
 *           FreeRTOS API functions can be called. So any ISR
 *           that calls an RTOS API function must have a priority
 *           numerically higher than this value. 
 *
 */
#define configMAX_SYSCALL_INTERRUPT_PRIORITY    (2)

/*
 * @brief    Highest Priority Interrupt FreeRTOS API Calls 
 *
 * @details  Same as the above macro but for older ports
 *
 */
#define configMAX_API_CALL_INTERRUPT_PRIORITY    configMAX_SYSCALL_INTERRUPT_PRIORITY    

/***************** RTOS ERROR HANDLING *****************/

/*
 * @brief   RTOS Error Trapping 
 *
 * @details Allows user to implement the assertion function
 *
 * @param [in] x : Value under test, if equal to 0 an assertion should be raised
 *
 */
#define configASSERT(x) \
                    do {\
                        if ( (x) == (0u) )\
                        {\
                            while(1) {} \
                        }\
                    } while (0);

/***************** OPTIONAL FUNCTIONS *****************/

/* 
 *  These macros allow you to remove unused functions from your build, in theory
 *  the linker should take care of this for you
 */
    

#define INCLUDE_vTaskPrioritySet                1
#define INCLUDE_uxTaskPriorityGet               1
#define INCLUDE_vTaskDelete                     1
#define INCLUDE_vTaskSuspend                    1
#define INCLUDE_xResumeFromISR                  1
#define INCLUDE_vTaskDelayUntil                 1
#define INCLUDE_vTaskDelay                      1
#define INCLUDE_xTaskGetSchedulerState          1
#define INCLUDE_xTaskGetCurrentTaskHandle       1
#define INCLUDE_uxTaskGetStackHighWaterMark     0
#define INCLUDE_xTaskGetIdleTaskHandle          0
#define INCLUDE_eTaskGetState                   0
#define INCLUDE_xEventGroupSetBitFromISR        0
#define INCLUDE_xTimerPendFunctionCall          0
#define INCLUDE_xTaskAbortDelay                 0
#define INCLUDE_xTaskGetHandle                  0
#define INCLUDE_xTaskResumeFromISR              1

/* prevent the trace header file from being included by the assembler */
#ifdef __ICCARM__
#include <trcKernelPort.h>
#endif


#endif /* FREERTOS_CONFIG_H */
