/*********************************************************************************

Copyright(c) 2016 Analog Devices, Inc. All Rights Reserved.

This software is proprietary and confidential.  By using this software you agree
to the terms of the associated Analog Devices License Agreement.

*********************************************************************************/

/*
* Use the GPIO service to Toggle LED's when the push buttons are pressed
* on the ADuCM4x50 EZ-Kit.
*/

#include <drivers/pwr/adi_pwr.h>
#include <drivers/gpio/adi_gpio.h>
#include "common.h"

/* used for exit timeout */
#define MAXCOUNT (10000000u)

static volatile uint64_t count;
static ADI_GPIO_RESULT eToggleResult;


/*
 * GPIO event Callback function
 */
static void pinIntCallback(void* pCBParam, uint32_t Port,  void* PinIntData)
{
    /* push button 1 */
    if((Port == (uint32_t)ADI_GPIO_PORT2) && (*(uint32_t*)PinIntData & ADI_GPIO_PIN_9))
    {
        /* toggle LED 4 */
        eToggleResult = adi_gpio_Toggle(ADI_GPIO_PORT1, ADI_GPIO_PIN_12);
    }
    /* push button 2 */
    else if((Port == (uint32_t)ADI_GPIO_PORT2) && (*(uint32_t*)PinIntData & ADI_GPIO_PIN_6))
    {
        /* toggle LED 5 */
        eToggleResult = adi_gpio_Toggle(ADI_GPIO_PORT1, ADI_GPIO_PIN_13);
    }

    /* reset the exit counter */
    count = 0u;
}

/*
 * main
 */
int main(void)
{
    ADI_GPIO_RESULT eResult;
    static uint8_t gpioMemory[ADI_GPIO_MEMORY_SIZE];

    /* example system initialization */
    common_Init();
    
    do
    {
        if(adi_pwr_Init()!= ADI_PWR_SUCCESS)
        {
            DEBUG_MESSAGE("\n Failed to initialize the power service \n");
            eResult = ADI_GPIO_FAILURE; 
            break;
        }
        if(ADI_PWR_SUCCESS != adi_pwr_SetClockDivider(ADI_CLOCK_HCLK,1))
        {
            DEBUG_MESSAGE("Failed to initialize the power service\n");
            eResult = ADI_GPIO_FAILURE;
            break;
        }
        if(ADI_PWR_SUCCESS != adi_pwr_SetClockDivider(ADI_CLOCK_PCLK,1))
        {
            DEBUG_MESSAGE("Failed to initialize the power service\n");
            eResult = ADI_GPIO_FAILURE;
            break;
        }
        
        /* init the GPIO service */
        if(ADI_GPIO_SUCCESS != (eResult = adi_gpio_Init(gpioMemory, ADI_GPIO_MEMORY_SIZE)))
        {
            DEBUG_MESSAGE("adi_gpio_Init failed\n");
            break;
        }

        /*
         * Setup Push Button 4 and 5
         */

        /* set GPIO input */
        if(ADI_GPIO_SUCCESS != (eResult = adi_gpio_InputEnable(ADI_GPIO_PORT2, ADI_GPIO_PIN_9, true)))
        {
            DEBUG_MESSAGE("adi_gpio_InputEnable failed\n");
            break;
        }

        /* set GPIO input */
        if(ADI_GPIO_SUCCESS != (eResult = adi_gpio_InputEnable(ADI_GPIO_PORT2, ADI_GPIO_PIN_6, true)))
        {
            DEBUG_MESSAGE("adi_gpio_InputEnable failed\n");
            break;
        }

        /* set Pin polarity as rising edge */
        if(ADI_GPIO_SUCCESS != (eResult = adi_gpio_SetGroupInterruptPolarity(ADI_GPIO_PORT2, ADI_GPIO_PIN_6 | ADI_GPIO_PIN_9)))
        {
            DEBUG_MESSAGE("adi_gpio_SetGroupInterruptPolarity failed\n");
            break;
        }

        /* Enable pin interrupt on group interrupt A */
        if(ADI_GPIO_SUCCESS != (eResult = adi_gpio_SetGroupInterruptPins(ADI_GPIO_PORT2, ADI_GPIO_INTA_IRQ, ADI_GPIO_PIN_9 | ADI_GPIO_PIN_6 )))
        {
            DEBUG_MESSAGE("adi_gpio_SetGroupInterruptPins failed\n");
            break;
        }
		
        /* Register the callback */
        if(ADI_GPIO_SUCCESS != (eResult = adi_gpio_RegisterCallback (ADI_GPIO_INTA_IRQ, pinIntCallback, (void*)ADI_GPIO_INTA_IRQ)))
        {
            DEBUG_MESSAGE("adi_gpio_RegisterCallback failed\n");
            break;
        }

        /* set GPIO output LED 4 and 5 */
        if(ADI_GPIO_SUCCESS != (eResult = adi_gpio_OutputEnable(ADI_GPIO_PORT1, (ADI_GPIO_PIN_12 | ADI_GPIO_PIN_13), true)))
        {
            DEBUG_MESSAGE("adi_gpio_SetDirection failed\n");
            break;
        }
    }while(0);

    count = 0u;
    DEBUG_MESSAGE("\nPress PB1 or PB2 to toggle LED4 and LED5 on the ADuCM4x50 EZ-Kit\n\n");

    /* wait for push button interrupts - exit the loop after a while */
    while(count < MAXCOUNT)
    {
        count++;
    }

    if (ADI_GPIO_SUCCESS != eResult)
    {
        common_Fail("Failed to configure the push buttons or LED's\n");
    }
    else if(ADI_GPIO_SUCCESS != eToggleResult)
    {
        common_Fail("Failed to run GPIO example using LED/Pushbutton\n");
    }
    else
    {
        common_Pass();
    }

    return 0;
}
