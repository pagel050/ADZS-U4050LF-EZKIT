         Analog Devices, Inc. ADuCM4x50 Application 


Overview:
=========    
  This example demonstrate how to use the ADC Controller driver. 
  The example uses the ADC to sample the input signal at channel 0 and write the acquired samples 
  to a file (when the WRITE_SAMPLES_TO_FILE macro is defined). 
  This examples operates on non-blocking mode. 


User Configuration Macros:
==========================
    ADI_ADC_ENABLE_MULTI_ACQUIRE which controls the types of data transfers used. If
    anything more than single channels, single reads is used then this should be set to 0.
    This example should use the default.

Hardware Setup:
===============
    ADuCM4x50 EZ Kit configured with default settings.

External connections:
=====================
    Connect a signal generator signal to pin 0 of J5, marked A0.  Ensure that the signal does not 
    exceed 2.5V (Internal reference set in the example).  
    

How to build and run:
=====================
    Build the project, load the executable to ADuCM4x50, open a "Terminal I/O" window and run it. 

Expected Result:
=====================
    Upon successful completion the example will produce an output file called ADC_Out.dat in:
      .\ADuCM4x50\iar - for the IAR environment.
      .\ADuCM4x50\cces\Debug or Release - for the CCES environment.
      Note: Saving of ADC data is not performed in Keil as it currently does not support File IO.
      However, the data can be seen in memory, by viewing the contents of the "ADC_DataBuffer" 
      array.

    The ADC_Out.dat file will contain the collected samples in a single column, and can be opened 
    using many text editor programs.  It can also be easily opened by MS Excel as a delimited 
    data file.  Data can also be plotted graphically using MS Excel, "Line Chart" being the most
    useful for this example - please consult the Help section in MS Excel for assistance on how
    to do this.
    
References:
===========
    ADuCM4x50 Hardware Reference Manual
