            Analog Devices, Inc. ADuCM4x50 Application Example

Project Name: crypto_example

Description:  Application example demonstrating the Crypto device driver in various cipher modes.
 

Overview:
=========
    This example demonstrates configuration of the Crypto device driver to perform a number of
    cipher encrypt/decrypt operations.  
    
    The application performs the usual declarations and initializations, followed by a series of
    crypto data transformation, consisting of: ECB, CBC, CCB and SHA-256.
    
	For ECB and CBC modes, known NIST input data is used for encryption and the encrypted data is 
	tested against known NIST encryption data. The input data and encrypted data are test vectors
	from: National Institute of Standards and Technology Special Publication 800-38A 2001 ED. The 
	data is then decrypted and tested against the original known input data. For CCB and SHA-256, 
	random data is used and decrypted results are verified against origional input data.

    Both callback and buffer query/get buffer management methods are supported.  Also, both DMA
    and PIO data transfer methods are supported.
    
    The Crypto driver has user configurable static build macros that are managed in the
    adi_crypto_config.h file found in the installation "ADuCM4x50_EZ_Kit\Include\config" directory. 
    All static configurations are set to their hardware (power-on-reset) values by default.

    See complete "Crypto Device Driver" module in the "ADuCM4x50 Device Drivers API Reference Manual"
    html documentation for full description of the Crypto Driver API and data structures.


User Configuration Macros:
==========================
	CRYPTO_ENABLE_CALLBACK
		This macro is controlled at the top of the crypto_example.c source file and controls use of
		application callbacks for obtaining buffer operation results, as well as event notifications.
		Enable this macro to test with callbacks, disable it to test with buffer query/get calls.
	

Hardware Setup:
===============
There is no special hardware setting to manage other than default jumper settings for the EZ-Kit.
    
 
External connections:
=====================
    Emulator connection required. This test requires a live debugger session to run because it uses
    semi-hosted printf output to write to the Terminal I/O window. Therefore, the test will hard fault
    on the first printf write attempt if no debugger is attached.
    
    No other external connections are required.



How to build and run:
=====================
    Load the project file, build, load and run the example.  Open the Terminal I/O window view to view output.
    

Expected Result:
=====================
	The example performs the following operations and reports progress to the Terminal I/O window:
		1. Encode and decode NIST data using ECB cipher mode. Test encrypted data against NIST standard.
		2. Encode and decode NIST data using CBC cipher mode. Test encrypted data against NIST standard.
		3. Encode and decode random data using CCB cipher mode.
		4. Compute the SHA-256 hash of two different blocks of random data.
		5. Readback and verify decoded, as well as authentication digest in CCB mode.
		6. On failure, look for failure-specific messages.
		7. On success, look for message:
			"All done! Crypto example completed successfully".
		
        
References:
===========
    ADuCM4x50 Hardware Reference Manual
