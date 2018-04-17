# Secure Communication for applications on embedded devices


 ### Project: Decentralizing authentication and authorization in embedded devices

The architecture is implemented using Python and C languages. The implementations use AES-CBC-128 and RSA-1024 as symmetric and asymmetric encryption algorithms, respectively. They use XORed double encryption of data for hash generation. The application was implemented using FreeRTOS running on EK-TM4C129EXL IoT board. 

* The C implementation focuses on resource constraints and portability.
It comprises a server and client entities. It provides portability files, that can be used to port the client/server entity to any device and/or OS.

You can read more about the project [here](https://sunithan29.github.io/hyde/blog/iot-post/)
