#include "secsock_portable.h"


int32_t secsock_sendto(void* xSocket, uint8_t* data, size_t DataLength, uint8_t* IPaddr, uint16_t* port)
{
    struct freertos_sockaddr xRemoteAddress;

    xRemoteAddress.sin_port = FreeRTOS_htons(*port);
    xRemoteAddress.sin_addr = FreeRTOS_inet_addr_quick( IPaddr[0], IPaddr[1], IPaddr[2], IPaddr[3]);

    return FreeRTOS_sendto(
                                xSocket,
                                (void*)data,
                                (size_t) DataLength,
                                0,
                                &xRemoteAddress,
                                sizeof(xRemoteAddress)
                          );
}
int32_t secsock_recvfrom(void* xSocket, uint8_t* data, size_t DataLength, uint8_t* IPaddr, uint16_t* port)
{
    struct freertos_sockaddr xSourceAddress;
    int32_t rxBytes,ip;

    rxBytes = FreeRTOS_recvfrom(
                                    xSocket,
                                    (void*)data,
                                    (size_t) DataLength,
                                    0,
                                    &xSourceAddress,
                                    sizeof(xSourceAddress)
                               );
    rxBytes -= 28;//ip + udp header
    if(rxBytes>0)
    {
        *port = FreeRTOS_ntohs(xSourceAddress.sin_port );
        ip = xSourceAddress.sin_addr;
        IPaddr[0] = ( ( ip ) & 0xffUL );
        IPaddr[1] = ( ( ip>>8 ) & 0xffUL );
        IPaddr[2] = ( ( ip>>16 ) & 0xffUL );
        IPaddr[3] = ( ( ip>>24 ) & 0xffUL );
        return rxBytes;
    }
    return 0;
}
