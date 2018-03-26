#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

#include "FreeRTOS.h"
#include "task.h"
#include "queue.h"
#include "semphr.h"
//#include "list.h"
//#include "FreeRTOS_IP.h"
#include "FreeRTOS_Sockets.h"

#include "secsock.h"
#include "secsock_portable.h"

#include "rsa.h"
#include "aes.h"
/*rsa keys*/
extern const char modulus[128];
extern const char privet_expo[128];
extern const char cert[128];
extern const char root_modulus[128];
extern const char public_expo[128];

#if ENTITY_IS_CLIENT
secsockAccessTable to_access_table[MAX_TABLES]={};
#endif
#if ENTITY_IS_SERVER
secsockAccessTable from_access_table[MAX_TABLES]={};
#endif
uint8_t authName[MAX_ENTITY_NAME];
uint8_t dist_key[16];
const char EntityName[] = ENTITY_NAME;
const char GroupName[] = GROUP_NAME;
uint8_t authIP[4] = AUTH_IP;
uint16_t authPort = AUTH_PORT;
bool isRegistered = 0;

//Temp Certificate
//uint8_t Certificate[]="this is for temporary use";
//uint32_t CertificateLength = sizeof(Certificate) - 1; //Can be calculated but this way it will save lot of time


bool respRegistration(void* xSocket)
{
    uint8_t rxBuffer[BUFF_SIZE], ip[sizeof(authIP)];
    int32_t rxSize;
    uint8_t flag;
    uint16_t port=0;
    uint8_t *authCertificate, *data=rxBuffer;
    uint32_t authCertificateLength;
    uint8_t *authkey,*authcert;
    uint32_t nonceGen[4]={rand(), rand(), rand(), rand()};
    int32_t i,j;

    while(1) //wait forever for response, shall be set to some timeout
    {
        rxSize = secsock_recvfrom((void*) xSocket, (uint8_t*) rxBuffer, (size_t) BUFF_SIZE, (uint8_t*) ip, (uint16_t*) &port);
        if(rxSize>0 && port==authPort)
        {
            if(memcmp(authIP, ip, sizeof(authIP)))
                return 0;
        }
        else
        {
            return 0;
        }


        data = memchr(rxBuffer, SEP, (size_t)rxSize);
        data[0] = '\0';
        flag = data[1];
        //Do RSA decryption here

        data += 2;
        authkey = data;
        authcert = data + 128;

        //Validate certificate here
        if(secsock_rsa_verify(authkey, authcert))
        {

           data += 256;
           secsock_rsa_decrypt_128(data, data);
           if(flag == RJCTREG)
           {
               return 0;
           }

           if(flag == NONCE)
           {
               for(i=0;i<16;i++)
               {
                   data[16+i] = ((uint8_t*)nonceGen)[i];
               }

               secsock_rsa_encrypt_128( data, data, 32, authkey); //authkey's place will be replaced by result

               authkey = data;  //Here auth key is used just as temp variable
               data = rxBuffer;
               strcpy(data, EntityName);
               data += strlen(EntityName);
               *data++ = SEP;
               *data++ = NONCE;
               memcpy(data,authkey,128);

               secsock_sendto((void*) xSocket, (uint8_t*) rxBuffer, (size_t) (data - rxBuffer)+128, (uint8_t*) authIP, (uint16_t*) &authPort);
           }

           if(flag == ACPTREG)
           {

               if(!memcmp(nonceGen, data, 16))
               {
                   memcpy(dist_key, data+16, 16);
                   strcpy(authName, rxBuffer);
                   isRegistered = 1;
                   return 1;
               }
           }
        }
    }
}


bool reqRegistration(void* xSocket)
{
    uint8_t txBuffer[BUFF_SIZE];
    uint8_t groupNameLength;
    uint8_t *data = txBuffer;
    int32_t i;

    if(isRegistered)
        return 1;

    strcpy(data, EntityName);
    data += strlen(EntityName);
    *data++ = SEP;
    *data++ = REQREG;

    groupNameLength = (uint8_t) strlen(GroupName);
    *data++ = groupNameLength;
    strcpy(data, GroupName);
    data += groupNameLength;

    for(i=0;i<128;i++)
    {
        data[i] = modulus[i];
        data[i+128] = cert[i];
    }
    data += 256;
    if(secsock_sendto((void*) xSocket, (uint8_t*) txBuffer, (size_t) (data - txBuffer), (uint8_t*) authIP, (uint16_t*) &authPort))
        return respRegistration(xSocket);
    else
        return 0;
}

#if ENTITY_IS_CLIENT
bool respAccess(void* xSocket)
{
    uint8_t rxBuffer[BUFF_SIZE], ip[sizeof(authIP)];
    uint32_t accessCount;
    int32_t rxSize;
    uint8_t flag;
    uint16_t port=0;
    uint8_t *data=rxBuffer;


    rxSize = secsock_recvfrom((void*) xSocket, (uint8_t*) rxBuffer, (size_t) BUFF_SIZE, (uint8_t*) ip, (uint16_t*) &port);
    if(rxSize>0 && port==authPort)
    {
        if(memcmp(authIP, ip, sizeof(authIP)))
            return 0;
    }
    else
    {
        return 0;
    }


    data = memchr(rxBuffer, SEP, (size_t)rxSize);
    data[0] = '\0';
    if(strcmp(authName, rxBuffer))
        return 0;

    if(data[1] != ENCPTD)
        return 0;

    //Do AES decryption here using data[2] and dist_key, return pointer
    data = data + 2;
    if(!secsock_decrypt(data, rxSize - (data-rxBuffer), dist_key))
        return 0;
    //////////////////////////////
    flag = data[0];
    if(flag == RJCTACC)
        return 0;
    if(flag == ACPTACC)
    {
        for(accessCount=0; accessCount< MAX_TABLES;accessCount++)
        {
            if(to_access_table[accessCount].time == 0)
            {
                memcpy(to_access_table[accessCount].entintyName, data+2, (size_t)data[1]);
                data += 2 + data[1];
                to_access_table[accessCount].time = secsock_timeins() + (60 * secsock_ntohl(*(uint32_t*)data));
                data += 4;
                memcpy(to_access_table[accessCount].ip, data, 4);
                data += 4;
                to_access_table[accessCount].port = secsock_ntohs(*(uint16_t*)data);
                data += 2;
                memcpy(to_access_table[accessCount].key, data, 16);
                return 1;
            }
        }
        //could not add if reaches here
        return 0;
    }
        return 0;
}



bool reqAccess(void* xSocket, uint8_t* xEntityName, uint32_t acctime)
{
    uint8_t txBuffer[BUFF_SIZE]={0};
    uint8_t xEntityNameLength;
    uint8_t *data = txBuffer;
    uint8_t *encrypt;
    uint32_t accessCount=0,xDataLength,current_time = secsock_timeins();

    for(accessCount=0;accessCount<MAX_TABLES;accessCount++)
    {
        if(to_access_table[accessCount].time != 0)
        {
            if(!strcmp(xEntityName, to_access_table[accessCount].entintyName))
            {
                if(current_time < to_access_table[accessCount].time)
                {
                    return 1;
                }
                else
                {
                    to_access_table[accessCount].time = 0;
                }
            }
        }
    }

    strcpy(data, EntityName);
    data += strlen(EntityName);
    *data++ = SEP;
    *data++ = ENCPTD;

    encrypt = data;
    *data++ = REQACC;
    xEntityNameLength = (uint8_t) strlen(xEntityName);
    *data++ = xEntityNameLength;
    strcpy(data, xEntityName);
    data += xEntityNameLength;

    *((uint32_t*)data) =  secsock_htonl(acctime);
    data +=  4;
    //Encrtpt data here using "encrypt" pointer
    xDataLength = secsock_encrypt(encrypt, (uint32_t)(data - encrypt), dist_key);

    if(secsock_sendto((void*) xSocket, (uint8_t*) txBuffer, (size_t) (encrypt - txBuffer) + xDataLength, (uint8_t*) authIP, (uint16_t*) &authPort))
        return respAccess(xSocket);
    else
        return 0;
}


bool sendMsg(void* xSocket, uint8_t* xEntityName, uint8_t* msg, uint32_t msgLength)
{
    uint8_t txBuffer[BUFF_SIZE];
    uint8_t *data = txBuffer;
    uint8_t *encrypt=0;
    uint32_t accessCount=0,current_time = secsock_timeins();
    secsockAccessTable *entry;
    uint32_t xDataLength;
    //Check weather message is too big
    if(msgLength > BUFF_SIZE - MAX_ENTITY_NAME - 30) //3 for SEP,ENCPTD and REQCOMM and others
        return 0;

    for(accessCount=0;accessCount<MAX_TABLES;accessCount++)
    {
        if(to_access_table[accessCount].time != 0)
        {
            if(!strcmp(xEntityName, to_access_table[accessCount].entintyName))
            {
                if(current_time < to_access_table[accessCount].time)
                {
                    entry = &(to_access_table[accessCount]);
                    break;
                }
                else
                {
                    to_access_table[accessCount].time = 0;
                    return 0;
                }
            }
         }
    }

    if(accessCount >= MAX_TABLES)
        return 0;       //Could not find entry in either 'to' or 'from' list


    strcpy(data, EntityName);
    data += strlen(EntityName);
    *data++ = SEP;
    *data++ = ENCPTD;

    encrypt = data;
    *data++ = REQCOMM;

    memcpy(data, msg, msgLength);
    data += (size_t)msgLength;



    //Encrypt data here using "encrypt" pointer and entry->key
    xDataLength = secsock_encrypt(encrypt, (uint32_t)(data - encrypt), entry->key);

    if(secsock_sendto((void*) xSocket, (uint8_t*) txBuffer, (size_t) (encrypt - txBuffer)+xDataLength, (uint8_t*) (entry->ip), (uint16_t*)(&(entry->port))))
        return 1;
    else
        return 0;
}



uint32_t recvMsg(void* xSocket, uint8_t* xEntityName, uint8_t* msg, uint32_t msgMaxLength)
{
    uint8_t rxBuffer[BUFF_SIZE];
    uint32_t accessCount,current_time = secsock_timeins();
    int32_t rxSize;
    uint8_t flag,ip[4];
    uint8_t *data=rxBuffer;
    uint16_t port;
    secsockAccessTable *entry;


    for(accessCount=0;accessCount<MAX_TABLES;accessCount++)
    {
        if(to_access_table[accessCount].time != 0)
        {
            if(!strcmp(xEntityName, to_access_table[accessCount].entintyName))
            {
                if(current_time < to_access_table[accessCount].time)
                {
                    entry = &(to_access_table[accessCount]);
                    break;
                }
                else
                {
                    to_access_table[accessCount].time = 0;
                    return 0;
                }
            }
        }
    }
    if(accessCount >= MAX_TABLES)
        return 0;       //Could not find entry in either 'to' or 'from' list


    rxSize = secsock_recvfrom((void*) xSocket, (uint8_t*) rxBuffer, (size_t) BUFF_SIZE, (uint8_t*) ip, (uint16_t*) &port);
    if(rxSize<=0)
    {
        return 0;
    }

    data = memchr(rxBuffer, SEP, (size_t)rxSize);
    data[0] = '\0';
    if(data[1] != ENCPTD)
        return 0;

    if(strcmp(xEntityName,rxBuffer))
        return 0;

    //Do AES decryption here using entry->key
    data = data + 2;
    if(!secsock_decrypt(data, rxSize - (data-rxBuffer), entry->key))
           return 0;
    //////////////////////////////
    flag = data[0];
    data++;
    if(flag==RESPCOMM)
    {
        rxSize -= (data - rxBuffer);
        if(msgMaxLength<rxSize)
            return 0;
        memcpy(msg, data, rxSize);
        return rxSize;
    }
    return 0;
}

#endif

uint32_t secsock_encrypt(uint8_t *data, uint32_t length, uint8_t *key)
{

    uint8_t hash_code[BUFF_SIZE]={0},*hash=(data+16);
    uint32_t iv[4]={rand(),rand(),rand(),rand()};
    int32_t i=length%16,j;
    uint32_t encLength = (i)?(length+16-i):(length);
    //Encrypting
    memcpy(hash_code,data,length);
    AES128_CBC_encrypt_buffer(data + 24, hash_code, length, key, (uint8_t*)iv);

    //generating Hash
    memcpy(hash_code, data+24, encLength);
    memcpy(data,(uint8_t*)iv,16);
    AES128_CBC_encrypt_buffer(hash_code, hash_code, encLength, key, iv);
    for(i=0;i<8;i++)
    {
        hash[i] =  hash_code[i] ^ hash_code[i+8];
    }
    for(j=16;j<encLength;j+=16)
    {
        for(i=0;i<8;i++)
        {
            hash[i] = hash[i] ^ hash_code[j+i] ^ hash_code[j+i+8];
        }
    }

    return encLength+24;
}

bool secsock_decrypt(uint8_t *data, uint32_t length, uint8_t *key)
{
    uint8_t hash_code[BUFF_SIZE]={0};
    uint8_t *iv=data,*hash=(data+16);

    int32_t i,j;

    if((length-8)%16 != 0)
        return 0;
    data = data + 24;
    length = length -24;

    //Check Hash code
    memcpy(hash_code, data, length);
    AES128_CBC_encrypt_buffer(hash_code, hash_code, length, key, iv);
    for(i=0;i<8;i++)
    {
        hash_code[i] =  hash_code[i] ^ hash_code[i+8];
    }
    for(j=16;j<length;j+=16)
    {
        for(i=0;i<8;i++)
        {
            hash_code[i] = hash_code[i] ^ hash_code[j+i] ^ hash_code[j+i+8];
        }
    }
    if(memcmp(hash_code,hash,8))
        return 0;

    //Decrypting data
    AES128_CBC_decrypt_buffer(hash_code,data,length,key,iv);
    memcpy(iv,hash_code,length);
    return 1;
}

bool secsock_rsa_encrypt_128(uint8_t res[], uint8_t data[], uint8_t length,uint8_t key[])
{
    uint8_t final_data[150]={0},final_key[150]={0};
    uint64_t expo[16]={0};
    int32_t i;
    expo[0]= 0x10001;
    if(length>128)
        return 0;
    /*
    uint32_t data_length = length/127, data_rest = length % 127;
    if(data_rest)
    {
        memset(data[(data_length*127)+data_rest], 0,127-data_rest);
        data_length++;
    }*/

    for(i=0;i<128;i++)
    {
        final_key[i]=key[127-i];
        if((127-i)<length-1 && i!=127)
            final_data[i]=data[127-i-1];
    }


    //compute rsa here
    rsa1024(final_data,final_data,expo,final_key);

    for(i=0;i<128;i++)
    {
        res[i]=final_data[127-i];
    }
    return 1;
}
bool secsock_rsa_decrypt_128(uint8_t res[], uint8_t data[])
{
    uint8_t final_data[150]={0},final_key[150]={0},final_expo[150]={0};
    int32_t i;

    /*
    uint32_t data_length = length/127, data_rest = length % 127;
    if(data_rest)
    {
        memset(data[(data_length*127)+data_rest], 0,127-data_rest);
        data_length++;
    }*/

    for(i=0;i<128;i++)
    {
        final_key[i]= modulus[127-i];
        final_data[i]= data[127-i];
        final_expo[i]= privet_expo[127-i];
    }


    //compute rsa here
    rsa1024(final_data,final_data,final_expo,final_key);

    for(i=0;i<127;i++)
    {
        res[i]=final_data[126-i];
    }
    res[i]=0;
    return 1;
}

bool secsock_rsa_verify(uint8_t key[], uint8_t cert_key[])
{
    uint8_t final_data[150]={0},final_key[150]={0};
    uint64_t expo[16]={0};
    int32_t i;
    expo[0]= 0x10001;

    for(i=0;i<128;i++)
    {
        final_key[i]=root_modulus[127-i];
        final_data[i]=cert_key[127-i];
    }

    rsa1024(final_data,final_data, expo, final_key);

    for(i=0;i<128;i++)
    {
        if(key[i]!=final_data[127-i])
            return 0;
    }

    return 1;
}
#if ENTITY_IS_SERVER
uint32_t secsock_listen(void* xSocket,uint8_t *xEntityName, uint8_t* msg, uint32_t msgMaxLength)
{
    uint8_t rxBuffer[BUFF_SIZE], ip[sizeof(authIP)];
    uint32_t accessCount,current_time;
    int32_t rxSize=0;
    uint8_t flag;
    uint16_t port=0;
    uint8_t *data,*key;
    secsockAccessTable *entry;

    while(1)
    {
        if(!isRegistered)
            return 0;   //terminate if not registered
        rxSize = 0;
        while(rxSize<=0)
            rxSize = secsock_recvfrom((void*) xSocket, (uint8_t*) rxBuffer, (size_t) BUFF_SIZE, (uint8_t*) ip, (uint16_t*) &port);

        data = memchr(rxBuffer, SEP, (size_t)rxSize);
        data[0] = '\0';

        if(data[1] != ENCPTD)
            continue;       //if not encrypted reject

        data += 2;

        if(!strcmp(authName, rxBuffer))
        {
               key = dist_key;
        }
        else
        {
            current_time = secsock_timeins();
            for(accessCount=0;accessCount<MAX_TABLES;accessCount++)
            {
                if(from_access_table[accessCount].time != 0)
                {
                    if(!strcmp(rxBuffer, from_access_table[accessCount].entintyName))
                    {
                        if(current_time < from_access_table[accessCount].time)
                        {
                            key = from_access_table[accessCount].key;
                            break;
                        }
                        else
                        {
                            from_access_table[accessCount].time = 0;
                            continue;
                        }
                    }
                }
            }
            if(accessCount >= MAX_TABLES)
                continue;       //Could not find entry in 'from' list
        }




        //Do AES decryption here using data[2] and dist_key, return pointer
        if(!secsock_decrypt(data, rxSize - (data-rxBuffer), key))
            continue;                   //Either integrity of authentication failed
        //////////////////////////////////////////////////////////////////////////
        flag = data[0];
        if(flag == ACKACC)
        {
            for(accessCount=0;accessCount<MAX_TABLES;accessCount++)
            {
                //if(from_access_table[accessCount].time != 0)
                {
                    if(!memcmp(from_access_table[accessCount].entintyName, data+2, (size_t)data[1]))
                    {
                            break;
                    }
                }
            }
            if(accessCount >= MAX_TABLES)
            {
                for(accessCount=0; accessCount< MAX_TABLES;accessCount++)
                {
                    if(from_access_table[accessCount].time == 0)
                    {
                        break;
                    }
                }
            }

            if(accessCount < MAX_TABLES)
            {
                if(from_access_table[accessCount].time == 0)
                {
                    memcpy(from_access_table[accessCount].entintyName, data+2, (size_t)data[1]);
                    data += 2 + data[1];
                    from_access_table[accessCount].time = secsock_timeins() + (60 * secsock_ntohl(*(uint32_t*)data));
                    data += 4;
                    memcpy(from_access_table[accessCount].ip, data, 4);
                    data += 4;
                    from_access_table[accessCount].port = secsock_ntohs(*(uint16_t*)data);
                    data += 2;
                    memcpy(from_access_table[accessCount].key, data, 16);
                }
            }
            else
            {
                //Table over flow
            }
            continue;
        }
        if(flag == REQCOMM)
        {
            data++;
            rxSize -= (data - rxBuffer);
            if(msgMaxLength<rxSize)
                continue;
            memcpy(msg, data, rxSize);
            strcpy(xEntityName,rxBuffer);
            return rxSize;
        }

    }

}

bool sendResp(void* xSocket, uint8_t* xEntityName, uint8_t* msg, uint32_t msgLength)
{
    uint8_t txBuffer[BUFF_SIZE];
    uint8_t *data = txBuffer;
    uint8_t *encrypt=0;
    uint32_t accessCount=0,current_time = secsock_timeins();
    secsockAccessTable *entry;
    uint32_t xDataLength;
    //Check weather message is too big
    if(msgLength > BUFF_SIZE - MAX_ENTITY_NAME - 30) //3 for SEP,ENCPTD and REQCOMM and others
        return 0;

    for(accessCount=0;accessCount<MAX_TABLES;accessCount++)
    {
        if(from_access_table[accessCount].time != 0)
        {
            if(!strcmp(xEntityName, from_access_table[accessCount].entintyName))
            {
                if(current_time < from_access_table[accessCount].time)
                {
                    entry = &(from_access_table[accessCount]);
                    break;
                }
                else
                {
                    from_access_table[accessCount].time = 0;
                    return 0;
                }
            }
         }
    }

    if(accessCount >= MAX_TABLES)
        return 0;       //Could not find entry in  'from' list


    strcpy(data, EntityName);
    data += strlen(EntityName);
    *data++ = SEP;
    *data++ = ENCPTD;

    encrypt = data;
    *data++ = RESPCOMM;

    memcpy(data, msg, msgLength);
    data += (size_t)msgLength;



    //Encrypt data here using "encrypt" pointer and entry->key
    xDataLength = secsock_encrypt(encrypt, (uint32_t)(data - encrypt), entry->key);

    if(secsock_sendto((void*) xSocket, (uint8_t*) txBuffer, (size_t) (encrypt - txBuffer)+xDataLength, (uint8_t*) (entry->ip), (uint16_t*)(&(entry->port))))
        return 1;
    else
        return 0;
}



#endif
//
//int32_t secsockFreeRTOS_sendto( Socket_t xSocket, const void *pvBuffer, size_t xDataLength, BaseType_t xFlags, const struct freertos_sockaddr *pxDestinationAddress, socklen_t xDestinationAddressLength )
//{
//    return secsockFreeRTOS_sendto(xSocket,pvBuffer,xDataLength,xFlags,pxDestinationAddress, xDestinationAddressLength )
//}
//
//
//
//int32_t secsockFreeRTOS_recvfrom( Socket_t xSocket, void *pvBuffer, size_t xBufferLength, BaseType_t xFlags, struct freertos_sockaddr *pxSourceAddress, socklen_t *pxSourceAddressLength )
//{
//    uin32_t xLength;
//    while(1)
//    {
//       xLength = secsockFreeRTOS_recvfrom(xSocket,pvBuffer,xBufferLength, xFlags, pxSourceAddress, pxSourceAddressLength );
//       if (xLength > 0)
//       {
//
//       }
//    }
//}
