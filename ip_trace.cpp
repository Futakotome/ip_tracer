#include<iostream>
#include<winsock2.h>
#include<ws2tcpip.h>
using namespace std;

#pragma comment(lib,"Ws2_32.lib")

typedef struct 
{
    unsigned char hdr_len:4; //4位头部长度
    unsigned char version:4; //4位版本号
    unsigned char tos;//8位服务类型
    unsigned short total_len; //16位总长度
    unsigned short identifier; //16标示符
    unsigned short frag_and_flags; //3位标志加13位片偏移
    unsigned char ttl;//8位生存时间
    unsigned char protocol;//8位上层协议号
    unsigned short checksum;//16位校验和
    unsigned long sourceIP;//32位源ip地址
    unsigned long destIP;//32位 目的ip地址
}IP_HEADER;

typedef struct 
{
    BYTE type;//8位类型字段
    BYTE code;//8位代码字段
    USHORT cksum;//16位校验和
    USHORT id;//16位标示符
    USHORT seq;//16位序列号
}ICMP_HEADER;

typedef struct 
{
    USHORT usSeqNo; //序列号
    DWORD dwRoundTripTime;//返回时间
    in_addr dwIPaddr;//返回报文的ip地址
}DECODE_RESULT;

