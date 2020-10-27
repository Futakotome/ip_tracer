#include <iostream>
#include <winsock2.h>
#include <ws2tcpip.h>

using namespace std;

#pragma comment(lib, "Ws2_32.lib")

typedef struct
{
    unsigned char hdr_len : 4;     //4位头部长度
    unsigned char version : 4;     //4位版本号
    unsigned char tos;             //8位服务类型
    unsigned short total_len;      //16位总长度
    unsigned short identifier;     //16标示符
    unsigned short frag_and_flags; //3位标志加13位片偏移
    unsigned char ttl;             //8位生存时间
    unsigned char protocol;        //8位上层协议号
    unsigned short checksum;       //16位校验和
    unsigned long sourceIP;        //32位源ip地址
    unsigned long destIP;          //32位 目的ip地址
} IP_HEADER;

typedef struct
{
    BYTE type;    //8位类型字段
    BYTE code;    //8位代码字段
    USHORT cksum; //16位校验和
    USHORT id;    //16位标示符
    USHORT seq;   //16位序列号
} ICMP_HEADER;

typedef struct
{
    USHORT usSeqNo;        //序列号
    DWORD dwRoundTripTime; //返回时间
    in_addr dwIPaddr;      //返回报文的ip地址
} DECODE_RESULT;

//机算网际校验和
USHORT checksum(USHORT *pBuf, int iSize)
{
    unsigned long cksum = 0;
    while (iSize > 1)
    {
        cksum += *pBuf++;
        iSize -= sizeof(USHORT);
    }
    if (iSize)
    {
        cksum += *(USHORT *)pBuf;
    }
    cksum = (cksum >> 16) + (cksum & 0xffff);
    cksum += (cksum >> 16);
    return (USHORT)(~cksum);
}

//对数据包解码
BOOL DecodeICMPResponse(char *pBuf, int iPacketSize, DECODE_RESULT &DecodeResult, BYTE ICMP_ECHO_REPLY, BYTE ICMP_TIMEOUT)
{
    //检查数据包大小的合法性
    IP_HEADER *pIpHdr = (IP_HEADER *)pBuf;
    int iIpHdrLen = pIpHdr->hdr_len * 4;
    if (iPacketSize < (int)(iIpHdrLen + sizeof(ICMP_HEADER)))
    {
        return false;
    }
    //根据icmp报文类型提取ID字段和序列号字段
    ICMP_HEADER *pIcmpHdr = (ICMP_HEADER *)(pBuf + iIpHdrLen);
    USHORT usId, usSquNo;
    //ICMP回显应答报文
    if (pIcmpHdr->type == ICMP_ECHO_REPLY)
    {
        usId = pIcmpHdr->id;
        usSquNo = pIcmpHdr->seq;
    }
    //ICMP超时差错报文
    else if (pIcmpHdr->type == ICMP_TIMEOUT)
    {
        //payload 中的ip头
        char *pInnerIpHdr = pBuf + iIpHdrLen + sizeof(ICMP_HEADER);
        //payload 中的ip头长
        int iInnerIPHdrLen = ((IP_HEADER *)pInnerIpHdr)->hdr_len * 4;
        //payload 中的icmp头
        ICMP_HEADER *pInnerIcmpHdr = (ICMP_HEADER *)(pInnerIpHdr + iInnerIPHdrLen);
        usId = pInnerIcmpHdr->id;
        usSquNo = pInnerIcmpHdr->seq;
    }
    else
    {
        return false;
    }
    //检查id和序列号以肯定受到期待的报文
    if (usId != (USHORT)GetCurrentProcessId() || usSquNo != DecodeResult.usSeqNo)
    {
        return false;
    }
    //记录ip地址并计算往返时间
    DecodeResult.dwIPaddr.s_addr = pIpHdr->sourceIP;
    DecodeResult.dwRoundTripTime = GetTickCount() - DecodeResult.dwRoundTripTime;
    //处理正确受到的ICMP报文
    if (pIcmpHdr->type == ICMP_ECHO_REPLY || pIcmpHdr->type == ICMP_TIMEOUT)
    {
        //输出往返时间信息
        if (DecodeResult.dwRoundTripTime)
        {
            cout << "     " << DecodeResult.dwRoundTripTime << "ms" << flush;
        }
        else
        {
            cout << "     "
                 << "<1ms" << flush;
        }
    }
    return true;
}

int main()
{
    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);
    char IpAddress[255];
    cout << "input a ip or address: ";
    cin >> IpAddress;
    u_long ulDestIP = inet_addr(IpAddress);
    //转换不成功时按域名解析
    if (ulDestIP == INADDR_NONE)
    {
        hostent *pHostent = gethostbyname(IpAddress);
        if (pHostent)
        {
            ulDestIP = (*(in_addr *)pHostent->h_addr).s_addr;
        }
        else
        {
            cout << "ip/address invalidate" << endl;
            WSACleanup();
            return 0;
        }
    }
    cout << "Tracing route to " << IpAddress << " with a maximum of 30 hops.\n"
         << endl;
    //填充目的端socket地址
    sockaddr_in destSockAddr;
    ZeroMemory(&destSockAddr, sizeof(sockaddr_in));
    destSockAddr.sin_family = AF_INET;
    destSockAddr.sin_addr.s_addr = ulDestIP;
    //建立原始套接字
    SOCKET sockRaw = WSASocket(AF_INET, SOCK_RAW, IPPROTO_ICMP, NULL, 0, WSA_FLAG_OVERLAPPED);
    //超时时间
    int iTimeout = 3000;
    //接收超时
    setsockopt(sockRaw, SOL_SOCKET, SO_RCVTIMEO, (char *)&iTimeout, sizeof(iTimeout));
    //发送超时
    setsockopt(sockRaw, SOL_SOCKET, SO_SNDTIMEO, (char *)&iTimeout, sizeof(iTimeout));

    //构造icmp回显请求消息,并以TTL递增的顺序发送报文
    //icmp类型字段
    const BYTE ICMP_ECHO_REQUEST = 8; //请求回显
    const BYTE ICMP_ECHO_REPLY = 0;   //回显应答
    const BYTE ICMP_TIMEOUT = 11;     //传输超时

    //其余常量定义
    const int DEF_ICMP_DATA_SIZE = 32;     //icmp报文默认数据字段长度
    const int MAX_ICMP_PACKET_SIZE = 1024; //icmp报文最大长度
    const DWORD DEF_ICMP_TIMEOUT = 3000;   //回显应答超时时间
    const int DEF_MAX_HOP = 30;            //最大跳数

    //填充icmp报文中每次发送时不变的字段
    char IcmpSendBuf[sizeof(ICMP_HEADER) + DEF_ICMP_DATA_SIZE]; //发送缓冲区
    memset(IcmpSendBuf, 0, sizeof(IcmpSendBuf));                //初始化发送缓冲区
    char IcmpRecvBuf[MAX_ICMP_PACKET_SIZE];                     //接收缓冲区
    memset(IcmpRecvBuf, 0, sizeof(IcmpRecvBuf));                //初始化接收缓冲区

    ICMP_HEADER *pIcmpHeader = (ICMP_HEADER *)IcmpSendBuf;
    pIcmpHeader->type = ICMP_ECHO_REQUEST;                              //请求回显
    pIcmpHeader->code = 0;                                              //代码字段为0
    pIcmpHeader->id = (USHORT)GetCurrentProcessId();                    //id字段为当前进程号
    memset(IcmpSendBuf + sizeof(ICMP_HEADER), 'E', DEF_ICMP_DATA_SIZE); //数据字段

    USHORT usSeqNo = 0; //ICMP报文序列号
    int iTTL = 1;       //ttl初始值为1
    BOOL bReachDestHost = FALSE;
    int iMaxHot = DEF_MAX_HOP; //循环的最大次数
    DECODE_RESULT DecodeResult;
    while (!bReachDestHost && iMaxHot--)
    {
        //设置ip报头的ttl字段
        setsockopt(sockRaw, IPPROTO_IP, IP_TTL, (char *)&iTTL, sizeof(iTTL));
        cout << iTTL << flush; //输出当前序号
        //填充ICMP报文中每次发送变化的字段
        ((ICMP_HEADER *)IcmpSendBuf)->cksum = 0;
        ((ICMP_HEADER *)IcmpSendBuf)->seq = htons(usSeqNo++);
        ((ICMP_HEADER *)IcmpSendBuf)->cksum = checksum((USHORT *)IcmpSendBuf, sizeof(destSockAddr));
        //记录序列号和当前时间
        DecodeResult.usSeqNo = ((ICMP_HEADER *)IcmpSendBuf)->seq;
        DecodeResult.dwRoundTripTime = GetTickCount();
        //发送TCP回显请求信息
        sendto(sockRaw, IcmpSendBuf, sizeof(IcmpSendBuf), 0, (sockaddr *)&destSockAddr, sizeof(destSockAddr));
        //接收icmp报文并解析处理
        sockaddr_in from;
        int iFromLen = sizeof(from);
        int iReadDataLen;
        while (1)
        {
            //接收数据
            iReadDataLen = recvfrom(sockRaw, IcmpRecvBuf, MAX_ICMP_PACKET_SIZE, 0, (sockaddr *)&from, &iFromLen);
            //有数据到达
            if (iReadDataLen != SOCKET_ERROR)
            {
                //解析
                if (DecodeICMPResponse(IcmpRecvBuf, iReadDataLen, DecodeResult, ICMP_ECHO_REPLY, ICMP_TIMEOUT))
                {
                    //到达目的地退出循环
                    if (DecodeResult.dwIPaddr.s_addr == destSockAddr.sin_addr.s_addr)
                    {
                        bReachDestHost = true;
                    }
                    cout << "\t" << inet_ntoa(DecodeResult.dwIPaddr) << endl;
                    break;
                }
            }
            //接收超时
            else if (WSAGetLastError() == WSAETIMEDOUT)
            {
                cout << "     *"
                     << "\t"
                     << "request time out" << endl;
                break;
            }
            else
            {
                break;
            }
        }
        iTTL++; //ttl递增
    }
}