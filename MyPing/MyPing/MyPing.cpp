// MyPing.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//
#include <stdio.h>
#include <time.h>
#include <Winsock2.h>
#include <Windows.h> 
#include <iostream>
#include <ws2tcpip.h>

#pragma comment (lib, "ws2_32.lib")

using namespace std;

// 2字节对齐sizeof(icmp_header) == 8 
// 这是ping 在wireshark抓包中的数据结构 
typedef struct icmp_header
{
    unsigned char icmp_type;    // 消息类型
    unsigned char icmp_code;    // 代码
    unsigned short icmp_checksum;    // 校验和
    unsigned short icmp_id;     // 用来惟一标识此请求的ID号，通常设置为进程ID
    unsigned short icmp_sequence;   // 序列号
} icmp_header;

#define ICMP_HEADER_SIZE sizeof(icmp_header)
#define ICMP_ECHO_REQUEST 0x08
#define ICMP_ECHO_REPLY 0x00

// 计算校验和 
unsigned short chsum(struct icmp_header* picmp, int len)
{
    long sum = 0;
    unsigned short* pusicmp = (unsigned short*)picmp;

    while (len > 1)
    {
        sum += *(pusicmp++);
        if (sum & 0x80000000)
        {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        len -= 2;
    }

    if (len)
    {
        sum += (unsigned short)*(unsigned char*)pusicmp;
    }

    while (sum >> 16)
    {
        sum = (sum & 0xffff) + (sum >> 16);
    }

    return (unsigned short)~sum;
}

static int respNum = 0;
static int minTime = 0, maxTime = 0, sumTime = 0;

int ping(char* szDestIp)
{
    int bRet = 1;

    WSADATA wsaData;
    int nTimeOut = 1000;//1s  
    char szBuff[ICMP_HEADER_SIZE + 32] = { 0 };
    icmp_header* pIcmp = (icmp_header*)szBuff;
    char icmp_data[32] = { 0 };
    int iResult;                    // Error check if WSAStartup successful

    iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (iResult != 0) {
        cout << "WSAStartup failed: " << iResult << endl;
        return 1;
    }

    // 创建原始套接字
    SOCKET s = socket(PF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (s == INVALID_SOCKET) {
        printf("socket failed with error: %ld\n", WSAGetLastError());
        WSACleanup();
        return 1;
    }

    // 设置接收超时
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (char const*)&nTimeOut, sizeof(nTimeOut));

    // 设置目的地址
    sockaddr_in dest_addr;
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_addr.S_un.S_addr = inet_addr(szDestIp);
    dest_addr.sin_port = htons(0);

    // 构造ICMP封包
    pIcmp->icmp_type = ICMP_ECHO_REQUEST;
    pIcmp->icmp_code = 0;
    pIcmp->icmp_id = (USHORT)::GetCurrentProcessId();
    pIcmp->icmp_sequence = 0;
    pIcmp->icmp_checksum = 0;

    // 填充数据，可以任意 
    memcpy((szBuff + ICMP_HEADER_SIZE), "abcdefghijklmnopqrstuvwabcdefghi", 32);

    // 计算校验和
    pIcmp->icmp_checksum = chsum((struct icmp_header*)szBuff, sizeof(szBuff));

    sockaddr_in from_addr;
    char szRecvBuff[1024];
    int nLen = sizeof(from_addr);
    int ret, flag = 0;

    DWORD  start = GetTickCount();
    ret = sendto(s, szBuff, sizeof(szBuff), 0, (SOCKADDR*)&dest_addr, sizeof(SOCKADDR));
    if (ret == SOCKET_ERROR) {
        printf("sendto failed with error: %d\n", WSAGetLastError());
        WSACleanup();
        return 1;
    }

    int i = 0;
    //用while循环，因为recvfrom 会接受到很多报文，包括发送出去的报文
    while (1) {
        if (i++ > 5) {// icmp报文 如果到不了目标主机，是不会返回报文，多尝试几次接受数据，如果都没收到 即请求失败 
            flag = 1;
            break;
        }
        memset(szRecvBuff, 0, 1024);
        int ret = recvfrom(s, szRecvBuff, MAXBYTE, 0, (SOCKADDR*)&from_addr, &nLen);
        if (ret == SOCKET_ERROR)
        {
            printf("recv failed with error: %d\n", WSAGetLastError());
            return 1;
        }
        //接受到 目标ip的 报文 
        if (strcmp(inet_ntoa(from_addr.sin_addr), szDestIp) == 0) {
            respNum++;
            break;
        }
    }



    DWORD  end = GetTickCount();
    DWORD time = end - start;

    if (flag) {
        printf("请求超时。\n");
        return bRet;
    }
    sumTime += time;
    if (minTime > time) {
        minTime = time;
    }
    if (maxTime < time) {
        maxTime = time;
    }



    // Windows的原始套接字 开发，系统没有去掉IP协议头，需要程序自己处理。
    // ip头部的第一个字节（只有1个字节不涉及大小端问题），前4位 表示 ip协议版本号，后4位 表示IP 头部长度(单位为4字节)
    char ipInfo = szRecvBuff[0];
    // ipv4头部的第9个字节为TTL的值
    char ttl = szRecvBuff[8];


    int ipVer = ipInfo >> 4;
    int ipHeadLen = ((char)(ipInfo << 4) >> 4) * 4;
    if (ipVer == 4) {
        // 跨过ip协议头，得到ICMP协议头的位置，不过是网络字节序。 
        // 网络字节序 是大端模式 低地址 高位字节 高地址 低位字节。-> 转换为 本地字节序 小端模式 高地址高字节 低地址低字节   
        icmp_header* icmp_rep = (icmp_header*)(szRecvBuff + ipHeadLen);
        //由于校验和是 2个字节 涉及大小端问题，需要转换字节序 
        unsigned short checksum_host = ntohs(icmp_rep->icmp_checksum);// 转主机字节序 和wireshark 抓取的报文做比较 

        if (icmp_rep->icmp_type == 0) { //回显应答报文 
            printf("来自 %s 的回复：字节=32 时间=%2dms TTL=%d checksum=0x%x \n", szDestIp, time, ttl, checksum_host);
        }
        else {
            bRet = 0;
            printf("请求超时。type = %d\n", icmp_rep->icmp_type);
        }
    }

    return bRet;
}

char* gethostaddress(PCSTR hostname)
{
    WORD wVersion = MAKEWORD(2, 2); // Used to request version 2.2 of Windows sockets
    WSADATA wsaData;                // Data loaded by WSAStartup
    int iResult;                    // Error check if WSAStartup successful
    DWORD dwRetval;

    // Initialize Winsock
    iResult = WSAStartup(wVersion, &wsaData);
    if (iResult != 0) {
        cout << "WSAStartup failed: " << iResult << endl;
        return NULL;
    }

    // Declare and initialize variables
    struct addrinfo* result = NULL;
    struct addrinfo* ptr = NULL;
    struct addrinfo hints;

    //--------------------------------
    // Setup the hints address info structure
    // which is passed to the getaddrinfo() function
    ZeroMemory(&hints, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    //--------------------------------
    // Call getaddrinfo(). If the call succeeds,
    // the result variable will hold a linked list
    // of addrinfo structures containing response
    // information
    dwRetval = getaddrinfo(hostname, "80", &hints, &result);
    if (dwRetval != 0) {
        printf("getaddrinfo failed with error: %d\n", dwRetval);
        WSACleanup();
        return NULL;
    }

    // Retrieve each address and print out the hex bytes
    struct sockaddr_in* sockaddr_ipv4;

    char ipstringbuffer[46];
    DWORD ipbufferlength = 46;

    int i = 1;

    ptr = result;

    while (ptr->ai_family != AF_INET)
    {
        ptr = ptr->ai_next;
    }

    if(ptr!=NULL){
        sockaddr_ipv4 = (struct sockaddr_in*) ptr->ai_addr;
        inet_ntop(AF_INET, &sockaddr_ipv4->sin_addr, ipstringbuffer, sizeof(ipstringbuffer));
    }
    printf("%s 的IPV4 地址为: %s\n",hostname,ipstringbuffer);

    WSACleanup();

    return ipstringbuffer;
}

int main(int argc, char** argv)
{
    if (argc < 2) {
        printf("usage : %s IPv4 address!\n", argv[0]);
        return 1;
    }

    char* address = (char *)malloc(16*sizeof(char));

    if(argv[1][0]>='0' && argv[1][0]<='9')
    {
        memcpy(address,argv[1],16*sizeof(char));
    }
    else
    {
        char* temp = gethostaddress(argv[1]);
        memcpy(address, temp, 16 * sizeof(char));
    }

    printf("\n正在 Ping %s 具有 32 字节的数据:\n", address);
    int i = 0;

    while (i < 4)
    {
        int result = ping(address);
        Sleep(500);
        i++;
    }

    printf("\n%s 的 Ping 统计信息:\n", argv[1]);
    printf("    数据包: 已发送 = %d，已接收 = %d，丢失 = %d (%d%% 丢失)，\n", i, respNum, i - respNum, (i - respNum) * 100 / i);
    if (i - respNum >= 4) {
        return 0;
    }
    printf("往返行程的估计时间(以毫秒为单位):\n");
    printf("    最短 = %dms，最长 = %dms，平均 = %dms\n", minTime, maxTime, sumTime / respNum);
    return 0;
}

// 运行程序: Ctrl + F5 或调试 >“开始执行(不调试)”菜单
// 调试程序: F5 或调试 >“开始调试”菜单

// 入门使用技巧: 
//   1. 使用解决方案资源管理器窗口添加/管理文件
//   2. 使用团队资源管理器窗口连接到源代码管理
//   3. 使用输出窗口查看生成输出和其他消息
//   4. 使用错误列表窗口查看错误
//   5. 转到“项目”>“添加新项”以创建新的代码文件，或转到“项目”>“添加现有项”以将现有代码文件添加到项目
//   6. 将来，若要再次打开此项目，请转到“文件”>“打开”>“项目”并选择 .sln 文件
