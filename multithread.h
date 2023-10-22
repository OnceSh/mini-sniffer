#ifndef MULTITHREAD_H
#define MULTITHREAD_H
#include <QThread>
#include "pcap.h"
#include "datapackage.h"
#include <QString>
#include "winsock2.h"
#include <Format.h>
#include <QQueue>

class multithread:public QThread
{
    Q_OBJECT
public:
    multithread();
    bool setPointer(pcap_t *pointer);       // 打开设备
    void setFlag();
    void resetFlag();
    void run() override;                    // 重载run函数
    int ethernetPackageHandle(const u_char *pkt_content, QString &info);
    int ipPackageHandle(const u_char *pkt_content, int &ipPackage);
    int tcpPackageHandle(const u_char *pkt_content, QString &info, int &ipPackage);
    int udpPackageHandle(const u_char *pkt_content, QString &info);
    QString arpPackageHandle(const u_char *pkt_content);
    QString icmpPackageHandle(const u_char *pkt_content);
    QString dnsPackageHandle(const u_char *pkt_content);
protected:
    static QString byteToString(u_char *str, int size);
signals:
    void send(DataPackage data);

private:
    pcap_t * pointer;
    struct pcap_pkthdr *header;
    const u_char *pkt_data;
    time_t local_time_sec;
    struct tm local_time;
    char timeString[16];
    bool isDone;
};

#endif // MULTITHREAD_H
