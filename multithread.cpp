#include "multithread.h"
#include <QDebug>
#include <QString>
#include "Format.h"
#include "datapackage.h"

multithread::multithread()
{
    this->isDone = true;
    this->pointer = nullptr;
    this->header = nullptr;
    this->pkt_data = nullptr;
}

bool multithread::setPointer(pcap *pointer){
    this->pointer = pointer;

    if(pointer){
        return true;
    }else{
        return false;
    }
}

void multithread::setFlag(){
    this->isDone = false;
}

void multithread::resetFlag(){
    this->isDone = true;
}

void multithread::run(){
    u_int number_package = 0;
    while(true){
        if(isDone){
            break;
        }else{
            int res = pcap_next_ex(pointer, &header, &pkt_data);
            if(res == 0){
                continue;
            }
            local_time_sec = header->ts.tv_sec;
            localtime_s(&local_time, &local_time_sec);
            strftime(timeString, sizeof(timeString), "%H:%M:%S", &local_time);

//            qDebug() << timeString;
            QString info = "";
            int type = ethernetPackageHandle(pkt_data, info);
            if(type){
                DataPackage data;
                int len = header->len;
                data.setInfo(info);
                data.setDataLength(len);
                data.setTimeStamp(timeString);
                data.setPackageType(type);
                data.setPointer(pkt_data, len);
                if(data.pkt_content != nullptr){
                    emit send(data);
                    number_package++;
                }
            }
        }
    }
}

int multithread::ethernetPackageHandle(const u_char *pkt_content, QString &info){
    ETHER_HEADER *ethenet;
    u_short content_type;
    ethenet = (ETHER_HEADER*)(pkt_content);
    content_type = ntohs(ethenet->ether_type);
    switch(content_type){
    case 0x0800:{   // ip
        int ipPackage = 0;
        int res = ipPackageHandle(pkt_content, ipPackage);
        switch(res){
        case 1:{    // icmp
            info = icmpPackageHandle(pkt_content);
            return 2;
        }
        case 6:{    // tcp
            return tcpPackageHandle(pkt_content, info, ipPackage);

        }
        case 17:{   // udp
            return udpPackageHandle(pkt_content, info);
        }
        default:break;
        }

        break;
    }
    case 0x0806:{   // arp
        info = arpPackageHandle(pkt_content);
        return 1;
    }
    default: break;
    }
    return 0;
}

int multithread::ipPackageHandle(const u_char *pkt_content, int &ipPackage){
    IP_HEADER *ip;
    ip = (IP_HEADER *)(pkt_content + 14);
    int protocol = ip->protocol;
    ipPackage = (ip->total_length - ((ip->versiosn_head_length) & 0x0F) * 4);
    return protocol;
}

int multithread::tcpPackageHandle(const u_char *pkt_content, QString &info, int &ipPackage){
    TCP_HEADER *tcp;
    tcp = (TCP_HEADER *)(pkt_content + 14 + 20);
    u_short src = ntohs(tcp->src_port);
    u_short des = ntohs(tcp->des_port);

    QString proSend = "";
    QString proRecv = "";

    int type = 3;
    int delta = (tcp->header_length >> 4) * 4;
    int tcpPayLoad = ipPackage - delta;

    if((src == 443 || des == 443) && (tcpPayLoad > 0)){
        if(src == 443){
            proSend = "(https)";
        }else{
            proRecv = "(https)";
        }
        u_char *ssl;
        ssl = (u_char*)(pkt_content + 14 + 20 + delta);
        u_char isTls = *(ssl);
        ssl++;
        u_short*pointer = (u_short*)(ssl);
        u_short version = ntohs(*pointer);
        if(isTls >= 20 && isTls <= 23 && version >= 0x0301 && version <= 0x0304){
            type = 6;
            switch(isTls){
            case 20:{
                info = "Change Cipher Spec";
                break;
            }
            case 21:{
                info = "Alert";
                break;
            }
            case 22:{
                info = "Handshake";
                ssl += 4;
                u_char type = (*ssl);
                switch (type) {
                case 1: {
                    info += " Client Hello";
                    break;
                }
                case 2: {
                    info += " Server hello";
                    break;
                }
                case 4: {
                    info += " New Session Ticket";
                    break;
                }
                case 11:{
                    info += " Certificate";
                    break;
                }
                case 16:{
                    info += " Client Key Exchange";
                    break;
                }
                case 12:{
                    info += " Server Key Exchange";
                    break;
                }
                case 14:{
                    info += " Server Hello Done";
                    break;
                }
                default:break;
                }
                break;
            }
            case 23:{
                info = "Application Data";
                break;
            }
            default:{
                break;
            }
            }
            return type;
        }else{
            type = 7;
        } 
    }

    if(type == 7){
        info = "Continuation Data";
    }else{
        info += QString::number(src) + proSend + "->" + QString::number(des) + proRecv;

        QString flag = "";
        if(tcp->flags & 0x08) flag += "PSH,";
        if(tcp->flags & 0x10) flag += "ACK,";
        if(tcp->flags & 0x02) flag += "SYN,";
        if(tcp->flags & 0x20) flag += "URG,";
        if(tcp->flags & 0x01) flag += "FIN,";
        if(tcp->flags & 0x04) flag += "RST,";
        if(flag != ""){
            flag = flag.left(flag.length() - 1);
            info += "[" + flag + "]";
        }

        u_int sequence = ntohl(tcp->sequence);
        u_int ack = ntohl(tcp->ack);
        u_short window = ntohs(tcp->window_size);

        info += " Seq=" + QString::number(sequence) + "Ack=" + QString::number(ack) + "win=" + QString::number(window) + "len=" + QString::number(tcpPayLoad);
    }
    
    return type;
}

int multithread::udpPackageHandle(const u_char *pkt_content, QString &info){
    UDP_HEADER *udp;
    udp = (UDP_HEADER *)(pkt_content + 14 + 20);
    u_short des = ntohs(udp->des_port);
    u_short src = ntohs(udp->src_port);

    if(des == 53 || src == 53){
        if(des == 53)   // dns query
            info = dnsPackageHandle(pkt_content);
        else if(src == 53)  // dns reply
            info = dnsPackageHandle(pkt_content);
        return 5;
    }else{
        QString res = QString::number(src) + "->" + QString::number(des);
        u_short data_len = ntohs(udp->data_length);
        res += "len = " + QString::number(data_len);
        info = res;
        return 4;
    }
}

QString multithread::arpPackageHandle(const u_char *pkt_content){
    ARP_HEADER *arp;
    arp = (ARP_HEADER *)(pkt_content + 14);

    u_short op = ntohs(arp->op_code);
    QString res = "";
    u_char *des_addr = arp->des_ip_addr;
    QString desIP = QString::number(*des_addr) + "."
                    + QString::number(*(des_addr + 1)) + "."
                    + QString::number(*(des_addr + 2)) + "."
                    + QString::number(*(des_addr + 3));
    u_char *src_addr = arp->src_ip_addr;
    QString srcIP = QString::number(*src_addr) + "."
                    + QString::number(*(src_addr + 1)) + "."
                    + QString::number(*(src_addr + 2)) + "."
                    + QString::number(*(src_addr + 3));
    u_char *src_eth_addr = arp->src_eth_addr;
    QString srcEth = byteToString(src_eth_addr, 1) + ":"
                    + byteToString((src_eth_addr + 1), 1) + ":"
                    + byteToString((src_eth_addr + 2), 1) + ":"
                    + byteToString((src_eth_addr + 3), 1) + ":"
                    + byteToString((src_eth_addr + 4), 1) + ":"
                    + byteToString((src_eth_addr + 5), 1);
    if(op == 1){
        res = "who has " + desIP + "? Tell " + srcIP;
    }
    else if(op == 2){
        res = srcIP + " is at " + srcEth;
    }
    return res;
}

QString multithread::byteToString(u_char *str, int size){
    QString res = "";
    for(int i = 0; i < size; i++){
        char one = str[i] >> 4;
        if(one >= 0x0A){
            one += 0x41 - 0x0A;
        }else{
            one += 0x30;
        }

        char two = str[i] & 0xF;
        if(two >= 0x0A){
            two += 0x41 - 0x0A;
        }else{
            two += 0x30;
        }

        res.append(one);
        res.append(two);
    }
    return res;
}

QString multithread::icmpPackageHandle(const u_char *pkt_content){
    ICMP_HEADER*icmp;
    icmp = (ICMP_HEADER*)(pkt_content + 20 + 14);
    u_char type = icmp->type;
    u_char code = icmp->code;
    QString result = "";
    switch (type) {
    case 0:{
        if(!code)
            result = "Echo response (ping)";
        break;
    }
    case 3:{
        switch (code) {
        case 0:{
            result = "Network unreachable";
            break;
        }
        case 1:{
            result = "Host unreachable";
            break;
        }
        case 2:{
            result = "Protocol unreachable";
            break;
        }
        case 3:{
            result = "Port unreachable";
            break;
        }
        case 4:{
            result = "Fragmentation is required, but DF is set";
            break;
        }
        case 5:{
            result = "Source route selection failed";
            break;
        }
        case 6:{
            result = "Unknown target network";
            break;
        }
        default:break;
        }
        break;
    }
    case 4:{
        result = "Source station suppression [congestion control]";
        break;
    }
    case 5:{
        result = "Relocation";
        break;
    }
    case 8:{
        if(!code)
            result = "Echo request (ping)";
        break;
    }
    default:break;
    }
    return result;
}


QString multithread::dnsPackageHandle(const u_char *pkt_content){
    DNS_HEADER*dns;
    dns = (DNS_HEADER*)(pkt_content + 14 + 20 + 8);
    u_short identification = ntohs(dns->identification);
    u_short type = ntohs(dns->flags);
    QString info = "";
    if((type & 0xf800) == 0x0000){
        info = "Standard query ";
    }
    else if((type & 0xf800) == 0x8000){
        info = "Standard query response ";
    }
    QString name = "";
    char*domain = (char*)(pkt_content + 14 + 20 + 8 + 12);
    while(*domain != 0x00){
        if(domain && (*domain) <= 64){
            int length = *domain;
            domain++;
            for(int k = 0;k < length;k++){
                name += (*domain);
                domain++;
            }
            name += ".";
        }else break;
    }
    // DNS_QUESITON *qus = (DNS_QUESITON*)(pkt_content + 14 + 20 + 8 + 12 + stringLength);
    // qDebug()<<ntohs(qus->query_type);
    // qDebug()<<ntohs(qus->query_class);
    name = name.left(name.length()-1);
    return info + "0x" + QString::number(identification,16) + " " + name;
}




