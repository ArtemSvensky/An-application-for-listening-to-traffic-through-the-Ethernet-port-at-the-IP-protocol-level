#include <iostream>
#include <fstream>
#include <string>
#include <WinSock2.h>
#include <Ws2tcpip.h>
#include <Windows.h>

#pragma comment(lib, "ws2_32.lib")

// Структура заголовка IP пакета
struct IPHeader {

    BYTE    ver_ihl;        // Версия и длина заголовка
    BYTE    tos;            // Тип обслуживания
    USHORT  tlen;           // Общая длина
    USHORT  identification; // Идентификатор
    USHORT  flags_fo;       // Флаги и фрагментация
    BYTE    ttl;            // Время жизни
    BYTE    proto;          // Протокол
    USHORT  crc;            // Контрольная сумма
    ULONG   srcIP;          // IP-адрес отправителя
    ULONG   destIP;         // IP-адрес получателя
};

// Структура заголовка TCP пакета
struct TCPHeader {
    USHORT  srcPort;        // Порт отправителя
    USHORT  destPort;       // Порт получателя
    ULONG   sequenceNum;    // Последовательность
    ULONG   ackNum;         // Подтверждение
    BYTE    reserved : 4;   // Зарезервировано
    BYTE    offset : 4;     // Смещение заголовка
    BYTE    flags;          // Флаги
    USHORT  window;         // Размер окна
    USHORT  checksum;       // Контрольная сумма
    USHORT  urgentPtr;      // Указатель срочности
};

// Структура заголовка UDP пакета
struct UDPHeader {
    USHORT  srcPort;        // Порт отправителя
    USHORT  destPort;       // Порт получателя
    USHORT  length;         // Длина пакета
    USHORT  checksum;       // Контрольная сумма
};

// Функция для записи заголовков в файл
void WriteHeaderToFile(const std::string& filename, const std::string& header) {
    std::ofstream file(filename, std::ios::app);
    if (file.is_open()) {
        file << header << std::endl;
        file.close();
    }
    else {
        std::cout << "Не удалось открыть файл для записи!" << std::endl;
    }
}

int main(int argc, char* argv[]) {

    setlocale(LC_ALL, "ru");
    // Проверяем наличие аргументов командной строки
    if (argc < 3) {
        std::cout << "Использование: sniffer.exe <IP> <filename>" << std::endl;
        return 1;
    }

    std::string ip = argv[1];
    std::string filename = argv[2];

    // Инициализация Winsock
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        std::cout << "Ошибка инициализации Winsock!" << std::endl;
        return 1;
    }

    // Создание сокета
    SOCKET snifferSocket = socket(AF_INET, SOCK_RAW, IPPROTO_IP);
    if (snifferSocket == INVALID_SOCKET) {
        std::cout << "Ошибка создания сокета!" << std::endl;
        return 1;
    }

    // Устанавливаем фильтр для прослушивания только указанного IP
    sockaddr_in addr;
    addr.sin_family = AF_INET;
    inet_pton(AF_INET, ip.c_str(), &(addr.sin_addr));

    if (bind(snifferSocket, (struct sockaddr*)&addr, sizeof(addr)) == SOCKET_ERROR) {
        std::cout << "Ошибка установки фильтра на сокет!" << std::endl;
        closesocket(snifferSocket);
        WSACleanup();
        return 1;
    }

    // Буфер для принимаемых пакетов
    char buffer[65536];

    while (true) {
        // Принимаем пакеты
        int packetSize = recv(snifferSocket, buffer, sizeof(buffer), 0);
        if (packetSize > 0) {
            // Распарсим IP заголовок
            IPHeader* ipHeader = reinterpret_cast<IPHeader*>(buffer);
            char srcIPStr[INET_ADDRSTRLEN];
            char destIPStr[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &(ipHeader->srcIP), srcIPStr, INET_ADDRSTRLEN);
            inet_ntop(AF_INET, &(ipHeader->destIP), destIPStr, INET_ADDRSTRLEN);
            std::string header = "IP: " + std::string(srcIPStr);
            header += " -> " + std::string(destIPStr);
            if (ipHeader->proto == IPPROTO_TCP) {
                // Распарсим TCP заголовок
                TCPHeader* tcpHeader = reinterpret_cast<TCPHeader*>(buffer + sizeof(IPHeader));
                header += "  TCP: " + std::to_string(ntohs(tcpHeader->srcPort));
                header += " -> " + std::to_string(ntohs(tcpHeader->destPort));
            }
            else if (ipHeader->proto == IPPROTO_UDP) {
                // Распарсим UDP заголовок
                UDPHeader* udpHeader = reinterpret_cast<UDPHeader*>(buffer + sizeof(IPHeader));
                header += "  UDP: " + std::to_string(ntohs(udpHeader->srcPort));
                header += " -> " + std::to_string(ntohs(udpHeader->destPort));
            }

            // Записываем заголовок в файл
            WriteHeaderToFile(filename, header);
        }
    }

    // Закрываем сокет и освобождаем ресурсы Winsock
    closesocket(snifferSocket);
    WSACleanup();

    return 0;
}