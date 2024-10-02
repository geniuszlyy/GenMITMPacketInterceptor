
# EN
**GenMITMPacketInterceptor** is a powerful PoC for performing a Man-in-the-Middle (MITM) attack to intercept and analyze HTTP and SSL/TLS traffic. It leverages `scapy` to capture network packets, searching for potential authentication data, such as usernames and passwords, within the intercepted traffic. This project is for educational and research purposes to understand the security vulnerabilities present in unencrypted communications and to raise awareness on the importance of secure data transmission.

## Features
- **Real-time Packet Interception:** Captures HTTP and SSL/TLS packets on the network to analyze their contents.
- **Keyword-Based Search:** Scans intercepted traffic for keywords related to authentication, like `username`, `password`, `login`, and more.
- **Modular Structure:** Easy-to-read, well-structured Python code for handling network packets and MITM attack management.
- **Automatic Cleanup:** Restores original system network settings after stopping the attack.

## Disclaimer

This tool is intended for educational purposes only. It should not be used for any illegal activities, and the author is not responsible for any misuse.

## Prerequisites

- Python 3.x
- Linux-based system with access to `iptables`
- `scapy` library
- `netfilterqueue` package
- `sslstrip` tool

## Installation

1. Clone the repository:
    ```bash
    git clone https://github.com/geniuszly/GenMITMPacketInterceptor
    cd GenMITMPacketInterceptor
    ```

2. Install necessary Python packages:
    ```bash
    pip install -r requirements.txt
    ```

3. Make sure you have `sslstrip` installed on your system:
    ```bash
    sudo apt-get install sslstrip
    ```

## Usage

1. Run the script as root to ensure `iptables` rules and packet interception work properly:
    ```bash
    sudo python3 main.py
    ```

2. Monitor the console for any intercepted packets containing potential authentication data.

3. To stop the attack, press `Ctrl + C`. The tool will clean up all `iptables` rules and restore system settings automatically.

## Example Output

When the script is running and intercepting packets, the console output will display information about intercepted HTTP requests and any potentially sensitive data found. for example:

```
[*] Запуск MITM атаки...
[*] Ожидание перехвата пакетов...
[+] HTTP-запрос обнаружен: www.example.com/login
[+] Найдены возможные аутентификационные данные: username=johndoe&password=12345678

[+] HTTP-запрос обнаружен: www.example.com/dashboard
[+] Найдены возможные аутентификационные данные: user=johndoe&pass=abcdefg12345

[!] Прерывание. Очищаем конфигурацию...
```

In this example, the tool successfully intercepted HTTP requests to `www.example.com` and found possible authentication data, such as `username` and `password`. When you press `Ctrl + C`, the attack is stopped, and all configurations are cleaned up automatically.


# RU
**GenMITMPacketInterceptor** — это мощный PoC для выполнения атаки "Человек посередине" (MITM), предназначенный для перехвата и анализа HTTP и SSL/TLS-трафика. Инструмент использует `scapy` для перехвата сетевых пакетов и поиска потенциальных аутентификационных данных, таких как логины и пароли, внутри перехваченного трафика. Этот проект создан в образовательных и исследовательских целях для понимания уязвимостей в незашифрованной передаче данных и повышения осведомленности о важности защищенной передачи данных.

## Возможности

- **Перехват пакетов в режиме реального времени:** Захватывает HTTP и SSL/TLS пакеты в сети для анализа их содержимого.
- **Поиск по ключевым словам:** Сканирует перехваченный трафик на наличие ключевых слов, связанных с аутентификацией, таких как `username`, `password`, `login` и другие.
- **Модульная структура:** Легкочитаемый и структурированный код на Python для обработки сетевых пакетов и управления атакой MITM.
- **Автоматическая очистка:** Восстанавливает исходные настройки сети после завершения атаки.

## Отказ от ответственности

Этот инструмент предназначен исключительно для образовательных целей. Он не должен использоваться для каких-либо незаконных действий, и автор не несет ответственности за любое его неправильное использование.

## Требования

- Python 3.x
- Linux-система с доступом к `iptables`
- Библиотека `scapy`
- Пакет `netfilterqueue`
- Инструмент `sslstrip`

## Установка

1. Клонируйте репозиторий:
    ```bash
    git clone https://github.com/geniuszly/GenMITMPacketInterceptor
    cd GenMITMPacketInterceptor
    ```

2. Установите необходимые Python-пакеты:
    ```bash
    pip install -r requirements.txt
    ```

3. Убедитесь, что у вас установлен `sslstrip`:
    ```bash
    sudo apt-get install sslstrip
    ```

## Использование

1. Запустите скрипт от имени суперпользователя для корректного перехвата пакетов:
    ```bash
    sudo python3 main.py
    ```

2. Отслеживайте консоль для просмотра перехваченных пакетов, содержащих потенциальные аутентификационные данные.

3. Чтобы остановить атаку, нажмите `Ctrl + C`. Инструмент автоматически очистит все правила `iptables` и восстановит системные настройки.

## Пример вывода 

Когда скрипт запущен и перехватывает пакеты, вывод в консоли отобразит информацию о перехваченных HTTP-запросах и любых обнаруженных аутентификационных данных. Например:

```
[*] Запуск MITM атаки...
[*] Ожидание перехвата пакетов...
[+] HTTP-запрос обнаружен: www.example.com/login
[+] Найдены возможные аутентификационные данные: username=johndoe&password=12345678

[+] HTTP-запрос обнаружен: www.example.com/dashboard
[+] Найдены возможные аутентификационные данные: user=johndoe&pass=abcdefg12345

[!] Прерывание. Очищаем конфигурацию...
```

В этом примере инструмент успешно перехватил HTTP-запросы к `www.example.com` и обнаружил возможные аутентификационные данные, такие как `username` и `password`. При нажатии `Ctrl + C` атака прекращается, и все конфигурации очищаются автоматически.
