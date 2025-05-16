import socket
import os
import threading
import hashlib
import json
import re

MAX_CLIENTS = 3
active_clients = 0
clients = {}
lock = threading.Lock()

# База данных пользователей
users_db = {
    "admin": {
        "salt": "randomsalt1",
        "hashed_password": hashlib.sha256(("admin123" + "randomsalt1").encode('utf-8')).hexdigest(),
        "is_admin": True
    },
    "user": {
        "salt": "randomsalt2",
        "hashed_password": hashlib.sha256(("user123" + "randomsalt2").encode('utf-8')).hexdigest(),
        "is_admin": False
    }
}

def create_user_directory(username):
    """Создает каталог пользователя и тестовые файлы"""
    user_dir = f"./{username}"
    if not os.path.exists(user_dir):
        os.makedirs(user_dir)
        for i in range(1, 4):
            with open(f"{user_dir}/file{i}.txt", "w") as f:
                f.write(f"Это файл {i} пользователя {username}.")

def send_message(sock, header, body=""):
    """Отправка сообщения с заголовком и телом"""
    message = json.dumps(header) + "\n\n" + body
    sock.sendall(message.encode('utf-8'))

def receive_message(sock):
    """Получение и парсинг сообщения"""
    data = sock.recv(4096).decode('utf-8')
    if not data:
        return None, None
    
    header_str, _, body = data.partition('\n\n')
    try:
        header = json.loads(header_str)
    except json.JSONDecodeError:
        return None, None
    
    return header, body.strip()

def parse_delete_command(command, current_user, is_admin):
    """
    Парсит команду delete и возвращает корректный путь к файлу
    """
    path_part = command[6:].strip()
    quoted_pattern = r'^"([^"/]+)"\s*/\s*"([^"]+)"$|^"([^"]+)"$'
    match = re.fullmatch(quoted_pattern, path_part)
    
    if not match:
        return None, "Неверный формат команды. Используйте: delete \"имя_файла\" или delete \"пользователь\"/\"имя_файла\""
    
    if match.group(1) and match.group(2):
        if not is_admin:
            return None, "Ошибка: только администратор может удалять файлы других пользователей"
        username = match.group(1)
        filename = match.group(2)
        filepath = f"./{username}/{filename}"
    else:
        filename = match.group(3)
        filepath = f"./{current_user}/{filename}"
    
    return filepath, None

def handle_client(client_socket, client_address):
    global active_clients
    username = "unknown"
    try:
        print(f"\nНовое подключение: {client_address}")
        print(f"Активных подключений: {active_clients}/{MAX_CLIENTS}")

        # Аутентификация
        header, username = receive_message(client_socket)
        if not header or not username:
            send_message(client_socket, {}, "Ошибка: некорректный запрос")
            return

        if username not in users_db:
            send_message(client_socket, header, "Ошибка: пользователь не найден")
            return

        # Отправляем соль
        salt = users_db[username]["salt"]
        send_message(client_socket, header, salt)

        # Подтверждение получения соли
        header, confirmation = receive_message(client_socket)
        if confirmation != "SALT_RECEIVED":
            return

        # Проверка пароля
        header, received_hash = receive_message(client_socket)
        expected_hash = users_db[username]["hashed_password"]
        is_admin = users_db[username]["is_admin"]

        if received_hash == expected_hash:
            send_message(client_socket, header, "auth_success")
            print(f"Пользователь {username} успешно аутентифицирован")
        else:
            send_message(client_socket, header, "auth_failed")
            return

        with lock:
            clients[client_socket] = (username, is_admin, header["clientID"])

        create_user_directory(username)

        # Основной цикл обработки команд
        while True:
            header, command = receive_message(client_socket)
            if not command:
                break

            command = command.lower()

            if command == "exit":
                break
            elif command == "help":
                help_text = """
                Доступные команды:
                - delete "имя_файла" - удалить файл
                    файлы пользователя:
                        file1.txt
                        file2.txt
                        file3.txt
                - exit - завершить сеанс
                - help - показать справку
                """
                if is_admin:
                    help_text += "\nАдминистратор может использовать: delete \"пользователь\"/\"имя_файла\""
                send_message(client_socket, header, help_text)
            elif command.startswith("delete"):
                filepath, error = parse_delete_command(command, username, is_admin)
                if error:
                    send_message(client_socket, header, error)
                    continue

                if not is_admin and not filepath.startswith(f"./{username}/"):
                    send_message(client_socket, header, "Ошибка: недостаточно прав для удаления файла")
                    continue

                try:
                    if not os.path.exists(filepath):
                        send_message(client_socket, header, f"Ошибка: файл {filepath} не существует")
                    else:
                        os.remove(filepath)
                        send_message(client_socket, header, f"Файл {filepath} успешно удален")
                        print(f"Пользователь {username} удалил файл: {filepath}")
                except Exception as e:
                    send_message(client_socket, header, f"Ошибка при удалении: {str(e)}")
            else:
                send_message(client_socket, header, "Неизвестная команда. Введите help для справки")

    except Exception as e:
        print(f"Ошибка с клиентом {username}: {str(e)}")
    finally:
        with lock:
            if client_socket in clients:
                del clients[client_socket]
            active_clients -= 1
            print(f"Клиент {username} отключен")
            print(f"Активных подключений: {active_clients}/{MAX_CLIENTS}")
        client_socket.close()

def start_server():
    global active_clients
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind(('0.0.0.0', 12345))
    server_socket.listen(5)
    print(f"Сервер запущен и ожидает подключений (макс. {MAX_CLIENTS} клиентов)...")

    for user in users_db:
        create_user_directory(user)

    try:
        while True:
            client_socket, client_address = server_socket.accept()
            
            with lock:
                if active_clients >= MAX_CLIENTS:
                    send_message(client_socket, {}, "Ошибка: сервер перегружен. Попробуйте позже.")
                    client_socket.close()
                    print(f"Отклонено подключение от {client_address} - достигнут лимит клиентов")
                    continue
                
                active_clients += 1
                thread = threading.Thread(target=handle_client, args=(client_socket, client_address))
                thread.start()

    except KeyboardInterrupt:
        print("\nЗавершение работы сервера...")
    finally:
        server_socket.close()
        print("Сервер остановлен")

if __name__ == "__main__":
    start_server()
