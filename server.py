import socket
import os
import threading
import hashlib
import re

MAX_CLIENTS = 3
clients = {}
lock = threading.Lock()

# БД
users_db = {
    "admin": {
        "salt": "randomsalt1",  # Соль для пользователя admin
        "hashed_password": hashlib.sha256(("admin123" + "randomsalt1").encode('utf-8')).hexdigest(),
        "is_admin": True
    },
    "user": {
        "salt": "randomsalt2",  # Соль для пользователя user
        "hashed_password": hashlib.sha256(("user123" + "randomsalt2").encode('utf-8')).hexdigest(),
        "is_admin": False
    }
}

def create_user_directory(username):
    """
    Создает каталог для пользователя и три текстовых файла, если их нет.
    """
    user_dir = f"./{username}"
    if not os.path.exists(user_dir):
        os.makedirs(user_dir)
        for i in range(1, 4):
            with open(f"{user_dir}/file{i}.txt", "w") as f:
                f.write(f"Это файл {i} пользователя {username}.")

def parse_header(header):
    """
    Парсит заголовок запроса и извлекает clientID, messageID и clientType.
    """
    client_id_match = re.search(r'clientID: (\w+)', header)
    message_id_match = re.search(r'messageID: (\d+)', header)
    client_type_match = re.search(r'clientType: (\d+)', header)

    client_id = client_id_match.group(1) if client_id_match else None
    message_id = int(message_id_match.group(1)) if message_id_match else None
    client_type = int(client_type_match.group(1)) if client_type_match else None

    return client_id, message_id, client_type

def handle_client(client_socket, client_address):
    try:
        # Выводим информацию о подключении клиента
        print(f"Подключен клиент с IP: {client_address[0]}")

        # Получаем данные от клиента (заголовок и логин)
        data = client_socket.recv(1024).decode('utf-8').strip()
        
        # Разделяем заголовок и логин
        if '\n' in data:
            header, username = data.split('\n', 1)
        else:
            client_socket.send("Ошибка: некорректный формат данных.".encode())
            client_socket.close()
            return

        # Парсим заголовок
        client_id, message_id, client_type = parse_header(header)

        if not client_id or not message_id or not client_type:
            client_socket.send("Ошибка: некорректный заголовок запроса.".encode())
            client_socket.close()
            return

        # Проверяем, есть ли такой пользователь в базе данных
        if username not in users_db:
            client_socket.send("Ошибка: пользователь не найден.".encode())
            client_socket.close()
            print(f"Клиент с IP {client_address[0]} отключен (пользователь не найден).")
            return

        # Отправляем соль клиенту
        salt = users_db[username]["salt"]
        client_socket.send(salt.encode('utf-8'))
        print(f"Соль отправлена клиенту с IP:{client_address[0]}")

        # Ожидаем подтверждения от клиента, что соль получена
        confirmation = client_socket.recv(1024).decode('utf-8').strip()
        if confirmation != "SALT_RECEIVED":
            print(f"Клиент с IP {client_address[0]} не подтвердил получение соли.")
            client_socket.close()
            return

        # Получаем хэшированный пароль от клиента
        received_hashed_password = client_socket.recv(1024).decode('utf-8').strip()

        # Получаем хэшированный пароль из базы данных
        expected_hashed_password = users_db[username]["hashed_password"]

        # Сравниваем полученный хэш с хэшем из базы данных
        if received_hashed_password == expected_hashed_password:
            client_socket.send("AUTH_SUCCESS".encode())
            is_admin = users_db[username]["is_admin"]
            print(f"Клиент {username} успешно аутентифицирован. IP: {client_address[0]}")
        else:
            client_socket.send("Ошибка аутентификации.".encode())
            client_socket.close()
            print(f"Клиент с IP {client_address[0]} отключен (ошибка аутентификации).")
            return

        with lock:
            clients[client_socket] = (username, is_admin, client_id, message_id, client_type)

        # Создаем каталог и файлы для пользователя, если их нет
        create_user_directory(username)

        while True:
            data = client_socket.recv(1024).decode().strip()
            if not data:
                break

            # Разделяем заголовок и команду
            if '\n' in data:
                header, command = data.split('\n', 1)
            else:
                command = data

            if command == "EXIT":
                break
            elif command.startswith("DELETE"):
                _, filename = command.split(" ", 1)
                # Формируем полный путь к файлу
                if is_admin:
                    # Администратор может указывать полный путь
                    filepath = filename
                else:
                    # Обычный пользователь может удалять файлы только в своем каталоге
                    filepath = f"./{username}/{filename}"

                # Проверяем права пользователя
                if is_admin or filepath.startswith(f"./{username}/"):
                    try:
                        os.remove(filepath)
                        client_socket.send(f"Файл {filepath} успешно удален.".encode())
                        print(f"Клиент {username} удалил файл {filepath}")
                    except Exception as e:
                        client_socket.send(f"Ошибка при удалении файла: {str(e)}".encode())
                else:
                    client_socket.send("Ошибка: недостаточно прав для удаления файла.".encode())
            else:
                client_socket.send("Неизвестная команда.".encode())

    except Exception as e:
        print(f"Ошибка при работе с клиентом {client_address}: {str(e)}")
    finally:
        with lock:
            if client_socket in clients:
                del clients[client_socket]
        client_socket.close()
        print(f"Клиент {username} отключен. IP: {client_address[0]}")
        print(26*'#')

def start_server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    # Добавляем настройку для повторного использования адреса
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    server_socket.bind(('0.0.0.0', 12345))
    server_socket.listen(5)
    print("Сервер запущен и ожидает подключений...")

    # Создаем каталоги и файлы для всех пользователей при старте сервера
    for username in users_db:
        create_user_directory(username)

    try:
        while True:
            client_socket, client_address = server_socket.accept()
            if len(clients) >= MAX_CLIENTS:
                client_socket.send("Ошибка: превышено максимальное количество подключений.".encode())
                client_socket.close()
                continue

            client_thread = threading.Thread(target=handle_client, args=(client_socket, client_address))
            client_thread.start()

    except KeyboardInterrupt:
        print("Сервер завершает работу...")
    finally:
        server_socket.close()
        print("Сервер остановлен.")

if __name__ == "__main__":
    start_server()
