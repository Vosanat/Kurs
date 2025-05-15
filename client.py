import socket
import hashlib
import random
import uuid
import argparse

def generate_client_id():
    # Генерация случайного clientID длиной от 1 до 24 символов
    return str(uuid.uuid4())[:24]

def generate_message_id():
    # Генерация случайного messageID от 1 до 32
    return random.randint(1, 32)

def print_help():
    """
    Выводит справку по доступным командам.
    """
    help_text = """
    Доступные команды:
    - DELETE <имя_файла>: Удалить указанный файл для обычного пользователя.
             admin/<имя_файла> для админа
    - EXIT: Завершить сессию и отключиться от сервера.
    - HELP: Показать эту справку.
    """
    print(help_text)

def connect_to_server(host, port=12345):
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        client_socket.connect((host, port))
    except Exception as e:
        print(f"Ошибка подключения к серверу {host}:{port}: {str(e)}")
        return

    try:
        # Генерация clientID, messageID и clientType
        client_id = generate_client_id()
        message_id = generate_message_id()
        client_type = 1  # Предположим, что клиент использует версию 1

        # Вводим логин
        username = input("Введите логин: ")
        
        # Формируем заголовок и логин в одном пакете
        header = f"connection: clientID: {client_id}, messageID: {message_id}, clientType: {client_type}\n"
        data = header + username
        client_socket.send(data.encode('utf-8'))

        # Получаем соль от сервера
        salt = client_socket.recv(1024).decode('utf-8')
        print(f"Получена соль от сервера: {salt}")

        # Подтверждаем получение соли
        client_socket.send("SALT_RECEIVED".encode('utf-8'))

        # Вводим пароль
        password = input("Введите пароль: ")

        # Хэшируем пароль с солью
        hashed_password = hashlib.sha256((password + salt).encode('utf-8')).hexdigest()

        # Отправляем хэшированный пароль на сервер
        client_socket.send(hashed_password.encode('utf-8'))

        # Получаем ответ от сервера
        auth_response = client_socket.recv(1024).decode('utf-8')
        print(f"Ответ сервера: {auth_response}")

        if auth_response != "AUTH_SUCCESS":
            print("Ошибка аутентификации")
            return

        print("Аутентификация прошла успешно.")

        while True:
            command = input("Введите команду (или HELP для справки): ").strip()
            if command.upper() == "EXIT":
                client_socket.send("EXIT".encode('utf-8'))
                print("Завершение сессии...")
                break
            elif command.upper() == "HELP":
                print_help()
            elif command.startswith("DELETE"):
                # Отправляем команду DELETE с указанием имени файла
                header = f"connection: clientID: {client_id}, messageID: {message_id}, clientType: {client_type}\n"
                data = header + command
                client_socket.send(data.encode('utf-8'))
                response = client_socket.recv(1024).decode('utf-8')
                print(response)
            else:
                header = f"connection: clientID: {client_id}, messageID: {message_id}, clientType: {client_type}\n"
                data = header + command
                client_socket.send(data.encode('utf-8'))
                response = client_socket.recv(1024).decode('utf-8')
                print(response)

    except KeyboardInterrupt:
        print("\nЗавершение работы клиента...")
    except Exception as e:
        print(f"Ошибка при работе с сервером: {str(e)}")
    finally:
        client_socket.close()

if __name__ == "__main__":
    # Настройка парсера аргументов командной строки
    parser = argparse.ArgumentParser(description='Клиент для подключения к серверу')
    parser.add_argument('--host', required=True, help='Адрес сервера для подключения')
    parser.add_argument('--port', type=int, default=12345, help='Порт сервера (по умолчанию: 12345)')
    
    args = parser.parse_args()
    
    connect_to_server(host=args.host, port=args.port)
