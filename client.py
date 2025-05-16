import socket
import hashlib
import random
import uuid
import argparse
import json

def generate_client_id():
    return str(uuid.uuid4())[:24]

def generate_message_id():
    return random.randint(1, 32)

def create_message_header(client_id, message_id, client_type):
    return {
        "clientID": client_id,
        "messageID": message_id,
        "clientType": client_type
    }

def send_message(sock, header, body=""):
    message = json.dumps(header) + "\n\n" + body
    sock.sendall(message.encode('utf-8'))

def receive_message(sock):
    data = sock.recv(4096).decode('utf-8')
    if not data:
        return None, None
    
    header_str, _, body = data.partition('\n\n')
    try:
        header = json.loads(header_str)
    except json.JSONDecodeError:
        return None, None
    
    return header, body.strip()

def print_help(is_admin=False):
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
    print(help_text)

def connect_to_server(host, port=12345):
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        client_socket.connect((host, port))
    except Exception as e:
        print(f"Ошибка подключения: {str(e)}")
        return

    try:
        client_id = generate_client_id()
        message_id = generate_message_id()
        client_type = 1

        header = create_message_header(client_id, message_id, client_type)
        username = input("Введите логин: ")
        send_message(client_socket, header, username)

        header, salt = receive_message(client_socket)
        if not header or not salt:
            print("Ошибка: некорректный ответ сервера")
            return

        print(f"Получена соль: {salt}")
        send_message(client_socket, header, "SALT_RECEIVED")

        password = input("Введите пароль: ")
        hashed_password = hashlib.sha256((password + salt).encode('utf-8')).hexdigest()
        send_message(client_socket, header, hashed_password)

        header, auth_response = receive_message(client_socket)
        if auth_response != "auth_success":
            print("Ошибка аутентификации")
            return

        print("Аутентификация успешна")
        is_admin = "admin" in username.lower()

        while True:
            command = input("Введите команду (help для справки): ").strip().lower()
            if not command:
                continue

            if command == "exit":
                send_message(client_socket, header, "exit")
                print("Завершение сессии...")
                break
            elif command == "help":
                print_help(is_admin)
            elif command.startswith("delete"):
                parts = command.split(maxsplit=1)
                if len(parts) < 2:
                    print("Ошибка: укажите имя файла")
                    continue
                
                filename_part = parts[1]
                if not (filename_part.startswith('"') and filename_part.endswith('"')):
                    print('Ошибка: имя файла должно быть в кавычках, например: delete "file1.txt"')
                    continue
                
                message_id = generate_message_id()
                header = create_message_header(client_id, message_id, client_type)
                send_message(client_socket, header, command)
                
                response_header, response = receive_message(client_socket)
                if response:
                    print(response)
            else:
                message_id = generate_message_id()
                header = create_message_header(client_id, message_id, client_type)
                send_message(client_socket, header, command)
                response_header, response = receive_message(client_socket)
                if response:
                    print(response)

    except KeyboardInterrupt:
        print("\nЗавершение работы...")
    except Exception as e:
        print(f"Ошибка: {str(e)}")
    finally:
        client_socket.close()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Клиент для подключения к серверу')
    parser.add_argument('--host', required=True, help='Адрес сервера')
    parser.add_argument('--port', type=int, default=12345, help='Порт сервера')
    args = parser.parse_args()
    connect_to_server(host=args.host, port=args.port)
