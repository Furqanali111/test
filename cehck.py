import sys

def vulnerability1(input_str):
    buffer = bytearray(10)
    buffer[:len(input_str)] = input_str.encode()
    print("Buffer contents:", buffer.decode())

def vulnerability2(input_str):
    buffer = bytearray(len(input_str))
    buffer[:len(input_str)] = input_str.encode()
    print("Buffer contents:", buffer.decode())

def vulnerability3():
    buffer = bytearray(10)
    print("Enter a password:")
    password = input().encode()
    buffer[:len(password)] = password
    if buffer.decode() == "password123":
        print("Access granted!")
    else:
        print("Access denied.")

def vulnerability4():
    buffer = bytearray(10)
    print("Enter your name:")
    name = input().encode()
    buffer[:len(name)] = name
    print("Hello,", buffer.decode(), "!")

def vulnerability5(input_str):
    buffer = bytearray(10)
    buffer[:len(input_str)] = input_str.encode()
    print("Buffer contents:", buffer.decode())

def main():
    args = sys.argv[1:]
    vulnerability1(args[0]) # buffer overflow
    vulnerability2(args[0]) # heap overflow
    vulnerability3()        # format string vulnerability
    vulnerability4()        # buffer overflow
    vulnerability5(args[0]) # potential buffer overflow

if __name__ == "__main__":
    main()
