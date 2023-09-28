import os


def generate_key():
    return os.urandom(24).hex()


if __name__ == "__main__":
    print(generate_key())
