import sys
from PyQt5.QtWidgets import QApplication, QMainWindow, QPushButton, QLabel, QLineEdit, QVBoxLayout, QWidget, QTextEdit

# Генерация констант
def generate_const(size_subblock):
    match size_subblock:
        case 16:
            return (0xB7E1, 0x9E37)
        case 32:
            return (0xB7E15163, 0x9E3779B9)
        case 64:
            return (0xB7E151628AED2A6B, 0x9E3779B97F4A7C15)

# Циклический сдвиг влево
def cyclic_shift_left(x, d, size_subblock):
    return (x << d) | (x >> (size_subblock - d))
# Циклический сдвиг вправо
def cyclic_shift_right(x, d, size_subblock):
    return (x >> d) | (x << (size_subblock - d))

# Построение таблицы расширенных ключей
def generate_key(key, rounds, size_subblock):
    P, Q = generate_const(size_subblock)
    m = 2 ** size_subblock
    S = []
    for i in range(2 * (rounds + 1)):
        S.append((P + i * Q) % m)
    #  Разбиение ключа
    u = size_subblock // 8
    if len(key) % u:
        key += b' ' * (u - len(key) % u)
    c = len(key) // u
    L = []
    for i in range(0, len(key), u):
        L.append(int.from_bytes(key[i:i + u], byteorder='little'))
    # Перемешивание ключа
    i, j, G, H = 0, 0, 0, 0
    for _ in range(max(3*c, 6*(rounds+1))):
        G = S[i] = (S[i] + G + H) % m
        G = cyclic_shift_left(G, 3, size_subblock)
        H = L[j] = (L[j] + G + H) % m
        H = cyclic_shift_left(H, G % size_subblock, size_subblock)
        i = (i + 1) % (2*(rounds+1))
        j = (j + 1) % c
    return S

# Шифрование блока
def encrypt_block(text, rounds, size_subblock, c_sym, S):
    # Левый подблок
    A = int.from_bytes(text[:c_sym], 'little')
    # Правый подблок
    B = int.from_bytes(text[c_sym:], 'little')
    m = 2 ** size_subblock
    A = (A + S[0]) % m
    B = (B + S[1]) % m
    for i in range(1, rounds + 1):
        A = A ^ B # Поразрядное суммирование по модулю 2
        A = cyclic_shift_left(A, B % size_subblock, size_subblock)
        A = (A + S[2 * i]) % m
        B = B ^ A # Поразрядное суммирование по модулю 2
        B = cyclic_shift_left(B, A % size_subblock, size_subblock)
        B = (B + S[2 * i + 1]) % m

    return A.to_bytes(c_sym, 'little') + B.to_bytes(c_sym, 'little')

# Дешифрование блока
def decrypt_block(text, rounds, size_subblock, c_sym, S):
    # Левый подблок
    A = int.from_bytes(text[:c_sym], 'little')
    # Правый подблок
    B = int.from_bytes(text[c_sym:], 'little')
    m = 2 ** size_subblock
    for i in range(rounds, 0, -1):
        B = (B - S[2 * i + 1]) % m
        B = cyclic_shift_right(B, A % size_subblock, size_subblock)
        B = B ^ A # поразрядное суммирование по модулю 2
        A = (A - S[2 * i]) % m
        A = cyclic_shift_right(A, B % size_subblock, size_subblock)
        A = A ^ B # поразрядное суммирование по модулю 2
    B = (B - S[1]) % m
    A = (A - S[0]) % m
    return A.to_bytes(c_sym, 'little') + B.to_bytes(c_sym, 'little')

# Количество символов в блоке
def count_symbol(size_block):
    match size_block:
        case 32:
            return 4
        case 64:
            return 8
        case 128:
            return 16

# Шифрование текста
def encrypt(text, key, rounds, size_block):
    text = text.encode('utf-8')
    key = key.encode('utf-8')
    if len(text) % 8 != 0:
        text += b' ' * (8 - len(text) % 8)
    count = count_symbol(size_block)
    new_text = ""
    size_subblock = size_block // 2
    S = generate_key(key, rounds, size_subblock)
    for i in range(0, len(text), count):
        new_text += encrypt_block(text[i:i+count], rounds, size_subblock, count//2, S).hex()
    return new_text

# Дешифрование текста
def decrypt(text, key, rounds, size_block):
    key = key.encode('utf-8')
    count = count_symbol(size_block)
    new_text = ""
    size_subblock = size_block // 2
    S = generate_key(key, rounds, size_subblock)
    try:
        text = bytes.fromhex(text)
        for i in range(0, len(text), count):
            new_text += decrypt_block(text[i:i + count], rounds, size_subblock, count//2, S).decode('utf-8')
        return new_text
    except Exception:
        return "Ошибка расшифровки"

class App(QMainWindow):
    def __init__(self):
        super().__init__()

        self.setWindowTitle("Шифр RC5")
        self.setGeometry(100, 100, 400, 400)

        self.initUI()

    def initUI(self):
        layout = QVBoxLayout()

        self.text_input = QTextEdit(self)
        self.text_input.setPlaceholderText("Введите текст")

        self.key_input = QLineEdit(self)
        self.key_input.setPlaceholderText("Введите секретный ключ")

        self.count_rounds_input = QLineEdit(self)
        self.count_rounds_input.setPlaceholderText("Введите количество раундов")

        self.size_block_input = QLineEdit(self)
        self.size_block_input.setPlaceholderText("Введите длину текстового блока (32, 64 или 128)")

        self.text_output = QTextEdit(self)
        self.text_output.setPlaceholderText("Результат")
        self.text_output.setReadOnly(True)

        encrypt_button = QPushButton("Зашифровать", self)
        encrypt_button.clicked.connect(self.encrypt)

        decrypt_button = QPushButton("Расшифровать", self)
        decrypt_button.clicked.connect(self.decrypt)

        layout.addWidget(QLabel("Текст:"))
        layout.addWidget(self.text_input)
        layout.addWidget(QLabel("Секретный ключ:"))
        layout.addWidget(self.key_input)
        layout.addWidget(QLabel("Количество раундов:"))
        layout.addWidget(self.count_rounds_input)
        layout.addWidget(QLabel("Длина блока:"))
        layout.addWidget(self.size_block_input)
        layout.addWidget(QLabel("Результат:"))
        layout.addWidget(self.text_output)
        layout.addWidget(encrypt_button)
        layout.addWidget(decrypt_button)

        container = QWidget()
        container.setLayout(layout)
        self.setCentralWidget(container)

    def encrypt(self):
        text = self.text_input.toPlainText()
        key = self.key_input.text()
        count_rounds = self.count_rounds_input.text()
        size_block = self.size_block_input.text()
        if count_rounds and size_block and text and key:
            count_rounds = int(count_rounds)
            size_block = int(size_block)
            if count_rounds>=0 and count_rounds<=255:
                if size_block==32 or size_block==64 or size_block==128:
                    if len(key) > 0 and len(key) <= 255:
                        encrypted = encrypt(text, key, count_rounds, size_block)
                        self.text_output.setPlainText(encrypted)
                    else:
                        self.text_output.setPlainText("Длина ключа может быть максимально 255 символов")
                else:
                    self.text_output.setPlainText("Длина текстового блока должна быть 32, 64 или 128 бит")
            else:
                self.text_output.setPlainText("Введенное количество раундов не входит в диапазон от 0 до 255")
        else:
            self.text_output.setPlainText("Введите информацию в поля ввода")

    def decrypt(self):
        text = self.text_input.toPlainText()
        key = self.key_input.text()
        count_rounds = self.count_rounds_input.text()
        size_block = self.size_block_input.text()
        if count_rounds and size_block and text and key:
            count_rounds = int(count_rounds)
            size_block = int(size_block)
            if count_rounds >= 0 and count_rounds <= 255:
                if size_block == 32 or size_block == 64 or size_block == 128:
                    if len(key) > 0 and len(key) <= 255:
                        decrypted = decrypt(text, key, count_rounds, size_block)
                        self.text_output.setPlainText(decrypted)
                    else:
                        self.text_output.setPlainText("Длина ключа может быть максимально 255 символов")
                else:
                    self.text_output.setPlainText("Длина текстового блока должна быть 32, 64 или 128 бит")
            else:
                self.text_output.setPlainText("Введенное количество раундов не входит в диапазон от 0 до 255")
        else:
            self.text_output.setPlainText("Введите информацию в поля ввода")

if __name__ == "__main__":
    app = QApplication(sys.argv)
    mainWin = App()
    mainWin.show()
    sys.exit(app.exec_())