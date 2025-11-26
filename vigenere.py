"""
vigenere.py
Implementación del criptosistema de Vigenère para SPSI 2025/2026.

Incluye:
- Normalización de texto (quitar caracteres no alfabéticos, pasar a mayúsculas).
- Conversión carácter <-> número (A=0,...,Z=25).
- Cifrado Vigenère.
- Descifrado Vigenère.
- Pequeñas pruebas de ejemplo en el bloque main.

Autor: (rellenar con tu nombre)
Asignatura: Seguridad y Protección de Sistemas Informáticos (SPSI)
Curso: 2025/2026
"""

import string

# Alfabeto que usaremos: letras mayúsculas A-Z
ALPHABET = string.ascii_uppercase
ALPHABET_SIZE = len(ALPHABET)


# ---------------------------------------------------------------------------
# Funciones auxiliares
# ---------------------------------------------------------------------------

def normalize_text(text: str) -> str:
    """
    Normaliza un texto:
    - Convierte a mayúsculas.
    - Elimina todos los caracteres que no sean letras A-Z (tildes, espacios, números...).

    Esto es lo habitual en cifrado clásico: trabajamos sólo con letras en mayúsculas.
    """
    text = text.upper()
    normalized = []

    for ch in text:
        if ch in ALPHABET:
            normalized.append(ch)
        # Si quisieras admitir Ñ o letras con tilde, aquí habría que mapearlas.

    return "".join(normalized)


def char_to_int(ch: str) -> int:
    """
    Convierte un carácter 'A'-'Z' a entero 0-25.
    No valida explícitamente: se asume que ch está en ALPHABET.
    """
    return ord(ch) - ord('A')


def int_to_char(n: int) -> str:
    """
    Convierte un entero 0-25 a carácter 'A'-'Z'.
    Se aplica módulo 26 para no salirnos del rango.
    """
    n = n % ALPHABET_SIZE
    return chr(n + ord('A'))


def normalize_key(key: str) -> str:
    """
    Normaliza la clave:
    - Igual que el texto: sólo letras A-Z, en mayúscula.
    - Además, comprobamos que la clave no queda vacía.

    Si la clave queda vacía -> se lanza ValueError.
    """
    k = normalize_text(key)

    if not k:
        raise ValueError("La clave debe contener al menos una letra A-Z.")

    return k


# ---------------------------------------------------------------------------
# Cifrado y descifrado Vigenère
# ---------------------------------------------------------------------------

def vigenere_encrypt(plaintext: str, key: str) -> str:
    """
    Cifra un mensaje usando el criptosistema de Vigenère.

    Parámetros:
    - plaintext: texto en claro (se normalizará: mayúsculas y sólo letras A-Z).
    - key: clave (se normalizará de igual forma).

    Devuelve:
    - ciphertext: texto cifrado en mayúsculas A-Z.

    Fórmula (en aritmética módulo 26):
        C_i = (P_i + K_i) mod 26
    donde:
        P_i: i-ésima letra del texto en claro (0-25)
        K_i: i-ésima letra de la clave repetida (0-25)
        C_i: i-ésima letra del criptograma (0-25)
    """
    # Normalizar entrada
    P = normalize_text(plaintext)
    K = normalize_key(key)

    ciphertext_chars = []
    key_len = len(K)

    for i, ch in enumerate(P):
        p_val = char_to_int(ch)
        k_val = char_to_int(K[i % key_len])  # repetimos la clave cíclicamente
        c_val = (p_val + k_val) % ALPHABET_SIZE
        c_ch = int_to_char(c_val)
        ciphertext_chars.append(c_ch)

    return "".join(ciphertext_chars)


def vigenere_decrypt(ciphertext: str, key: str) -> str:
    """
    Descifra un mensaje cifrado con el criptosistema de Vigenère.

    Parámetros:
    - ciphertext: texto cifrado (se normalizará: mayúsculas y sólo letras A-Z).
    - key: clave (se normalizará de igual forma).

    Devuelve:
    - plaintext: texto en claro (mayúsculas A-Z, sin espacios ni signos).

    Fórmula (en aritmética módulo 26):
        P_i = (C_i - K_i) mod 26
    donde:
        C_i: i-ésima letra del criptograma (0-25)
        K_i: i-ésima letra de la clave repetida (0-25)
        P_i: i-ésima letra del texto en claro (0-25)
    """
    C = normalize_text(ciphertext)
    K = normalize_key(key)

    plaintext_chars = []
    key_len = len(K)

    for i, ch in enumerate(C):
        c_val = char_to_int(ch)
        k_val = char_to_int(K[i % key_len])
        p_val = (c_val - k_val) % ALPHABET_SIZE
        p_ch = int_to_char(p_val)
        plaintext_chars.append(p_ch)

    return "".join(plaintext_chars)


# ---------------------------------------------------------------------------
# Pequeñas pruebas (se ejecutan solo si el fichero se ejecuta como script)
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    # Ejemplo sencillo para comprobar que cifrar y luego descifrar devuelve lo original
    mensaje = "ESTE ES UN MENSAJE DE PRUEBA PARA VIGENERE 123!!!"
    clave = "CRYPTO"

    print("Mensaje original   :", mensaje)
    print("Clave              :", clave)

    cifrado = vigenere_encrypt(mensaje, clave)
    print("Cifrado (normaliz.):", cifrado)

    descifrado = vigenere_decrypt(cifrado, clave)
    print("Descifrado         :", descifrado)
