import secrets


def is_prime(n, k=5):
    #Miller-Rabin primality test
    #k is the number of rounds (higher = more accurate)

    if n<2:
        return False
    if n == 2 or n == 3:
        return True
    if n%2 == 0:
        return False

    #write n-1 as 2^r * d to factor out powers of 2 from n-1
    r = 0
    d = n-1
    while d % 2 == 0:
        r += 1
        d //= 2

    #witness loop
    for _ in range(k):
        a = secrets.randbelow(n - 3) + 2
        x = pow(a, d, n)

        if x == 1 or x == n - 1:
            continue

        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def generate_prime(bits):
    #generate a random prime number with specified bit length
    while True:
        #generate random odd number
        p = secrets.randbits(bits)
        p |= (1 << (bits - 1)) | 1  #set most significant bit and least significant bit to 1

        if is_prime(p):
            return p


def hcf(a, b):
    #calculate highest common factor using Euclidean algorithm
    while b:
        temp = b
        b = a%b
        a = temp
    return a


def extended_hcf(a, b):
    #extended Euclidean Algorithm
    #returns (hcf, x, y) where hcf = ax + by

    if a == 0:
        return b, 0, 1

    hcf_val, x1, y1 = extended_hcf(b % a, a)
    x = y1 - (b // a) * x1
    y = x1

    return hcf_val, x, y


def mod_inverse(e, phi):
    #calculate modular multiplicative inverse of e mod phi
    hcf_val, x, _ = extended_hcf(e, phi)

    if hcf_val != 1:
        raise ValueError("modular inverse does not exist")

    return x%phi


def generate_keypair(bits):
    #generate RSA public and private key pair
    #returns: ((e, n), (d, n)) where (e,n) is public key and (d,n) is private key

    #generate two different primes
    p = generate_prime(bits)
    q = generate_prime(bits)

    while p == q:
        q = generate_prime(bits)

    #calculate n and phi(n)
    n = p*q
    phi = (p - 1)*(q - 1)

    #choose e (commonly 65537 for efficiency and security)
    e = 65537 #Fermat prime

    #make sure e and phi are coprime
    if hcf(e, phi) != 1:
        #if not, find a suitable e
        e = 3
        while hcf(e, phi) != 1:
            e += 2

    #calculate d (private exponent)
    d = mod_inverse(e, phi)

    print(f"Key size: {n.bit_length()} bits")
    return ((e, n), (d, n))


def encrypt(message, public_key):
    #encrypt a message using RSA public key
    #message: integer to encrypt (must be < n)
    e, n = public_key

    if message >= n:
        raise ValueError("Message too large for key size")

    #encryption: ciphertext = message^e mod n
    ciphertext = pow(message, e, n)
    return ciphertext


def decrypt(ciphertext, private_key):
    #decrypt a ciphertext using RSA private key
    #ciphertext: integer to decrypt
    d, n = private_key

    #decryption: message = ciphertext^d mod n
    message = pow(ciphertext, d, n)
    return message


def text_to_int(text):
    #convert text string to integer
    return int.from_bytes(text.encode("utf-8"), byteorder="big")


def int_to_text(number):
    #convert integer back to text string
    #calculate number of bytes needed
    num_bytes = (number.bit_length() + 7) // 8
    return number.to_bytes(num_bytes, byteorder="big").decode("utf-8")


def rsa(message, bits):
    #generate keys (using smaller bits for faster demo)
    public_key, private_key = generate_keypair(bits)
    e, n = public_key
    d, _ = private_key

    print(f"Public Key ({e}, {n}):")
    print(f"Private Key ({d}, {n}):")


    #example with text (short message)
    print(f"Plaintext: {message}")

    #convert to number
    message_int = text_to_int(message)
    print(f"Integer value of text: {message_int}")

    #check if message fits in key size
    if message_int < n:
        encrypted = encrypt(message_int, public_key)
        print(f"Encrypted: {encrypted}")

        decrypted_int = decrypt(encrypted, private_key)
        decrypted_text = int_to_text(decrypted_int)
        print(f"Decrypted: {decrypted_text}")
        if message == decrypted_text:
            print("Success!")
        else:
            print("Failure")
    else:
        print("Message too large! Would need to split into blocks.")

"""
Key Insights:
=================================================================
1. RSA security relies on the difficulty of factoring n into p*q"
2. Public key (e,n) can be shared freely"
3. Private key (d,n) must be kept secret"
4. Real implementations use padding schemes (OAEP) for security"
5. For large messages, hybrid encryption is used (RSA + AES)"
"""

if __name__ == "__main__":
    message = input("Please enter a message to encrypt: ")
    bits = int(input("Enter key size in bits (e.g., 512, 1024): "))
    rsa(message, bits//2)
