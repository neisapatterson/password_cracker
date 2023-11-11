import argparse
from passlib.hash import sha512_crypt, md5_crypt

LOWERCASE = "abcdefghijklmnopqrstuvwxyz"
UPPERCASE = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
INT = "0123456789"
ASCII = "".join(chr(i) for i in range(33, 126 + 1))

def main(file, min_val, max_val, charset):
    # hashed passwords will be stored as the key with format, salt, and the remaining string as the input
    passwords = {}

    with open(file, 'r') as password_list:
        for line in password_list:
            line = line.strip()
            passwords[line] = [line.split('$')[1], line.split('$')[2], line.split('$')[3]]

    for password in passwords:
        crack(password, passwords[password][0], passwords[password][1], passwords[password][2], min_val, max_val, charset, passwords_length)

def crack(password, format, salt, orginal_string, min_val, max_val, charset, passwords_length):
    cracked_passwords = []

    match charset:
        case "lowercase":
            charset=LOWERCASE
        case "uppercase":
            charset=UPPERCASE
        case "int":
            charset=INT
        case "ascii":
            charset=ASCII
        case _:
            charset=charset

    for guess in generate_combinations("", charset, min_val, max_val):
        if check_password(orginal_string, salt, guess, format):
            print(f"{password} decrypts to {guess}")
            cracked_passwords.append(guess)
            if len(cracked) == passwords_length:
                exit(0)

            


def generate_combinations(curr_string, possible, min_val, max_val):
    if len(possible) > 0: 
        for i in range(len(possible)):
            new_combination = curr_string + possible[i]
            if len(new_combination) >= min_val and len(new_combination) <= max_val:
                print(new_combination)
                yield new_combination

            yield from generate_combinations(new_combination, possible[:i] + possible[i + 1:])

def check_password(enc_pass, salt, guess, format):
    if format == 6:
        hashed_guess = sha512_crypt.using(salt=salt, rounds=5000).hash(guess)
        return sha512_crypt.verify(hashed_guess, enc_pass)
    elif format == 1:
        hashed_guess = md5_crypt.using(salt=salt, rounds=5000).hash(guess)
        return md5_crypt.verify(hashed_guess, enc_pass)   

if __name__ == "__main__":
    parser = argparse.ArgumentParser(prog="Password Cracker", description="This password cracker will generate all possible combinations of a given character set and length and attempt to decrypt given hashed passwords.")

    parser.add_argument("FILE", type=str, help="File containing hashed passwords. Expected format is a hased password on each line.", metavar="file")

    parser.add_argument("MIN_VAL", type=int, help="Minimum length of the generated string", metavar="min")

    parser.add_argument("MAX_VAL", type=int, help="Maximum length of the generated string", metavar="max")

    parser.add_argument("CHARSET", type=str, help="Types of characters to use. Choose from: 'lowercase', 'uppercase', 'int', 'ascii' or enter your own charset.", metavar="charset")

    args = parser.parse_args()

    main(file=args.FILE, min_val=args.MIN_VAL, max_val=args.MAX_VAL, charset=args.CHARSET)
