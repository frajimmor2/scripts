import requests
import hashlib
from getpass import getpass
import math
import string


def check_pwned(pwd: str) -> int:
    # Get SHA1
    sha1 = hashlib.sha1(pwd.encode()).hexdigest().upper()
    prefix = sha1[:5]
    suffix = sha1[5:]
    r = requests.get(f"https://api.pwnedpasswords.com/range/{prefix}")
    hashes = r.text.splitlines()

    for line in hashes:
        h, count = line.split(":")
        if h == suffix:
            return int(count)
    return 0


def analyze_strength(pwd: str) -> list:
    score = 0
    tips = []

    if len(pwd) >= 14:
        score += 1
    else:
        tips.append("Use at least 14 characters")

    if any(c.isupper() for c in pwd):
        score += 1
    else:
        tips.append("Use capital letters")

    if any(c.islower() for c in pwd):
        score += 1
    else:
        tips.append("Use lower case")

    if any(c.isdigit() for c in pwd):
        score += 1
    else:
        tips.append("Add numbers")

    if any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in pwd):
        score += 1
    else:
        tips.append("Add special characters (!@#$...)")

    if score <= 2:
        strength = "Very weak"
    elif score <= 3:
        strength = "Weak"
    elif score == 4:
        strength = "Ok"
    else:
        strength = "Strong"

    return strength, tips


def complex_password(pwd: str) -> int:
    length = len(pwd)
    complexity = 0

    lower = string.ascii_lowercase
    upper = string.ascii_uppercase
    nums = string.digits

    has_lower = False
    has_upper = False
    has_sym = False
    has_num = False

    has_outwards_sym = False
    has_outwards_num = False
    has_outwards_upper = False

    symbols = ''.join(c for c in string.printable if c not in lower and c not in upper and c not in nums)

    for index in range(length):

        if pwd[index] in lower:
            has_lower = True

        elif pwd[index] in upper:
            if index == 0 or index == (length - 1):
                has_outwards_upper = True
            else:
                has_upper = True

        elif pwd[index] in nums:
            if index == 0 or index == (length - 1):
                has_outwards_num = True
            else:
                has_num = True

        elif pwd[index] in symbols:
            if index == 0 or index == (length - 1):
                has_outwards_sym = True
            else:
                has_sym = True

    if has_lower:
        complexity += 26
    if has_upper:
        complexity += 26
        has_outwards_upper = False
    if has_sym:
        complexity += 38
        has_outwards_sym = False
    if has_num:
        complexity += 10
        has_outwards_num = False

    if complexity == 0:
        complexity = 1

    combinations = complexity ** length

    if has_outwards_num:
        combinations *= 10
    if has_outwards_upper:
        combinations *= 26
    if has_outwards_sym:
        combinations *= 38

    return combinations


def min_complex_password(pwd: str)-> int:
    return len(''.join(set(pwd))) ** len(pwd)


def complex_zero(pwd: str)-> int:
    total = 0
    for x in range(len(pwd)):
        total += complex_password(pwd[x:])
    return total


def min_zero(pwd: str)-> int:
    total = 0
    for x in range(len(pwd)):
        total += min_complex_password(pwd[x:])
    return total


if __name__ == "__main__":
    pwd = getpass("Please provide the password: ")
    strength, tips = analyze_strength(pwd)
    print(f"Your password is classified as {strength}")
    print("You should follow those tips:")
    print(*tips, sep=", ")
    print(f"This password has been compromised: {check_pwned(pwd)} times.")

    b = complex_password(pwd)
    c = min_complex_password(pwd)
    d = complex_zero(pwd)
    e = min_zero(pwd)
    f = math.log(complex_password(pwd), 2)
    print(50*"-")
    print(f'Your password would approximately take {b} tries to bruteforce knowing the exact length')
    print(f'Your password would approximately take {c} tries to bruteforce by knowing the exact character set and length')
    print(f'Your password would approximately take {d} tries to bruteforce without knowing the exact length or character set')
    print(f'Your password would approximately take {e} tries to bruteforce by knowing the character set but not the length')
    print(f'Your password has ~{f} bits of entropy')
