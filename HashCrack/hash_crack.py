from argparse import ArgumentParser
from hashlib import md5, sha1, sha256, sha512

def main():
    parser = ArgumentParser()
    parser.add_argument("-t", "--target", help="specify target hash")
    parser.add_argument("-w", "--wordfile", help="specify wordlist")
    args = parser.parse_args()
    if args.target and args.wordfile:
        target = args.target.lower()
        if len(target) == 32:
            print("[*] Hash identified as md5.")
            hasher = md5
        elif len(target) == 40:
            print("[*] Hash identified as sha1.")
            hasher = sha1
        elif len(target) == 64:
            print("[*] Hash identified as sha256.")
            hasher = sha256
        elif len(target) == 128:
            print("[*] Hash identified as sha512.")
            hasher = sha512
        else:
            print("[!] Invalid hash.")
            return
        with open(args.wordfile, "r") as f:
            fdata = f.read().strip()
        wordlist = fdata.split("\n")
        total = len(wordlist)
        print(f"[*] Loaded {total} words.")
        for word in wordlist:
            data = word.encode("UTF-8")
            hashed = hasher(data).hexdigest()
            if hashed == target:
                print(f"[+] {target} --> {word}")
                return
        else:
            print("[-] Not found.")
            return
    else:
        print("[!] Missing argument.")
        return

if __name__ == "__main__":
    main()
