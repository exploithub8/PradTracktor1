import itertools
import time
import hashlib
from datetime import datetime
from colorama import Fore, Back, Style, init
import argparse
import sys
import os
import zipfile
import threading
import queue

# Initialize colorama
init(autoreset=True)

# Global flag for stopping threads
stop_flag = False

def print_banner():
    """Print colorful ASCII art banner"""
    print(Fore.YELLOW + r"""
   ___                      _     _____               _    _             
  / _ \ _ __   ___ __ _  __| |   /__   \_ __ __ _  __| | _| |_ ___  _ __ 
 / /_)/| '__| / __/ _` |/ _` |     / /\/ '__/ _` |/ _` |/ / __/ _ \| '__|
/ ___/ | |   | (_| (_| | (_| |    / /  | | | (_| | (_|   <| || (_) | |   
\/     |_|    \___\__,_|\__,_|    \/   |_|  \__,_|\__,_|\_\\__\___/|_|   
    """ + Style.RESET_ALL)
    print(Fore.CYAN + "=" * 60)
    print(Fore.GREEN + "||" + Fore.WHITE + "         ADVANCED PASSWORD CRACKER  By Exploit_hub8    " + Fore.GREEN + "||")
    print(Fore.CYAN + "=" * 60 + Style.RESET_ALL)

def hybrid_attack(target_hash, wordlist, hash_type='md5', max_suffix=3, max_prefix=3):
    """Combine dictionary words with brute-force modifications"""
    hash_func = get_hash_function(hash_type)
    
    for word in wordlist:
        if stop_flag:
            break
            
        # Try the word itself
        if hash_func(word.encode()).hexdigest() == target_hash:
            return word
            
        # Try with numeric suffixes
        for i in range(1, max_suffix + 1):
            for suffix in itertools.product('0123456789', repeat=i):
                candidate = word + ''.join(suffix)
                if hash_func(candidate.encode()).hexdigest() == target_hash:
                    return candidate
                    
        # Try with numeric prefixes
        for i in range(1, max_prefix + 1):
            for prefix in itertools.product('0123456789', repeat=i):
                candidate = ''.join(prefix) + word
                if hash_func(candidate.encode()).hexdigest() == target_hash:
                    return candidate
                    
        # Try with common special characters
        for char in ['!', '@', '#', '$', '%', '^', '&', '*']:
            for candidate in [char + word, word + char, char + word + char]:
                if hash_func(candidate.encode()).hexdigest() == target_hash:
                    return candidate
    return None
def get_hash_function(hash_type):
    """Return the appropriate hashlib function based on hash type"""
    hash_functions = {
        'md5': hashlib.md5,
        'sha1': hashlib.sha1,
        'sha256': hashlib.sha256,
        'sha512': hashlib.sha512
    }
    return hash_functions.get(hash_type.lower(), hashlib.md5)

def load_wordlist(wordlist_path):
    """Load passwords from a wordlist file"""
    try:
        with open(wordlist_path, 'r', encoding='utf-8', errors='ignore') as f:
            return [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print(Fore.RED + f"[-] Wordlist file not found: {wordlist_path}")
        return None

def dictionary_attack(target_hash, wordlist, hash_type='md5', verbose=True):
    """Perform dictionary attack using a wordlist"""
    start_time = time.time()
    attempts = 0
    hash_func = get_hash_function(hash_type)
    
    if verbose:
        print(Fore.BLUE + "\n[+] " + Fore.WHITE + "Starting dictionary attack")
        print(Fore.BLUE + "[+] " + Fore.WHITE + f"Target hash: " + Fore.RED + f"{target_hash}")
        print(Fore.BLUE + "[+] " + Fore.WHITE + f"Hash type: " + Fore.YELLOW + f"{hash_type}")
        print(Fore.BLUE + "[+] " + Fore.WHITE + f"Wordlist size: " + Fore.GREEN + f"{len(wordlist):,}")
        print(Fore.BLUE + "[+] " + Fore.WHITE + f"Start time: " + Fore.CYAN + f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(Fore.MAGENTA + "-" * 60)
    
    for password in wordlist:
        if stop_flag:
            break
            
        attempts += 1
        candidate_hash = hash_func(password.encode()).hexdigest()
        
        if verbose and attempts % 1000 == 0:
            elapsed = time.time() - start_time
            print(Fore.BLUE + "[*] " + Fore.WHITE + f"Attempt {attempts:,}: " + Fore.YELLOW + f"{password}" + 
                  Fore.WHITE + f" (Elapsed: {elapsed:.2f}s, Speed: {attempts/elapsed:,.0f} hashes/s)", end='\r')
        
        if candidate_hash == target_hash:
            elapsed = time.time() - start_time
            print("\n" + Fore.GREEN + "-" * 60)
            print(Fore.GREEN + "[+] " + Fore.WHITE + "Password found!")
            print(Fore.GREEN + "[+] " + Fore.WHITE + "Password: " + Fore.YELLOW + f"{password}")
            print(Fore.GREEN + "[+] " + Fore.WHITE + "Hash: " + Fore.CYAN + f"{candidate_hash}")
            print(Fore.GREEN + "[+] " + Fore.WHITE + "Attempts: " + Fore.MAGENTA + f"{attempts:,}")
            print(Fore.GREEN + "[+] " + Fore.WHITE + "Time elapsed: " + Fore.RED + f"{elapsed:.2f} seconds")
            print(Fore.GREEN + "[+] " + Fore.WHITE + "Speed: " + Fore.CYAN + f"{attempts/elapsed:,.0f} hashes/s")
            print(Fore.GREEN + "[+] " + Fore.WHITE + "End time: " + Fore.CYAN + f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
            print(Fore.GREEN + "-" * 60 + Style.RESET_ALL)
            return password
    
    print(Fore.RED + "\n[-] " + Fore.WHITE + "Password not found in wordlist")
    return None

def brute_force_worker(target_hash, charset, length_range, hash_type, result_queue, verbose=False):
    """Worker function for multi-threaded brute force"""
    hash_func = get_hash_function(hash_type)
    
    for length in length_range:
        for candidate in itertools.product(charset, repeat=length):
            if stop_flag:
                return
                
            candidate = ''.join(candidate)
            candidate_hash = hash_func(candidate.encode()).hexdigest()
            
            if candidate_hash == target_hash:
                result_queue.put(candidate)
                return

def brute_force_cracker(target_hash, max_length=6, charset=None, hash_type='md5', threads=4, verbose=True):
    """
    Advanced brute force password cracker with multi-threading support.
    
    Args:
        target_hash (str): The hash of the password to crack
        max_length (int): Maximum password length to try
        charset (str): Character set to use (default: lowercase + digits + symbols)
        hash_type (str): Type of hash (md5, sha1, sha256, sha512)
        threads (int): Number of threads to use
        verbose (bool): Whether to print progress
    """
    # Default character set (lowercase + uppercase + digits + symbols)
    if charset is None:
        charset = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()'
    
    global stop_flag
    stop_flag = False
    start_time = time.time()
    attempts = 0
    result_queue = queue.Queue()
    workers = []
    
    if verbose:
        print(Fore.BLUE + "\n[+] " + Fore.WHITE + "Starting brute force attack")
        print(Fore.BLUE + "[+] " + Fore.WHITE + f"Target hash: " + Fore.RED + f"{target_hash}")
        print(Fore.BLUE + "[+] " + Fore.WHITE + f"Hash type: " + Fore.YELLOW + f"{hash_type}")
        print(Fore.BLUE + "[+] " + Fore.WHITE + f"Max length: " + Fore.YELLOW + f"{max_length}")
        print(Fore.BLUE + "[+] " + Fore.WHITE + f"Charset: " + Fore.GREEN + f"{charset[:20]}..." + Fore.WHITE + f" ({len(charset)} characters)")
        print(Fore.BLUE + "[+] " + Fore.WHITE + f"Threads: " + Fore.CYAN + f"{threads}")
        print(Fore.BLUE + "[+] " + Fore.WHITE + f"Start time: " + Fore.CYAN + f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(Fore.MAGENTA + "-" * 60)
    
    # Split work among threads
    length_ranges = [[] for _ in range(threads)]
    for length in range(1, max_length + 1):
        length_ranges[length % threads].append(length)
    
    # Start worker threads
    for i in range(threads):
        t = threading.Thread(
            target=brute_force_worker,
            args=(target_hash, charset, length_ranges[i], hash_type, result_queue, verbose)
        )
        workers.append(t)
        t.start()
    
    # Monitor progress
    last_update = time.time()
    while not any(t.is_alive() for t in workers) and result_queue.empty():
        time.sleep(0.1)
        
        # Calculate attempts (approximate)
        elapsed = time.time() - start_time
        if elapsed > 0:
            speed = attempts / elapsed
        else:
            speed = 0
            
        if verbose and time.time() - last_update > 1.0:
            last_update = time.time()
            print(Fore.BLUE + "[*] " + Fore.WHITE + f"Attempts: {attempts:,} | " +
                  f"Speed: {speed:,.0f} hashes/s | " +
                  f"Elapsed: {elapsed:.2f}s", end='\r')
    
    # Wait for result or completion
    try:
        password = result_queue.get(timeout=0.1)
        stop_flag = True
        for t in workers:
            t.join()
            
        elapsed = time.time() - start_time
        print("\n" + Fore.GREEN + "-" * 60)
        print(Fore.GREEN + "[+] " + Fore.WHITE + "Password found!")
        print(Fore.GREEN + "[+] " + Fore.WHITE + "Password: " + Fore.YELLOW + f"{password}")
        print(Fore.GREEN + "[+] " + Fore.WHITE + "Hash: " + Fore.CYAN + f"{hash_func(password.encode()).hexdigest()}") # pyright: ignore[reportUndefinedVariable]
        print(Fore.GREEN + "[+] " + Fore.WHITE + "Time elapsed: " + Fore.RED + f"{elapsed:.2f} seconds")
        print(Fore.GREEN + "[+] " + Fore.WHITE + "End time: " + Fore.CYAN + f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(Fore.GREEN + "-" * 60 + Style.RESET_ALL)
        return password
        
    except queue.Empty:
        stop_flag = True
        for t in workers:
            t.join()
            
        print(Fore.RED + "\n[-] " + Fore.WHITE + "Password not found with given parameters")
        return None

def crack_zip_file(zip_path, wordlist=None, max_length=6, charset=None, threads=4):
    """Attempt to crack a password-protected ZIP file"""
    if not os.path.exists(zip_path):
        print(Fore.RED + f"[-] ZIP file not found: {zip_path}")
        return None
    
    try:
        with zipfile.ZipFile(zip_path) as zip_file:
            # Get the first file in the archive for testing
            test_file = zip_file.namelist()[0]
            
            if wordlist:
                print(Fore.BLUE + "[+] " + Fore.WHITE + "Starting dictionary attack on ZIP file")
                passwords = load_wordlist(wordlist)
                if not passwords:
                    return None
                    
                for password in passwords:
                    try:
                        zip_file.extract(test_file, pwd=password.encode())
                        print(Fore.GREEN + "\n[+] " + Fore.WHITE + "Password found: " + Fore.YELLOW + f"{password}")
                        return password
                    except (RuntimeError, zipfile.BadZipFile):
                        continue
            else:
                print(Fore.BLUE + "[+] " + Fore.WHITE + "Starting brute force attack on ZIP file")
                return brute_force_cracker(
                    None,  # No hash for ZIP cracking
                    max_length=max_length,
                    charset=charset,
                    threads=threads,
                    verbose=True,
                    zip_file=zip_file
                )
                
    except Exception as e:
        print(Fore.RED + f"[-] Error processing ZIP file: {e}")
        return None

def main():
    """Main function with argument parsing"""
    parser = argparse.ArgumentParser(description="Advanced Password Cracker")
    parser.add_argument("-H", "--hash", help="Target hash to crack")
    parser.add_argument("-t", "--hash-type", default="md5", 
                       choices=["md5", "sha1", "sha256", "sha512"],
                       help="Hash algorithm (default: md5)")
    parser.add_argument("-w", "--wordlist", help="Path to wordlist file for dictionary attack")
    parser.add_argument("-m", "--max-length", type=int, default=6,
                       help="Maximum password length for brute force (default: 6)")
    parser.add_argument("-c", "--charset", 
                       help="Custom character set for brute force (default: a-zA-Z0-9 and basic symbols)")
    parser.add_argument("-T", "--threads", type=int, default=4,
                       help="Number of threads to use (default: 4)")
    parser.add_argument("-z", "--zip", help="Path to password-protected ZIP file to crack")
    
    args = parser.parse_args()
    
    if not any([args.hash, args.zip]):
        print_banner()
        print(Fore.CYAN + "\nPassword Cracking Tool (Advanced)")
        print(Fore.CYAN + "=" * 60)
        
        # Interactive mode
        target_hash = input(Fore.BLUE + "[?] " + Fore.WHITE + "Enter target hash (or leave blank for ZIP cracking): " + Fore.YELLOW).strip()
        zip_path = input(Fore.BLUE + "[?] " + Fore.WHITE + "Or enter path to ZIP file (if cracking ZIP): " + Fore.YELLOW).strip()
        
        if not target_hash and not zip_path:
            print(Fore.YELLOW + "[!] Using demo mode with default password 'abc1'")
            target_hash = hashlib.md5("abc1".encode()).hexdigest()
            hash_type = "md5"
        elif zip_path:
            args.zip = zip_path
        else:
            hash_type = input(Fore.BLUE + "[?] " + Fore.WHITE + "Enter hash type (md5, sha1, sha256, sha512): " + Fore.YELLOW).strip() or "md5"
            args.hash_type = hash_type
            
        if not zip_path:
            args.hash = target_hash
    
    if args.zip:
        wordlist = None
        if input(Fore.BLUE + "[?] " + Fore.WHITE + "Use wordlist? (y/n): " + Fore.YELLOW).strip().lower() == 'y':
            wordlist = input(Fore.BLUE + "[?] " + Fore.WHITE + "Enter wordlist path: " + Fore.YELLOW).strip()
        
        max_length = int(input(Fore.BLUE + "[?] " + Fore.WHITE + "Enter max password length (default 6): " + Fore.YELLOW) or 6)
        args.max_length = max_length
        
        if not wordlist:
            charset = input(Fore.BLUE + "[?] " + Fore.WHITE + "Enter character set (or leave blank for default): " + Fore.YELLOW).strip()
            if charset:
                args.charset = charset
        
        result = crack_zip_file(args.zip, wordlist, args.max_length, args.charset, args.threads)
    elif args.hash:
        if args.wordlist:
            wordlist = load_wordlist(args.wordlist)
            if wordlist:
                result = dictionary_attack(args.hash, wordlist, args.hash_type)
        else:
            result = brute_force_cracker(
                args.hash,
                max_length=args.max_length,
                charset=args.charset,
                hash_type=args.hash_type,
                threads=args.threads
            )
    else:
        parser.print_help()
        return
    
    if not result:
        print(Fore.RED + "\n[-] " + Fore.WHITE + "Failed to crack the password")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(Fore.RED + "\n[!] " + Fore.WHITE + "Operation cancelled by user")
        stop_flag = True
        sys.exit(1)