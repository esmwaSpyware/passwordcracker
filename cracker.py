import hashlib
import itertools
import string
import subprocess
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext

# Core Functions
def hash_password(password, algorithm="sha256"):
    return hashlib.new(algorithm, password.encode()).hexdigest()

def dictionary_attack(target_hash, wordlist_path, algorithm):
    try:
        with open(wordlist_path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                password = line.strip()
                hashed = hash_password(password, algorithm)
                if hashed == target_hash:
                    return f"[✔] Password found: {password}"
    except FileNotFoundError:
        return "[✘] Wordlist not found."
    return "[✘] Not found in dictionary."

def brute_force_crack(target_hash, algorithm="sha256", max_length=5):
    characters = string.ascii_lowercase + string.digits
    for length in range(1, max_length + 1):
        for guess in itertools.product(characters, repeat=length):
            password = ''.join(guess)
            hashed = hash_password(password, algorithm)
            if hashed == target_hash:
                return f"[✔] Password found: {password}"
    return "[✘] Brute-force failed."

def gpu_hashcat_crack(target_hash, wordlist_path, hash_type):
    try:
        with open("hashes.txt", "w") as f:
            f.write(target_hash + "\n")
        subprocess.run(["hashcat", "-m", hash_type, "-a", "0", "hashes.txt", wordlist_path, "--force", "--potfile-disable"])
        result = subprocess.run(["hashcat", "-m", hash_type, "-a", "0", "hashes.txt", wordlist_path, "--show", "--potfile-disable"], capture_output=True, text=True)
        return result.stdout or "[✘] Password not found with hashcat."
    except FileNotFoundError:
        return "[✘] Hashcat not installed."

def shadow_crack(wordlist_path):
    try:
        subprocess.run(["sudo", "unshadow", "/etc/passwd", "/etc/shadow"], stdout=open("shadow_combined.txt", "w"))
        subprocess.run(["john", "--wordlist=" + wordlist_path, "shadow_combined.txt"])
        result = subprocess.run(["john", "--show", "shadow_combined.txt"], capture_output=True, text=True)
        return result.stdout
    except Exception as e:
        return f"[✘] Shadow crack error: {e}"

def rainbow_crack(target_hash):
    try:
        result = subprocess.run(["rcrack", ".", "-h", target_hash], capture_output=True, text=True)
        return result.stdout or "[✘] Not found in rainbow tables."
    except FileNotFoundError:
        return "[✘] rcrack not installed."

# GUI Logic
class CrackerGUI:
    def __init__(self, root):
        self.root = root
        root.title("Password Cracker GUI")
        root.geometry("700x600")

        self.hash_var = tk.StringVar()
        self.wordlist_path = tk.StringVar()
        self.algorithm = tk.StringVar(value="sha256")
        self.max_length = tk.StringVar(value="5")
        self.hash_type = tk.StringVar(value="1400")

        tk.Label(root, text="Target Hash:").pack()
        tk.Entry(root, textvariable=self.hash_var, width=70).pack()

        tk.Label(root, text="Hash Algorithm (md5, sha1, sha256, etc):").pack()
        tk.Entry(root, textvariable=self.algorithm, width=20).pack()

        tk.Button(root, text="Select Wordlist", command=self.select_wordlist).pack()
        tk.Label(root, textvariable=self.wordlist_path, fg="blue").pack()

        tk.Button(root, text="Run Dictionary Attack", command=self.run_dictionary).pack()
        tk.Button(root, text="Run Brute-force Attack", command=self.run_brute).pack()

        tk.Label(root, text="Max Length for Brute-force:").pack()
        tk.Entry(root, textvariable=self.max_length, width=5).pack()

        tk.Label(root, text="Hashcat Mode (e.g., 0=MD5, 1400=SHA256):").pack()
        tk.Entry(root, textvariable=self.hash_type, width=10).pack()
        tk.Button(root, text="Run Hashcat (GPU)", command=self.run_hashcat).pack()

        tk.Button(root, text="Crack /etc/shadow", command=self.run_shadow).pack()
        tk.Button(root, text="Rainbow Table Crack", command=self.run_rainbow).pack()

        self.output = scrolledtext.ScrolledText(root, width=80, height=20)
        self.output.pack()

    def select_wordlist(self):
        path = filedialog.askopenfilename(title="Select Wordlist File")
        if path:
            self.wordlist_path.set(path)

    def run_dictionary(self):
        h = self.hash_var.get()
        alg = self.algorithm.get()
        wordlist = self.wordlist_path.get()
        result = dictionary_attack(h, wordlist, alg)
        self.output.insert(tk.END, result + "\n")

    def run_brute(self):
        h = self.hash_var.get()
        alg = self.algorithm.get()
        maxlen = int(self.max_length.get())
        result = brute_force_crack(h, alg, maxlen)
        self.output.insert(tk.END, result + "\n")

    def run_hashcat(self):
        h = self.hash_var.get()
        wordlist = self.wordlist_path.get()
        mode = self.hash_type.get()
        result = gpu_hashcat_crack(h, wordlist, mode)
        self.output.insert(tk.END, result + "\n")

    def run_shadow(self):
        wordlist = self.wordlist_path.get()
        result = shadow_crack(wordlist)
        self.output.insert(tk.END, result + "\n")

    def run_rainbow(self):
        h = self.hash_var.get()
        result = rainbow_crack(h)
        self.output.insert(tk.END, result + "\n")

# Launch GUI
if __name__ == "__main__":
    root = tk.Tk()
    app = CrackerGUI(root)
    root.mainloop()
