import hashlib
import tkinter as tk
from tkinter import filedialog, messagebox

# Function to hash a password using the selected algorithm
def hash_password(password, algorithm):
    if algorithm == "md5":
        return hashlib.md5(password.encode()).hexdigest()
    elif algorithm == "sha1":
        return hashlib.sha1(password.encode()).hexdigest()
    elif algorithm == "sha256":
        return hashlib.sha256(password.encode()).hexdigest()
    elif algorithm == "sha512":
        return hashlib.sha512(password.encode()).hexdigest()
    elif algorithm == "sha224":
        return hashlib.sha224(password.encode()).hexdigest()
    elif algorithm == "sha384":
        return hashlib.sha384(password.encode()).hexdigest()
    elif algorithm == "blake2b":
        return hashlib.blake2b(password.encode()).hexdigest()
    elif algorithm == "blake2s":
        return hashlib.blake2s(password.encode()).hexdigest()
    elif algorithm == "ripemd160":
        return hashlib.new('ripemd160', password.encode()).hexdigest()
    elif algorithm == "whirlpool":
        return hashlib.new('whirlpool', password.encode()).hexdigest()
    else:
        raise ValueError(f"Unsupported algorithm: {algorithm}")

# Function to crack hashes
def crack_hashes(hash_file, wordlist, algorithm):
    try:
        # Open hash file and read hashes
        with open(hash_file, 'r') as f:
            hashes = [line.strip() for line in f.readlines()]

        # Try each word in the wordlist and hash it with the specified algorithm
        for word in wordlist:
            hashed_word = hash_password(word, algorithm)
            if hashed_word in hashes:
                return f"Cracked password: {word} (Hash: {hashed_word})"
        return "No match found"
    
    except Exception as e:
        return f"Error: {str(e)}"

# GUI setup
class PasswordCrackerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Password Cracker & Hash Generator")

        # Initial wordlist (default password list)
        self.default_wordlist = [
            "password", "123456", "123456789", "qwerty", "abc123", "password1", "letmein", 
            "welcome", "iloveyou", "admin", "1234", "password123", "sunshine", "trustno1", 
            "123123", "password1", "qwertyuiop"
        ]
        self.wordlist = self.default_wordlist  # Initially set to default wordlist

        self.hash_file = None
        self.wordlist_file = None
        self.algorithm = tk.StringVar(value="md5")  # Default to MD5

        self.create_widgets()

    def create_widgets(self):
        # Hash File Selection
        self.hash_file_label = tk.Label(self.root, text="Select Hash File:")
        self.hash_file_label.grid(row=0, column=0, padx=10, pady=10, sticky='e')

        self.hash_file_button = tk.Button(self.root, text="Browse", command=self.select_hash_file)
        self.hash_file_button.grid(row=0, column=1, padx=10, pady=10)

        self.hash_file_display = tk.Entry(self.root, width=40)
        self.hash_file_display.grid(row=0, column=2, padx=10, pady=10)

        # Wordlist File Selection
        self.wordlist_label = tk.Label(self.root, text="Select Wordlist File:")
        self.wordlist_label.grid(row=1, column=0, padx=10, pady=10, sticky='e')

        self.wordlist_button = tk.Button(self.root, text="Browse", command=self.select_wordlist_file)
        self.wordlist_button.grid(row=1, column=1, padx=10, pady=10)

        self.wordlist_display = tk.Entry(self.root, width=40)
        self.wordlist_display.grid(row=1, column=2, padx=10, pady=10)

        # Wordlist Edit Box (Allow user to add or modify words)
        self.wordlist_edit_label = tk.Label(self.root, text="Edit Wordlist (Optional):")
        self.wordlist_edit_label.grid(row=2, column=0, padx=10, pady=10, sticky='e')

        self.wordlist_edit_box = tk.Text(self.root, height=6, width=40)
        self.wordlist_edit_box.grid(row=2, column=1, columnspan=2, padx=10, pady=10)

        # Algorithm Selection (MD5, SHA256, SHA1, SHA512, etc.)
        self.algorithm_label = tk.Label(self.root, text="Select Hash Algorithm:")
        self.algorithm_label.grid(row=3, column=0, padx=10, pady=10, sticky='e')

        # Add more algorithms here
        self.algorithm_menu = tk.OptionMenu(self.root, self.algorithm, "md5", "sha1", "sha256", "sha512", 
                                            "sha224", "sha384", "blake2b", "blake2s", "ripemd160", "whirlpool")
        self.algorithm_menu.grid(row=3, column=1, padx=10, pady=10)

        # Start Cracking Button
        self.crack_button = tk.Button(self.root, text="Start Cracking", command=self.start_cracking)
        self.crack_button.grid(row=4, column=1, columnspan=2, pady=20)

        # Output area
        self.result_label = tk.Label(self.root, text="Result:")
        self.result_label.grid(row=5, column=0, padx=10, pady=10, sticky='e')

        self.result_display = tk.Text(self.root, height=5, width=50, wrap=tk.WORD)
        self.result_display.grid(row=5, column=1, columnspan=2, padx=10, pady=10)

        # Populate default wordlist into edit box
        self.update_wordlist_edit_box()

    def update_wordlist_edit_box(self):
        # Display the current wordlist in the text box
        self.wordlist_edit_box.delete(1.0, tk.END)
        for word in self.wordlist:
            self.wordlist_edit_box.insert(tk.END, word + "\n")

    def select_hash_file(self):
        self.hash_file = filedialog.askopenfilename(title="Select Hash File", filetypes=(("Text files", "*.txt"), ("All files", "*.*")))
        if self.hash_file:
            self.hash_file_display.delete(0, tk.END)
            self.hash_file_display.insert(0, self.hash_file)

    def select_wordlist_file(self):
        self.wordlist_file = filedialog.askopenfilename(title="Select Wordlist File", filetypes=(("Text files", "*.txt"), ("All files", "*.*")))
        if self.wordlist_file:
            self.wordlist_display.delete(0, tk.END)
            self.wordlist_display.insert(0, self.wordlist_file)

            # Load the selected wordlist from file
            with open(self.wordlist_file, 'r') as f:
                self.wordlist = [line.strip() for line in f.readlines()]

            # Update the wordlist edit box with the newly loaded wordlist
            self.update_wordlist_edit_box()

    def start_cracking(self):
        # Get the updated wordlist from the text box
        self.wordlist = [line.strip() for line in self.wordlist_edit_box.get(1.0, tk.END).splitlines() if line.strip()]

        # Validate inputs
        if not self.hash_file or not self.wordlist:
            messagebox.showerror("Error", "Please select both the hash file and wordlist file.")
            return

        algorithm = self.algorithm.get()
        result = crack_hashes(self.hash_file, self.wordlist, algorithm)
        self.result_display.delete(1.0, tk.END)
        self.result_display.insert(tk.END, result)

# Main loop for the GUI
if __name__ == "__main__":
    root = tk.Tk()
    app = PasswordCrackerApp(root)
    root.mainloop()
