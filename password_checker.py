import re
import random
import json
import string
import hashlib
import requests
import os
import pyperclip
import tkinter as tk
from tkinter import messagebox, ttk, Canvas
from functools import lru_cache
import nltk
from nltk.corpus import words

# Constants
PASSWORD_FILE = "saved_passwords.json"
HISTORY_FILE = "password_history.txt"
SALT = "my_secure_salt"

# Download words dataset if not already downloaded
try:
    nltk.data.find("corpora/words.zip")
except LookupError:
    nltk.download("words")

# Load common English words
COMMON_WORDS = set(words.words())

# Extended keyboard patterns including special characters
SEQUENTIAL_PATTERNS = [
    "qwerty", "asdf", "zxcv", "1234", "5678", "7890",
    "qaz", "wsx", "edc", "rfv", "tgb", "yhn", "ujm", "ik,", "ol.", "p;/",
    "!@#$", "%^&*", "qwerty123", "asdf!@#", "zxcv$%^", "123!@#", "456&*("
]

# Leetspeak substitutions
LEET_MAPPING = {"@": "a", "0": "o", "1": "i", "3": "e", "5": "s", "$": "s", "7": "t"}

# Common weak passwords
WEAK_PASSWORDS = ["password", "123456", "qwerty", "abc123", "admin", "letmein", "welcome"]

def contains_common_passphrase(password):
    password_lower = password.lower()
    words_in_password = re.findall(r"[a-zA-Z]+", password_lower)  # Extract words from password
    
    for word in words_in_password:
        if word in COMMON_WORDS and len(word) > 3:  # Ignore very short words
            return True
    return False

# Function to normalize leetspeak
def normalize_leetspeak(password):
    for leet, normal in LEET_MAPPING.items():
        password = password.replace(leet, normal)
    return password

# Function to check for sequential patterns
def contains_keyboard_sequence(password):
    password_lower = password.lower()
    return any(pattern in password_lower for pattern in SEQUENTIAL_PATTERNS)

# Function to check repeating characters
def contains_repeating_patterns(password):
    return re.search(r'(.)\1{3,}', password) is not None  # Detects any 4+ repeating characters

# Function to calculate entropy
def calculate_entropy(password):
    unique_chars = set(password)
    return (len(unique_chars) / len(password) * 100) if password else 0  # Convert to percentage

# Function to check password strength
def check_password_strength(password):
    score = 0
    suggestions = []

    normalized_password = normalize_leetspeak(password)
    if contains_common_passphrase(password):
        suggestions.append("Avoid using dictionary words as passwords.")
        score = 0  # Mark the password as weak
    if len(password) >= 12:
        score += 2
    elif len(password) >= 8:
        score += 1
    else:
        suggestions.append("Make your password at least 8 characters long.")

    if re.search(r'[A-Z]', password) and re.search(r'[a-z]', password):
        score += 1
    else:
        suggestions.append("Include both uppercase and lowercase letters.")

    if re.search(r'\d', password):
        score += 1
    else:
        suggestions.append("Add at least one number.")

    if re.search(r'[!@#$%^&*()_+-=<>?/{}~]', password):
        score += 1
    else:
        suggestions.append("Use at least one special character (!@#$%^&* etc.)")
        
    # Detect leetspeak usage
    if password != normalized_password:  # If password contained leetspeak substitutions
        suggestions.append("Avoid using leetspeak substitutions.")
        score -= 1   # Deduct score for leetspeak usage

    # Check for weaknesses
    if (normalized_password.lower() in WEAK_PASSWORDS or 
        contains_keyboard_sequence(password) or 
        contains_repeating_patterns(password) or 
        contains_common_passphrase(password)):
        suggestions.append("Avoid using common, sequential, or repeated character patterns.")
        score = 0  # Mark as weak

    # Calculate entropy
    entropy_score = calculate_entropy(password)
    if entropy_score < 50:
        suggestions.append("Your password is too predictable. Try adding more random characters.")

    if score >= 4 and entropy_score >= 60:
        return "🟢 Strong Password ✅", suggestions, 100
    elif score == 2 or score == 3:
        return "🟡 Medium Password ⚠️", suggestions, 50
    else:
        return "🔴 Weak Password ❌", suggestions, 20
    
# Caching function to avoid repeated API calls
@lru_cache(maxsize=100)
def check_breached_password(password):
    sha1_hash = hashlib.sha1(password.encode()).hexdigest().upper()
    prefix, suffix = sha1_hash[:5], sha1_hash[5:]
    url = f"https://api.pwnedpasswords.com/range/{prefix}"
    try:
        response = requests.get(url, timeout=5)  # Add timeout to prevent hanging
        if response.status_code == 200:
            hashes = (line.split(':') for line in response.text.splitlines())
            for h, count in hashes:
                if h == suffix:
                    return int(count)
    except (requests.RequestException, ConnectionError, TimeoutError):
        # Handle possible network issues
        pass
    return 0

# Secure password history tracking
def store_password_hash(password):
    salted_hash = hashlib.sha256((SALT + password).encode()).hexdigest()

    if not os.path.exists(HISTORY_FILE):
        with open(HISTORY_FILE, "w") as file:
            file.write("")

    with open(HISTORY_FILE, "r+") as file:
        hashes = file.read().splitlines()
        if salted_hash in hashes:
            return True
        file.write(salted_hash + "\n")
    return False

# Generate a strong password
def generate_strong_password(length=14):
    characters = string.ascii_letters + string.digits + "!@#$%^&*()_+-=<>?/{}~"
    password = ''.join(random.choice(characters) for _ in range(length))
    return password

# Save password function
def save_password():
    website = website_entry.get().strip()
    username = username_entry.get().strip()
    password = password_entry.get().strip()

    if not website or not username or not password:
        messagebox.showwarning("Warning", "Please fill in all fields.")
        return False

    try:
        if os.path.exists(PASSWORD_FILE):
            with open(PASSWORD_FILE, "r") as file:
                data = json.load(file)
        else:
            data = {}

        data[website] = {"username": username, "password": password}
        
        with open(PASSWORD_FILE, "w") as file:
            json.dump(data, file, indent=4)
        
        messagebox.showinfo("Success", "Password saved successfully!")
        update_website_dropdown()
        return True
    except Exception as e:
        messagebox.showerror("Error", f"Failed to save password: {str(e)}")
        return False

# Retrieve password function
def retrieve_password():
    website = website_var.get().strip()
    if not website:
        messagebox.showwarning("Warning", "Select a website.")
        return

    try:
        if os.path.exists(PASSWORD_FILE):
            with open(PASSWORD_FILE, "r") as file:
                data = json.load(file)

            if website in data:
                # Update the retrieved section with the data
                retrieved_website_value.config(text=website)
                retrieved_username_value.config(text=data[website]["username"])
                
                # Handle the password display with asterisks
                retrieved_password = data[website]["password"]
                masked_password = "*" * len(retrieved_password)
                retrieved_password_value.config(text=masked_password)
                
                # Store the actual password for the copy button
                retrieved_password_value.actual_password = retrieved_password
                
                # Show the retrieval section
                retrieval_display_frame.pack(fill="x", pady=(5, 10), padx=5)
                
                # Enable the show/copy buttons
                show_retrieved_button.config(state="normal")
                copy_retrieved_button.config(state="normal")
                
                # Evaluate the password strength in the background
                evaluate_retrieved_password(retrieved_password)
            else:
                messagebox.showwarning("Warning", "No password found for this website.")
        else:
            messagebox.showwarning("Warning", "No passwords have been saved yet.")
    except Exception as e:
        messagebox.showerror("Error", f"Failed to retrieve password: {str(e)}")

# Evaluate the retrieved password
def evaluate_retrieved_password(password):
    if not password:
        retrieved_strength_value.config(text="")
        return
        
    rating, _, strength_value = check_password_strength(password)
    retrieved_strength_value.config(text=rating)

# Toggle retrieved password visibility
def toggle_retrieved_password():
    # Get the current text and the actual password
    current_text = retrieved_password_value.cget("text")
    actual_password = getattr(retrieved_password_value, "actual_password", "")
    
    # Toggle between showing the password and asterisks
    if "*" in current_text:
        retrieved_password_value.config(text=actual_password)
        show_retrieved_button.config(text="Hide Password")
    else:
        retrieved_password_value.config(text="*" * len(actual_password))
        show_retrieved_button.config(text="Show Password")

# Copy retrieved password
def copy_retrieved_password():
    actual_password = getattr(retrieved_password_value, "actual_password", "")
    if actual_password:
        pyperclip.copy(actual_password)
        messagebox.showinfo("Copied", "Password copied to clipboard!")

# Update dropdown with saved websites
def update_website_dropdown():
    try:
        if os.path.exists(PASSWORD_FILE):
            with open(PASSWORD_FILE, "r") as file:
                data = json.load(file)
                website_dropdown["values"] = list(data.keys())
    except Exception as e:
        messagebox.showerror("Error", f"Failed to update website list: {str(e)}")

# Copy password function for generated passwords
def copy_to_clipboard():
    suggested_pass = suggested_label.cget("text").replace("Suggested Strong Password: ", "")
    if suggested_pass:
        pyperclip.copy(suggested_pass)
        messagebox.showinfo("Copied", "Password copied to clipboard!")
    else:
        pyperclip.copy(password_entry.get())
        messagebox.showinfo("Copied", "Password copied to clipboard!")

# Toggle password visibility
def toggle_password():
    password_entry.config(show="" if show_var.get() else "*")

# Update strength bar
def update_strength_bar(value):
    width = (value / 100) * 280  # Scale to fit the canvas width
    color = "#28a745" if value == 100 else "#ffc107" if value == 50 else "#dc3545"
    strength_canvas.itemconfig(strength_rect, fill=color)
    strength_canvas.coords(strength_rect, 5, 5, 5 + width, 25)

# Generate and set password
def generate_and_set_password():
    new_password = generate_strong_password()
    password_entry.delete(0, tk.END)
    password_entry.insert(0, new_password)
    evaluate_password()

# Flag to control auto-evaluation
auto_evaluate = True

# Evaluate password
def evaluate_password(save=False):
    password = password_entry.get()
    
    if not password:
        result_label.config(text="Password Rating: Enter a password to check")
        update_strength_bar(0)
        suggestions_text.config(state="normal")
        suggestions_text.delete("1.0", tk.END)
        suggestions_text.config(state="disabled")
        suggested_label.config(text="")
        copy_button.pack_forget()
        return
    
    if store_password_hash(password):
        messagebox.showwarning("Warning", "You have used this password before! Avoid reusing passwords.")

    rating, tips, strength_value = check_password_strength(password)
    result_label.config(text=f"Password Rating: {rating}")
    update_strength_bar(strength_value)
    
    # Check for breaches in background (only if not empty)
    if len(password) > 3:  # Only check substantive passwords
        try:
            breach_count = check_breached_password(password)
            if breach_count > 0:
                messagebox.showwarning("Breached Password", 
                                      f"This password has been found in {breach_count:,} breaches! Choose a different password.")
        except Exception:
            # If the API call fails, just continue without breach check
            pass

    suggestions_text.config(state="normal")
    suggestions_text.delete("1.0", tk.END)
    if tips:
        suggestions_text.insert("1.0", "• " + "\n• ".join(tips))
    suggestions_text.config(state="disabled")

    if strength_value < 100:
        suggested_password = generate_strong_password()
        suggested_label.config(text=f"Suggested Strong Password: {suggested_password}")
        copy_button.pack(pady=(5, 0))
    else:
        suggested_label.config(text="Great! Your password is strong.")
        copy_button.pack_forget()
        
    # Don't save on evaluation unless explicitly requested
    if save and website_entry.get().strip() and username_entry.get().strip():
        save_password()

# Handle password entry keyrelease without saving
def on_password_change(event):
    global auto_evaluate
    if auto_evaluate:
        evaluate_password(save=False)  # Only evaluate, don't save

# Clear the retrieved password display
def clear_retrieved_password():
    retrieval_display_frame.pack_forget()
    retrieved_website_value.config(text="")
    retrieved_username_value.config(text="")
    retrieved_password_value.config(text="")
    retrieved_strength_value.config(text="")
    retrieved_password_value.actual_password = ""

# Clear all fields
def clear_all_fields():
    website_entry.delete(0, tk.END)
    username_entry.delete(0, tk.END)
    password_entry.delete(0, tk.END)
    evaluate_password(save=False)

# ---------------------------- UI SETUP ----------------------------

# Create main window
root = tk.Tk()
root.title("🔐 Password Manager")
root.geometry("700x800")
root.resizable(True, True)
root.configure(bg="#f8f9fa")

# Configure styles
style = ttk.Style()
style.theme_use('clam')

# Custom colors
ACCENT_COLOR = "#007bff"
SUCCESS_COLOR = "#28a745"
WARNING_COLOR = "#ffc107"
DANGER_COLOR = "#dc3545"
LIGHT_BG = "#f8f9fa"
WHITE_BG = "#ffffff"

style.configure("Title.TLabel", font=("Segoe UI", 16, "bold"), background=LIGHT_BG, foreground="#212529")
style.configure("Heading.TLabel", font=("Segoe UI", 12, "bold"), background=WHITE_BG, foreground="#495057")
style.configure("Info.TLabel", font=("Segoe UI", 10), background=WHITE_BG, foreground="#6c757d")
style.configure("Custom.TFrame", background=WHITE_BG, relief="flat", borderwidth=1)
style.configure("Custom.TLabelframe", background=WHITE_BG, relief="solid", borderwidth=1)
style.configure("Custom.TLabelframe.Label", background=WHITE_BG, font=("Segoe UI", 11, "bold"), foreground="#495057")
style.configure("Action.TButton", font=("Segoe UI", 10), padding=(10, 6))

# Create scrollable main frame
canvas = tk.Canvas(root, bg=LIGHT_BG, highlightthickness=0)
scrollbar = ttk.Scrollbar(root, orient="vertical", command=canvas.yview)
scrollable_frame = ttk.Frame(canvas, style="Custom.TFrame")

scrollable_frame.bind(
    "<Configure>",
    lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
)

canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
canvas.configure(yscrollcommand=scrollbar.set)

# Pack scrollbar and canvas
canvas.pack(side="left", fill="both", expand=True)
scrollbar.pack(side="right", fill="y")

# Main container with padding
main_frame = ttk.Frame(scrollable_frame, style="Custom.TFrame")
main_frame.pack(fill="both", expand=True, padx=20, pady=20)

# Title
title_frame = ttk.Frame(main_frame, style="Custom.TFrame")
title_frame.pack(fill="x", pady=(0, 20))
title_label = ttk.Label(title_frame, text="🔐 Password Manager", style="Title.TLabel")
title_label.pack()
subtitle_label = ttk.Label(title_frame, text="Secure password creation, storage, and strength analysis", 
                          style="Info.TLabel")
subtitle_label.pack(pady=(5, 0))

# Create Password Section
create_frame = ttk.LabelFrame(main_frame, text=" Create & Save Passwords ", style="Custom.TLabelframe", padding=15)
create_frame.pack(fill="x", pady=(0, 15))

# Form fields with better spacing
fields_frame = ttk.Frame(create_frame, style="Custom.TFrame")
fields_frame.pack(fill="x", pady=(0, 15))

# Website entry
website_frame = ttk.Frame(fields_frame, style="Custom.TFrame")
website_frame.pack(fill="x", pady=(0, 10))
ttk.Label(website_frame, text="Website/Service:", style="Heading.TLabel").pack(anchor="w")
website_entry = ttk.Entry(website_frame, font=("Segoe UI", 11), width=50)
website_entry.pack(fill="x", pady=(5, 0))

# Username entry
username_frame = ttk.Frame(fields_frame, style="Custom.TFrame")
username_frame.pack(fill="x", pady=(0, 10))
ttk.Label(username_frame, text="Username/Email:", style="Heading.TLabel").pack(anchor="w")
username_entry = ttk.Entry(username_frame, font=("Segoe UI", 11), width=50)
username_entry.pack(fill="x", pady=(5, 0))

# Password entry with toggle
password_frame = ttk.Frame(fields_frame, style="Custom.TFrame")
password_frame.pack(fill="x", pady=(0, 10))
ttk.Label(password_frame, text="Password:", style="Heading.TLabel").pack(anchor="w")
password_input_frame = ttk.Frame(password_frame, style="Custom.TFrame")
password_input_frame.pack(fill="x", pady=(5, 0))
password_entry = ttk.Entry(password_input_frame, font=("Segoe UI", 11), show="*")
password_entry.pack(side="left", fill="x", expand=True)
show_var = tk.BooleanVar()
show_button = ttk.Checkbutton(password_input_frame, text="Show", variable=show_var, command=toggle_password)
show_button.pack(side="right", padx=(10, 0))

# Auto-evaluate option
auto_eval_frame = ttk.Frame(fields_frame, style="Custom.TFrame")
auto_eval_frame.pack(fill="x")
auto_eval_var = tk.BooleanVar(value=True)
auto_eval_check = ttk.Checkbutton(
    auto_eval_frame, 
    text="Real-time password strength checking", 
    variable=auto_eval_var,
    command=lambda: globals().update(auto_evaluate=auto_eval_var.get())
)
auto_eval_check.pack(anchor="w")

# Action buttons
buttons_frame = ttk.Frame(create_frame, style="Custom.TFrame")
buttons_frame.pack(fill="x")
save_button = ttk.Button(buttons_frame, text="💾 Save Password", command=save_password, style="Action.TButton")
save_button.pack(side="left", padx=(0, 10))
generate_button = ttk.Button(buttons_frame, text="🎲 Generate Password", command=generate_and_set_password, style="Action.TButton")
generate_button.pack(side="left", padx=(0, 10))
clear_button = ttk.Button(buttons_frame, text="🗑️ Clear Fields", command=clear_all_fields, style="Action.TButton")
clear_button.pack(side="left")

# Retrieve Section
retrieve_frame = ttk.LabelFrame(main_frame, text=" Retrieve Saved Passwords ", style="Custom.TLabelframe", padding=15)
retrieve_frame.pack(fill="x", pady=(0, 15))

# Retrieve selection
retrieve_selection_frame = ttk.Frame(retrieve_frame, style="Custom.TFrame")
retrieve_selection_frame.pack(fill="x", pady=(0, 10))
ttk.Label(retrieve_selection_frame, text="Select Website/Service:", style="Heading.TLabel").pack(anchor="w")
retrieve_input_frame = ttk.Frame(retrieve_selection_frame, style="Custom.TFrame")
retrieve_input_frame.pack(fill="x", pady=(5, 0))
website_var = tk.StringVar()
website_dropdown = ttk.Combobox(retrieve_input_frame, textvariable=website_var, state="readonly", 
                               font=("Segoe UI", 11), width=40)
website_dropdown.pack(side="left", fill="x", expand=True)
retrieve_button = ttk.Button(retrieve_input_frame, text="📥 Retrieve", command=retrieve_password, style="Action.TButton")
retrieve_button.pack(side="right", padx=(10, 0))

# Retrieved Password Display Section (initially hidden)
retrieval_display_frame = ttk.LabelFrame(retrieve_frame, text=" Retrieved Password Details ", 
                                       style="Custom.TLabelframe", padding=15)

# Retrieved details grid
details_frame = ttk.Frame(retrieval_display_frame, style="Custom.TFrame")
details_frame.pack(fill="x", pady=(0, 15))

# Website
ttk.Label(details_frame, text="Website:", style="Heading.TLabel").grid(row=0, column=0, sticky="w", pady=(0, 8))
retrieved_website_value = ttk.Label(details_frame, text="", font=("Segoe UI", 11), background=WHITE_BG)
retrieved_website_value.grid(row=0, column=1, sticky="w", padx=(10, 0), pady=(0, 8))

# Username
ttk.Label(details_frame, text="Username:", style="Heading.TLabel").grid(row=1, column=0, sticky="w", pady=(0, 8))
retrieved_username_value = ttk.Label(details_frame, text="", font=("Segoe UI", 11), background=WHITE_BG)
retrieved_username_value.grid(row=1, column=1, sticky="w", padx=(10, 0), pady=(0, 8))

# Password
ttk.Label(details_frame, text="Password:", style="Heading.TLabel").grid(row=2, column=0, sticky="w", pady=(0, 8))
retrieved_password_value = ttk.Label(details_frame, text="", font=("Segoe UI", 11), background=WHITE_BG)
retrieved_password_value.grid(row=2, column=1, sticky="w", padx=(10, 0), pady=(0, 8))

# Strength
ttk.Label(details_frame, text="Strength:", style="Heading.TLabel").grid(row=3, column=0, sticky="w")
retrieved_strength_value = ttk.Label(details_frame, text="", font=("Segoe UI", 11), background=WHITE_BG)
retrieved_strength_value.grid(row=3, column=1, sticky="w", padx=(10, 0))

# Configure grid weights
details_frame.columnconfigure(1, weight=1)

# Retrieved password action buttons
retrieved_buttons_frame = ttk.Frame(retrieval_display_frame, style="Custom.TFrame")
retrieved_buttons_frame.pack(fill="x")
show_retrieved_button = ttk.Button(retrieved_buttons_frame, text="👁️ Show Password", 
                                 command=toggle_retrieved_password, state="disabled", style="Action.TButton")
show_retrieved_button.pack(side="left", padx=(0, 10))
copy_retrieved_button = ttk.Button(retrieved_buttons_frame, text="📋 Copy Password", 
                                 command=copy_retrieved_password, state="disabled", style="Action.TButton")
copy_retrieved_button.pack(side="left", padx=(0, 10))
close_retrieved_button = ttk.Button(retrieved_buttons_frame, text="✖️ Close", 
                                  command=clear_retrieved_password, style="Action.TButton")
close_retrieved_button.pack(side="left")

# Strength Checker Section
strength_frame = ttk.LabelFrame(main_frame, text=" Password Strength Analysis ", style="Custom.TLabelframe", padding=15)
strength_frame.pack(fill="x", pady=(0, 15))

# Check strength button
check_frame = ttk.Frame(strength_frame, style="Custom.TFrame")
check_frame.pack(fill="x", pady=(0, 15))
check_button = ttk.Button(check_frame, text="🔍 Analyze Current Password", 
                         command=lambda: evaluate_password(save=False), style="Action.TButton")
check_button.pack()

# Result display
result_frame = ttk.Frame(strength_frame, style="Custom.TFrame")
result_frame.pack(fill="x", pady=(0, 15))
result_label = ttk.Label(result_frame, text="Password Rating: Enter a password to check", 
                        font=("Segoe UI", 12, "bold"), background=WHITE_BG)
result_label.pack()

# Strength meter
meter_frame = ttk.Frame(strength_frame, style="Custom.TFrame")
meter_frame.pack(fill="x", pady=(0, 15))
ttk.Label(meter_frame, text="Strength Meter:", style="Heading.TLabel").pack(anchor="w")
strength_canvas = tk.Canvas(meter_frame, width=290, height=30, bg="#e9ecef", highlightthickness=1, 
                           highlightbackground="#dee2e6")
strength_canvas.pack(pady=(5, 0))
strength_rect = strength_canvas.create_rectangle(5, 5, 5, 25, fill="#28a745")

# Suggestions area
suggestions_frame = ttk.Frame(strength_frame, style="Custom.TFrame")
suggestions_frame.pack(fill="x", pady=(0, 15))
ttk.Label(suggestions_frame, text="Improvement Suggestions:", style="Heading.TLabel").pack(anchor="w")
suggestions_text = tk.Text(suggestions_frame, height=6, font=("Segoe UI", 10), wrap="word", 
                          state="disabled", bg=WHITE_BG, relief="solid", borderwidth=1)
suggestions_text.pack(fill="x", pady=(5, 0))

# Suggested password section
suggested_frame = ttk.Frame(strength_frame, style="Custom.TFrame")
suggested_frame.pack(fill="x")
suggested_label = ttk.Label(suggested_frame, text="", font=("Segoe UI", 11), background=WHITE_BG, wraplength=650)
suggested_label.pack(anchor="w")

# Copy button (hidden initially)
copy_button = ttk.Button(suggested_frame, text="📋 Copy Suggested Password", 
                        command=copy_to_clipboard, style="Action.TButton")

# Initialize
update_website_dropdown()

# Bind events
password_entry.bind("<KeyRelease>", on_password_change)

# Mouse wheel scrolling
def _on_mousewheel(event):
    canvas.yview_scroll(int(-1*(event.delta/120)), "units")

canvas.bind_all("<MouseWheel>", _on_mousewheel)

# Start the application
root.mainloop()