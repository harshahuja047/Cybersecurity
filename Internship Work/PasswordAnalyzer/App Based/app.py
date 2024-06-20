import tkinter as tk
from tkinter import messagebox
import random
import string
import pyperclip

# Function to generate password
def generate_password(length):
    charset = string.ascii_letters + string.digits + string.punctuation
    password = ''.join(random.choice(charset) for _ in range(length))
    return password

# Function to analyze password
def analyze_password(password):
    score = 0
    if len(password) >= 8:
        score += 1
    if any(c.islower() for c in password):
        score += 1
    if any(c.isupper() for c in password):
        score += 1
    if any(c.isdigit() for c in password):
        score += 1
    if any(c in string.punctuation for c in password):
        score += 1

    if score == 5:
        return "Very Strong"
    elif score == 4:
        return "Strong"
    elif score == 3:
        return "Medium"
    else:
        return "Weak"

# Function to handle generate button click
def handle_generate():
    try:
        length = int(length_entry.get())
        if length < 8 or length > 128:
            raise ValueError("Invalid length")
        password = generate_password(length)
        password_entry.config(state=tk.NORMAL)
        password_entry.delete(0, tk.END)
        password_entry.insert(0, password)
        password_entry.config(state='readonly')
        pyperclip.copy(password)
        messagebox.showinfo("Copied", "Password copied to clipboard!")
    except ValueError:
        messagebox.showerror("Error", "Please enter a valid length between 8 and 128")

# Function to handle analyze button click
def handle_analyze():
    password = analyze_entry.get()
    analysis = analyze_password(password)
    analysis_label.config(text=f"Password Strength: {analysis}")

# Set up the main application window
app = tk.Tk()
app.title("Password Generator & Analyzer")
app.geometry("400x400")
app.resizable(False, False)
app.configure(bg="#2e2e2e")

# Password Generator section
tk.Label(app, text="Password Generator", font=("Helvetica", 16), bg="#2e2e2e", fg="#ffffff").pack(pady=10)
tk.Label(app, text="Password Length:", bg="#2e2e2e", fg="#ffffff").pack()
length_entry = tk.Entry(app)
length_entry.pack(pady=5)
length_entry.insert(0, "16")
tk.Button(app, text="Generate Password", command=handle_generate, bg="#4a4a4a", fg="#ffffff").pack(pady=5)
password_entry = tk.Entry(app, state='readonly', width=30)
password_entry.pack(pady=5)

# Password Analyzer section
tk.Label(app, text="Password Analyzer", font=("Helvetica", 16), bg="#2e2e2e", fg="#ffffff").pack(pady=10)
tk.Label(app, text="Analyze Password:", bg="#2e2e2e", fg="#ffffff").pack()
analyze_entry = tk.Entry(app)
analyze_entry.pack(pady=5)
tk.Button(app, text="Analyze Password", command=handle_analyze, bg="#4a4a4a", fg="#ffffff").pack(pady=5)
analysis_label = tk.Label(app, text="Password Strength: ", bg="#2e2e2e", fg="#ffffff")
analysis_label.pack(pady=10)

# Run the application
app.mainloop()
