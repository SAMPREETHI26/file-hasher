import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from PIL import Image, ImageTk
import sqlite3
import hashlib
import os
import subprocess
from algorithmss import *
file_list = []  # List to store file paths
file_listbox = None  # Listbox to display file list
algorithm_var = None  # Variable to store the selected algorithm
root = None  # Variable to store the main Tkinter window

# Create or connect to the SQLite database
conn = sqlite3.connect('hash_database.db')
c = conn.cursor()

# Create the table if it doesn't exist
c.execute('''CREATE TABLE IF NOT EXISTS hash_values
             (id INTEGER PRIMARY KEY AUTOINCREMENT, filename TEXT, file_location TEXT, md5_hash TEXT, sha256_hash TEXT,integrity_status TEXT)''')
conn.commit()

def add_file():
    file_path = filedialog.askopenfilename()
    if file_path:
        file_list.append(file_path)
        update_file_listbox()
        if len(file_list) == 1 and file_path.lower().endswith(('.png', '.jpg', '.jpeg', '.gif', '.bmp')):  
            display_exif(file_path)  # Display Exif data when a single image file is added

def check_metadata():
    selected_index = file_listbox.curselection()
    if selected_index:
        file_path = file_list[selected_index[0]]
        if file_path.lower().endswith(('.png', '.jpg', '.jpeg', '.gif', '.bmp')):
            display_exif(file_path)
        else:
            messagebox.showinfo("Metadata", "Metadata cannot be displayed for non-image files.")

def delete_file():
    global file_listbox
    selected_index = file_listbox.curselection()
    if selected_index:
        file_list.pop(selected_index[0])
        update_file_listbox()

def update_file_listbox():
    global file_listbox
    file_listbox.delete(0, tk.END)
    for file_path in file_list:
        file_listbox.insert(tk.END, file_path)

def generate_hashes(algorithm):
    if not file_list:
        messagebox.showwarning("No Files", "Please add files before generating hashes.")
        return None  # Return None if no files are added

    output_file = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text Files", "*.txt")])
    if not output_file:
        return None  # Return None if no output file is selected

    with open(output_file, 'w') as hash_file:
        hash_file.write("Hash Results:\n")
        for file_path in file_list:
            with open(file_path, 'rb') as file:
                data = file.read()
                hash_value = calculate_hash(data, algorithm)
                hash_file.write(f"File: {file_path}, Hash: {hash_value}\n")

    messagebox.showinfo("Hashes Generated", f"Hashes generated successfully and saved to {output_file}")
    return output_file  

def view_hashes():
    output_file = generate_hashes(algorithm_var.get())
    if output_file:
        try:
            with open(output_file, 'r') as hash_file:
                hash_content = hash_file.read()
                messagebox.showinfo("Generated Hash Results", hash_content)
        except FileNotFoundError:
            messagebox.showwarning("File Not Found", "No hash results file found.")
    else:
        messagebox.showwarning("No Hash File", "No hash file generated to view.")

def detect_collision(algorithm, data1, data2):
    if algorithm == "md5":
        return detect_collision_md5(data1, data2)
    elif algorithm == "sha1":
        return detect_collision_sha1(data1, data2)
    elif algorithm == "sha224":
        return detect_collision_sha224(data1, data2)
    elif algorithm == "sha256":
        return detect_collision_sha256(data1, data2)
    elif algorithm == "sha384":
        return detect_collision_sha384(data1, data2)
    elif algorithm == "sha512":
        return detect_collision_sha512(data1, data2)
    elif algorithm == "sha3_224":
        return detect_collision_sha3_224(data1, data2)
    elif algorithm == "sha3_256":
        return detect_collision_sha3_256(data1, data2)
    elif algorithm == "sha3_384":
        return detect_collision_sha3_384(data1, data2)
    elif algorithm == "sha3_512":
        return detect_collision_sha3_512(data1, data2)
    elif algorithm == "blake2b":
        return detect_collision_blake2b(data1, data2)
    elif algorithm == "blake2s":
        return detect_collision_blake2s(data1, data2)
    elif algorithm == "ripemd160":
        return detect_collision_ripemd160(data1, data2)
    else:
        raise ValueError("Unsupported hashing algorithm")

def check_collision(algorithm):
    if len(file_list) < 2:
        messagebox.showwarning("Insufficient Files", "Please add at least two files for collision detection.")
        return

    collisions = []
    for i in range(len(file_list)):
        for j in range(i+1, len(file_list)):
            with open(file_list[i], 'rb') as file1, open(file_list[j], 'rb') as file2:
                data1 = file1.read()
                data2 = file2.read()

                if detect_collision(algorithm, data1, data2):
                    collisions.append((file_list[i], file_list[j]))

    if collisions:
        messagebox.showinfo("Collisions Detected", f"Collisions detected between the following files: {collisions}")
    else:
        messagebox.showinfo("No Collisions", "No collisions detected among the added files.")

def open_verify_window():
    if len(file_list) != 1:
        messagebox.showwarning("Invalid Input", "You can only verify a single file at once.")
        return
    verify_window = tk.Toplevel(root)
    verify_window.title("Verify File")
    verify_window.grab_set()  # Make the verify window modal

    file_path = file_list[0]
    generate_hash_for_single_file(file_path, verify_window)

def generate_hash_for_single_file(file_path, window):
    with open(file_path, 'rb') as file:
        data = file.read()

        # Generate MD5 hash
        md5_hash = hashlib.md5(data).hexdigest()

        # Generate SHA-256 hash
        sha256_hash = hashlib.sha256(data).hexdigest()

        # Get the filename and file location
        filename = os.path.basename(file_path)
        file_location = os.path.dirname(file_path)

        # Check the integrity status
        c.execute("SELECT md5_hash, sha256_hash FROM hash_values WHERE file_location=? AND filename=?", (file_location, filename))
        stored_hashes = c.fetchone()
        integrity_status = ""
        if stored_hashes:
            stored_md5_hash, stored_sha256_hash = stored_hashes
            if md5_hash == stored_md5_hash and sha256_hash == stored_sha256_hash:
                integrity_status = "Verified"
            else:
                integrity_status = "Verification Failed"
        else:
            integrity_status = "No stored hashes found"

        # Store the hash values and integrity status in the database
        c.execute("INSERT INTO hash_values (filename, file_location, md5_hash, sha256_hash, integrity_status) VALUES (?, ?, ?, ?, ?)",
                  (filename, file_location, md5_hash, sha256_hash, integrity_status))
        conn.commit()

        # Display the hash values and file integrity status in the window
        message = f"Filename: {filename}\nFile Location: {file_location}\n\nMD5 Hash: {md5_hash}\nSHA-256 Hash: {sha256_hash}\nIntegrity: {integrity_status}"
        messagebox.showinfo("Hash Values", message, parent=window)

def extract_exif(file_path):
    # Construct the command to run ExifTool
    exiftool_cmd = ["ExifRead.exe", file_path]

    try:
        # Run ExifTool and capture the output
        output = subprocess.check_output(exiftool_cmd, stderr=subprocess.STDOUT)

        # Decode the output from bytes to string and return
        return output.decode("utf-8")

    except subprocess.CalledProcessError as e:
        print("Error while executing ExifTool command:", e)
        return None

def display_exif(file_path):
    try:
        exif_data = extract_exif(file_path)
        messagebox.showinfo("Exif Data", exif_data)
    except Exception as e:
        messagebox.showerror("Error", str(e))

def check_collision_wrapper():
    selected_algorithm = algorithm_var.get()
    check_collision(selected_algorithm)

def check_collision_gui():
    global file_listbox, algorithm_var, root

    root = tk.Tk()
    root.title("Hash Collision Detector")
    screen_width = root.winfo_screenwidth()
    screen_height = root.winfo_screenheight()
    root.geometry(f"{screen_width}x{screen_height}")

    main_frame = ttk.Frame(root, padding="20")
    main_frame.pack()

    # Set background image
    img = Image.open("image.jpg")  
    img = img.resize((screen_width, screen_height), Image.ANTIALIAS)
    img = ImageTk.PhotoImage(img)
    canvas = tk.Canvas(root, width=screen_width, height=screen_height)
    canvas.pack(fill="both", expand=True)
    canvas.create_image(0, 0, image=img, anchor="nw")

    add_button = ttk.Button(main_frame, text="Add File", command=add_file)
    add_button.grid(row=0, column=0, padx=5, pady=5, sticky="ew")

    delete_button = ttk.Button(main_frame, text="Delete File", command=delete_file)
    delete_button.grid(row=1, column=0, padx=5, pady=5, sticky="ew")

    file_listbox = tk.Listbox(main_frame, selectmode=tk.SINGLE)
    file_listbox.grid(row=0, column=1, rowspan=2, padx=5, pady=5, sticky="nsew")

    scrollbar = ttk.Scrollbar(main_frame, orient=tk.VERTICAL, command=file_listbox.yview)
    scrollbar.grid(row=0, column=2, rowspan=2, sticky="ns")
    file_listbox.config(yscrollcommand=scrollbar.set)

    algorithm_label = ttk.Label(main_frame, text="Select Algorithm:")
    algorithm_label.grid(row=2, column=0, padx=5, pady=5)

    algorithm_var = tk.StringVar(root)
    algorithm_var.set("md5")  # Default algorithm

    algorithm_menu = ttk.Combobox(main_frame, textvariable=algorithm_var, values=["md5", "sha1", "sha224", "sha256", "sha384", "sha512", "sha3_224", "sha3_256", "sha3_384", "sha3_512", "blake2b", "blake2s", "ripemd160"])
    algorithm_menu.grid(row=2, column=1, padx=5, pady=5)

    view_button = ttk.Button(main_frame, text="Generate and View Hashes", command=view_hashes)
    view_button.grid(row=4, column=0, padx=5, pady=5, columnspan=2, sticky="ew")

    check_button = ttk.Button(main_frame, text="Check Collision", command=check_collision_wrapper)
    check_button.grid(row=5, column=0, padx=5, pady=5, columnspan=2, sticky="ew")

    verify_button = ttk.Button(main_frame, text="Verify File", command=open_verify_window)
    verify_button.grid(row=6, column=0, padx=5, pady=5, columnspan=2, sticky="ew")


    root.mainloop()

if __name__ == "__main__":
    check_collision_gui()
