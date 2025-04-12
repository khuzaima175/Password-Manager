import tkinter as tk
import tkinter.messagebox as messagebox
import customtkinter as ctk
import json
import os
import base64
import secrets
import string
# --- pyperclip Check/Install (Do this ONCE globally) ---
try:
    import pyperclip
except ImportError:
    print("pyperclip library not found. Attempting to install...")
    try:
        import subprocess
        import sys
        subprocess.check_call([sys.executable, "-m", "pip", "install", "pyperclip"])
        print("pyperclip installed successfully.")
        import pyperclip # Try importing again
    except Exception as e:
        print(f"Failed to install pyperclip: {e}")
        print("Clipboard functionality will be unavailable.")
        # Define dummy functions if pyperclip failed to install/import
        class DummyPyperclip:
            def copy(self, text): print("Clipboard unavailable (pyperclip missing).")
            def paste(self): return ""
        pyperclip = DummyPyperclip()
# --- End Global pyperclip Check ---

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


# --- Constants ---
DEFAULT_FILENAME = "passwords.json.enc"
SALT_SIZE = 16
KEY_ITERATIONS = 390000

# --- Encryption/Decryption Functions ---
def derive_key(password: bytes, salt: bytes) -> bytes:
    """Derives a cryptographic key from a password and salt using PBKDF2-HMAC-SHA256."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32, # Use 32 bytes for Fernet key
        salt=salt,
        iterations=KEY_ITERATIONS,
    )
    return base64.urlsafe_b64encode(kdf.derive(password))

def encrypt_data(data: dict, password: str) -> tuple[bytes, bytes]:
    """Encrypts dictionary data using a password-derived key and Fernet."""
    salt = os.urandom(SALT_SIZE)
    key = derive_key(password.encode(), salt)
    f = Fernet(key)
    encrypted_data = f.encrypt(json.dumps(data).encode())
    return salt, encrypted_data

def decrypt_data(salt: bytes, encrypted_data: bytes, password: str) -> dict | None:
    """Decrypts data using a password, salt, and Fernet. Returns None on failure."""
    try:
        key = derive_key(password.encode(), salt)
        f = Fernet(key)
        decrypted_data = f.decrypt(encrypted_data)
        return json.loads(decrypted_data.decode())
    except (InvalidToken, TypeError, ValueError, json.JSONDecodeError, Exception):
        return None

def generate_password(length=16):
    """Generates a strong random password using secrets module."""
    if length <= 0: length = 1
    alphabet = string.ascii_letters + string.digits + string.punctuation
    if not alphabet or length <= 0: return ""
    password = ''.join(secrets.choice(alphabet) for _ in range(length))
    return password

# --- Password Manager Class ---

class PasswordManager:
    """Handles the core logic of storing, retrieving, and saving password data."""
    def __init__(self, filename=DEFAULT_FILENAME):
        self.filename = os.path.abspath(filename)
        self.passwords = {}
        self.master_password = None
        self._data_changed = False

    def set_master_password(self, password: str):
        self.master_password = password

    def mark_changed(self):
        self._data_changed = True

    def has_changed(self):
        return self._data_changed

    def add_password(self, website, username, password):
        """Adds or updates a password entry in memory."""
        website_lower = website.lower().strip()
        if not website_lower: return
        self.passwords[website_lower] = {"username": username.strip(), "password": password}
        self.mark_changed()

    def get_password(self, website):
        """Retrieves password data for a given website (case-insensitive) from memory."""
        return self.passwords.get(website.lower().strip())

    def remove_password(self, website):
        """Removes a password entry from memory. Returns True if successful, False otherwise."""
        website_lower = website.lower().strip()
        if website_lower in self.passwords:
            del self.passwords[website_lower]
            self.mark_changed()
            return True
        return False

    def list_websites(self):
        """Returns a sorted list of website names currently in memory."""
        return sorted(self.passwords.keys())

    def save_to_file(self):
        """Encrypts and saves the current passwords (from memory) to the file."""
        if not self.master_password:
            messagebox.showerror("Error", "Master password not set. Cannot save.")
            return False
        if not self.passwords and os.path.exists(self.filename):
             if not messagebox.askyesno("Confirm Save", "Warning: No passwords loaded.\nSaving now will overwrite the existing file with empty data.\n\nContinue?"):
                 return False

        try:
            salt, encrypted_data = encrypt_data(self.passwords, self.master_password)
            data_to_save = {
                "salt": base64.urlsafe_b64encode(salt).decode('utf-8'),
                "data": base64.urlsafe_b64encode(encrypted_data).decode('utf-8')
            }
            with open(self.filename, "w") as f:
                json.dump(data_to_save, f, indent=4)
            self._data_changed = False
            return True
        except Exception as e:
            messagebox.showerror("Save Error", f"Failed to save data to file:\n{e}")
            return False

    def load_from_file(self, password_attempt: str) -> bool:
        """Loads and decrypts passwords from the file into memory. Returns True on success."""
        if not os.path.exists(self.filename):
            self.set_master_password(password_attempt)
            self.passwords = {}
            self._data_changed = False
            return True

        try:
            with open(self.filename, "r") as f:
                saved_data = json.load(f)

            if "salt" not in saved_data or "data" not in saved_data:
                 raise ValueError("Invalid file format: missing 'salt' or 'data'.")

            salt = base64.urlsafe_b64decode(saved_data["salt"].encode('utf-8'))
            encrypted_data = base64.urlsafe_b64decode(saved_data["data"].encode('utf-8'))
            decrypted_passwords = decrypt_data(salt, encrypted_data, password_attempt)

            if decrypted_passwords is not None:
                self.passwords = decrypted_passwords
                self.set_master_password(password_attempt)
                self._data_changed = False
                return True
            else:
                self.passwords = {}
                self.master_password = None
                messagebox.showerror("Load Error", "Incorrect Master Password or corrupted data file.")
                return False
        except (json.JSONDecodeError, KeyError, FileNotFoundError, ValueError, Exception) as e:
            self.passwords = {}
            self.master_password = None
            messagebox.showerror("Load Error", f"Error reading or parsing file: {e}.\nPlease check the file integrity or master password.")
            return False


# --- GUI Application Class ---

class PasswordManagerApp(ctk.CTk):
    """The main application window for the Password Manager GUI."""
    def __init__(self, password_manager: PasswordManager):
        super().__init__()
        self.pm = password_manager

        self.title("Secure Password Manager")
        self.geometry("800x600")
        ctk.set_appearance_mode("System")
        ctk.set_default_color_theme("blue")

        self._create_widgets()
        self.refresh_website_list()
        self._update_status("Loaded successfully.", "green")

        self.protocol("WM_DELETE_WINDOW", self._on_closing)

    def _create_widgets(self):
        """Creates and arranges all widgets in the main application window."""
        self.grid_columnconfigure(0, weight=1)
        self.grid_columnconfigure(1, weight=2)
        self.grid_rowconfigure(1, weight=1)

        # --- Top Frame for Actions ---
        self.top_frame = ctk.CTkFrame(self, height=50)
        self.top_frame.grid(row=0, column=0, columnspan=2, sticky="ew", padx=10, pady=(10, 0))

        self.add_button = ctk.CTkButton(self.top_frame, text="Add New", command=self._add_password_dialog)
        self.add_button.pack(side=tk.LEFT, padx=5, pady=5)

        self.save_button = ctk.CTkButton(self.top_frame, text="Save Changes", command=self._save_data)
        self.save_button.pack(side=tk.LEFT, padx=5, pady=5)

        self.generate_button = ctk.CTkButton(self.top_frame, text="Generate Password", command=self._generate_password_dialog)
        self.generate_button.pack(side=tk.LEFT, padx=5, pady=5)

        self.change_master_button = ctk.CTkButton(self.top_frame, text="Change Master PW", command=self._change_master_password_dialog)
        self.change_master_button.pack(side=tk.LEFT, padx=5, pady=5)

        self.status_label = ctk.CTkLabel(self.top_frame, text="", text_color="gray")
        self.status_label.pack(side=tk.RIGHT, padx=10, pady=5)


        # --- Left Frame for Website List ---
        self.left_frame = ctk.CTkFrame(self)
        self.left_frame.grid(row=1, column=0, sticky="nsew", padx=(10, 5), pady=10)
        self.left_frame.grid_rowconfigure(1, weight=1)
        self.left_frame.grid_columnconfigure(0, weight=1)

        self.search_var = tk.StringVar()
        self.search_var.trace_add("write", lambda *args: self.refresh_website_list())
        self.search_entry = ctk.CTkEntry(self.left_frame, placeholder_text="Search websites...", textvariable=self.search_var)
        self.search_entry.grid(row=0, column=0, sticky="ew", padx=5, pady=5)

        self.website_listbox = tk.Listbox(self.left_frame, selectmode=tk.SINGLE, borderwidth=1, relief="sunken", highlightthickness=1, font=("Segoe UI", 11), exportselection=False)
        self.website_listbox.grid(row=1, column=0, sticky="nsew", padx=5, pady=(0, 5))
        self.website_listbox.bind("<<ListboxSelect>>", self._on_website_select)

        self.list_scrollbar = ctk.CTkScrollbar(self.left_frame, command=self.website_listbox.yview)
        self.list_scrollbar.grid(row=1, column=1, sticky="ns", pady=(0,5))
        self.website_listbox.configure(yscrollcommand=self.list_scrollbar.set)

        # --- Right Frame for Details (Read-Only Display) ---
        self.right_frame = ctk.CTkFrame(self)
        self.right_frame.grid(row=1, column=1, sticky="nsew", padx=(5, 10), pady=10)
        self.right_frame.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(self.right_frame, text="Website:").grid(row=0, column=0, sticky="w", padx=10, pady=5)
        ctk.CTkLabel(self.right_frame, text="Username:").grid(row=1, column=0, sticky="w", padx=10, pady=5)
        ctk.CTkLabel(self.right_frame, text="Password:").grid(row=2, column=0, sticky="w", padx=10, pady=5)

        self.website_entry_var = tk.StringVar()
        self.website_entry = ctk.CTkEntry(self.right_frame, textvariable=self.website_entry_var, state='readonly')
        self.website_entry.grid(row=0, column=1, sticky="ew", padx=10, pady=5)

        self.username_entry_var = tk.StringVar()
        self.username_entry = ctk.CTkEntry(self.right_frame, textvariable=self.username_entry_var, state='readonly')
        self.username_entry.grid(row=1, column=1, sticky="ew", padx=10, pady=5)

        self.password_entry_var = tk.StringVar()
        self.password_entry = ctk.CTkEntry(self.right_frame, textvariable=self.password_entry_var, state='readonly', show='*')
        self.password_entry.grid(row=2, column=1, sticky="ew", padx=10, pady=5)

        self.button_frame = ctk.CTkFrame(self.right_frame, fg_color="transparent")
        self.button_frame.grid(row=3, column=0, columnspan=2, pady=10)

        self.show_pw_button = ctk.CTkButton(self.button_frame, text="Show", width=60, command=self._toggle_password_visibility, state=tk.DISABLED)
        self.show_pw_button.pack(side=tk.LEFT, padx=5)

        self.copy_user_button = ctk.CTkButton(self.button_frame, text="Copy User", width=90, command=self._copy_username, state=tk.DISABLED)
        self.copy_user_button.pack(side=tk.LEFT, padx=5)

        self.copy_pw_button = ctk.CTkButton(self.button_frame, text="Copy PW", width=90, command=self._copy_password, state=tk.DISABLED)
        self.copy_pw_button.pack(side=tk.LEFT, padx=5)

        self.delete_button = ctk.CTkButton(self.button_frame, text="Delete", fg_color="#D32F2F", hover_color="#B71C1C", command=self._delete_password, state=tk.DISABLED)
        self.delete_button.pack(side=tk.LEFT, padx=5)

    # <<< Method INDENTED correctly inside the class >>>
    def _on_website_select(self, event=None):
        """Handles selection changes in the listbox. Populates detail fields directly."""
        selection = self.website_listbox.curselection()

        if not selection:
            self._clear_details()
            return

        try:
            selected_index = selection[0]
            selected_website_display = self.website_listbox.get(selected_index)
            selected_website_key = selected_website_display.lower()

            data = self.pm.get_password(selected_website_key)

            if data:
                # --- Direct Widget Manipulation START ---
                try:
                    # Temporarily make widgets normal to insert text
                    self.website_entry.configure(state=tk.NORMAL)
                    self.username_entry.configure(state=tk.NORMAL)
                    self.password_entry.configure(state=tk.NORMAL)

                    # Delete existing content and insert new content
                    self.website_entry.delete(0, tk.END)
                    self.website_entry.insert(0, selected_website_display)

                    self.username_entry.delete(0, tk.END)
                    self.username_entry.insert(0, data["username"])

                    self.password_entry.delete(0, tk.END)
                    self.password_entry.insert(0, data["password"])

                    # Set back to read-only and ensure password hidden initially
                    self.website_entry.configure(state='readonly')
                    self.username_entry.configure(state='readonly')
                    self.password_entry.configure(state='readonly', show='*')

                except Exception as e_direct:
                    print(f"ERROR during DIRECT widget update: {e_direct}") # Keep error prints
                # --- Direct Widget Manipulation END ---

                # --- Also set StringVars (Good practice, might be needed elsewhere) ---
                self.website_entry_var.set(selected_website_display)
                self.username_entry_var.set(data["username"])
                self.password_entry_var.set(data["password"])
                # --------------------------------------------------------------------

                # Reset password visibility state for button
                self.show_pw_button.configure(text="Show", state=tk.NORMAL)

                # Enable other buttons
                self.copy_user_button.configure(state=tk.NORMAL)
                self.copy_pw_button.configure(state=tk.NORMAL)
                self.delete_button.configure(state=tk.NORMAL)
            else:
                self._clear_details()

        except tk.TclError as e:
             self._clear_details()
        except Exception as e:
            print(f"Unexpected error in _on_website_select: {e}") # Keep error prints
            import traceback
            traceback.print_exc()
            self._clear_details()

    def _clear_details(self):
        """Clears the detail entry fields and disables associated buttons."""
        self.website_entry_var.set("")
        self.username_entry_var.set("")
        self.password_entry_var.set("")

        # Also clear the widgets directly if necessary (though StringVars should handle it)
        try:
            self.website_entry.configure(state=tk.NORMAL)
            self.username_entry.configure(state=tk.NORMAL)
            self.password_entry.configure(state=tk.NORMAL)
            self.website_entry.delete(0, tk.END)
            self.username_entry.delete(0, tk.END)
            self.password_entry.delete(0, tk.END)
            self.website_entry.configure(state='readonly')
            self.username_entry.configure(state='readonly')
            self.password_entry.configure(state='readonly', show='*')
        except Exception: pass # Ignore errors if widgets don't exist yet

        self.password_entry.configure(show='*')
        self.show_pw_button.configure(text="Show", state=tk.DISABLED)
        self.copy_user_button.configure(state=tk.DISABLED)
        self.copy_pw_button.configure(state=tk.DISABLED)
        self.delete_button.configure(state=tk.DISABLED)

    def _update_status(self, message, color="gray"):
        """Updates the status bar label and Save button appearance."""
        self.status_label.configure(text=message, text_color=color)
        if self.pm.has_changed():
            self.title("Secure Password Manager *")
            try:
                unsaved_color = ("#FFA000", "#FF8F00")
            except:
                 unsaved_color = "#FFA000"
            self.save_button.configure(fg_color=unsaved_color, text="Save Changes*")
        else:
            self.title("Secure Password Manager")
            try:
                default_color = ctk.ThemeManager.theme["CTkButton"]["fg_color"]
            except:
                 default_color = None
            self.save_button.configure(fg_color=default_color, text="Save Changes")

    def refresh_website_list(self):
        """Clears and repopulates the website listbox, applying search filter and attempting to re-select."""
        search_term = self.search_var.get().lower()
        current_selection_index = self.website_listbox.curselection()
        selected_website_key = None
        if current_selection_index:
            try:
                selected_website_key = self.website_listbox.get(current_selection_index[0]).lower()
            except tk.TclError:
                selected_website_key = None

        self.website_listbox.delete(0, tk.END)
        websites = self.pm.list_websites()
        new_index_to_select = None
        current_display_index = 0
        for site in websites:
            if search_term in site:
                display_site = site.capitalize()
                self.website_listbox.insert(tk.END, display_site)
                if selected_website_key and site == selected_website_key:
                    new_index_to_select = current_display_index
                current_display_index += 1

        if new_index_to_select is not None:
            try:
                self.website_listbox.selection_set(new_index_to_select)
                self.website_listbox.activate(new_index_to_select)
                self.website_listbox.see(new_index_to_select)
                # Don't automatically call _on_website_select here,
                # let the user click explicitly or the bind event handle it.
                # self._on_website_select()
            except tk.TclError:
                self._clear_details()
        else:
            self._clear_details()

    def _toggle_password_visibility(self):
        """Toggles the password field between hidden ('*') and visible ('')."""
        if self.password_entry.cget('show') == '*':
            self.password_entry.configure(show='')
            self.show_pw_button.configure(text="Hide")
        else:
            self.password_entry.configure(show='*')
            self.show_pw_button.configure(text="Show")

    def _copy_username(self):
        """Copies the username (from display variable) to the clipboard."""
        username = self.username_entry_var.get()
        if username:
            try:
                pyperclip.copy(username)
                self._update_status("Username copied to clipboard.", "blue")
            except Exception as e:
                 self._update_status(f"Clipboard error: {e}", "orange")
                 messagebox.showwarning("Clipboard Error", f"Could not copy to clipboard:\n{e}")

    def _copy_password(self):
        """Copies the actual password (from display variable) to the clipboard."""
        password = self.password_entry_var.get()
        if password:
            try:
                pyperclip.copy(password)
                self._update_status("Password copied to clipboard.", "blue")
            except Exception as e:
                 self._update_status(f"Clipboard error: {e}", "orange")
                 messagebox.showwarning("Clipboard Error", f"Could not copy to clipboard:\n{e}")

    def _delete_password(self):
        """Deletes the selected password from memory after confirmation."""
        selection = self.website_listbox.curselection()
        if not selection: return

        selected_index = selection[0]
        try:
            website_display = self.website_listbox.get(selected_index)
            website_key = website_display.lower()

            if messagebox.askyesno("Confirm Deletion", f"Are you sure you want to delete the entry for '{website_display}'?"):
                if self.pm.remove_password(website_key):
                    self.refresh_website_list()
                    status_message = f"Deleted '{website_display}'. Click 'Save Changes*' to make permanent."
                    self._update_status(status_message, "orange")
                    messagebox.showinfo("Remember to Save", status_message, parent=self)
                else:
                    self._update_status(f"Failed to delete '{website_display}'.", "red")
                    messagebox.showerror("Error", f"Could not find or delete entry for '{website_display}'.")
        except tk.TclError:
             return

    def _save_data(self):
        """Saves the current password data (from memory) to the encrypted file."""
        if self.pm.save_to_file():
            self._update_status(f"Data saved to {os.path.basename(self.pm.filename)}", "green")

    def _on_closing(self):
        """Handles the window close event, prompting to save if needed."""
        if self.pm.has_changed():
            if messagebox.askyesno("Unsaved Changes", "You have unsaved changes. Do you want to save before exiting?"):
                if not self._save_data():
                    return
        self.destroy()

    # --- Dialog Functions ---

    def _add_password_dialog(self):
        """Opens a dialog to add a NEW password."""
        try:
            self.website_listbox.selection_clear(0, tk.END)
        except tk.TclError: pass
        self._clear_details()

        dialog = ctk.CTkToplevel(self)
        dialog.title("Add New Password")
        dialog.geometry("450x250")
        dialog.transient(self)
        dialog.grab_set()
        dialog.resizable(False, False)
        dialog.after(100, dialog.lift)

        dialog.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(dialog, text="Website:").grid(row=0, column=0, padx=10, pady=10, sticky="w")
        website_entry = ctk.CTkEntry(dialog, state=tk.NORMAL)
        website_entry.grid(row=0, column=1, columnspan=2, padx=10, pady=10, sticky="ew")

        ctk.CTkLabel(dialog, text="Username:").grid(row=1, column=0, padx=10, pady=10, sticky="w")
        username_entry = ctk.CTkEntry(dialog)
        username_entry.grid(row=1, column=1, columnspan=2, padx=10, pady=10, sticky="ew")

        ctk.CTkLabel(dialog, text="Password:").grid(row=2, column=0, padx=10, pady=10, sticky="w")
        password_entry = ctk.CTkEntry(dialog, show="*")
        password_entry.grid(row=2, column=1, padx=(10, 0), pady=10, sticky="ew")

        pw_button_frame = ctk.CTkFrame(dialog, fg_color="transparent")
        pw_button_frame.grid(row=2, column=2, padx=(5, 10), pady=10, sticky="e")

        def toggle_pw():
             if password_entry.cget('show') == '*': password_entry.configure(show='')
             else: password_entry.configure(show='*')
        show_button = ctk.CTkButton(pw_button_frame, text="👁", command=toggle_pw, width=30)
        show_button.pack(side=tk.LEFT, padx=(0, 5))

        def generate_and_fill():
             pw = generate_password()
             password_entry.delete(0, tk.END)
             password_entry.insert(0, pw)
        gen_button = ctk.CTkButton(pw_button_frame, text="Gen", command=generate_and_fill, width=50)
        gen_button.pack(side=tk.LEFT)

        is_editing = False # Always False for this button action

        button_frame = ctk.CTkFrame(dialog, fg_color="transparent")
        button_frame.grid(row=3, column=0, columnspan=3, pady=20)

        def save_entry():
            website = website_entry.get().strip()
            username = username_entry.get().strip()
            password = password_entry.get()

            if not website:
                messagebox.showerror("Error", "Website name cannot be empty.", parent=dialog)
                return
            if not password:
                 if not messagebox.askyesno("Confirm", "Password field is empty. Save anyway?", parent=dialog):
                     return

            self.pm.add_password(website, username, password)
            website_key_to_select = website.lower()

            self.refresh_website_list()

            try:
                 all_items_lower = list(map(str.lower, self.website_listbox.get(0, tk.END)))
                 idx = all_items_lower.index(website_key_to_select)
                 if 0 <= idx < self.website_listbox.size():
                     self.website_listbox.selection_clear(0, tk.END)
                     self.website_listbox.selection_set(idx)
                     self.website_listbox.activate(idx)
                     self.website_listbox.see(idx)
                     self._on_website_select()
                 else: self._clear_details()
            except ValueError: self._clear_details()
            except tk.TclError: self._clear_details()

            action = "Added"
            status_message = f"{action} '{website.capitalize()}'. Click 'Save Changes*' to make permanent."
            self._update_status(status_message, "orange")

            messagebox.showinfo("Remember to Save",
                                f"Entry for '{website.capitalize()}' added in memory.\n\nPlease click the main 'Save Changes*' button to save permanently to the file.",
                                parent=self)

            dialog.destroy()

        save_btn = ctk.CTkButton(button_frame, text="Save", command=save_entry)
        save_btn.pack(side=tk.LEFT, padx=10)

        cancel_btn = ctk.CTkButton(button_frame, text="Cancel", command=dialog.destroy, fg_color="gray")
        cancel_btn.pack(side=tk.LEFT, padx=10)

        website_entry.focus_set()

    def _generate_password_dialog(self):
        """Shows a dialog to generate a password and copies it."""
        length_dialog = ctk.CTkInputDialog(text="Enter desired password length (e.g., 16):", title="Generate Password")
        length_dialog.geometry("300x150")

        entry_widget = None
        try:
            potential_entry = length_dialog.winfo_children()[1]
            if isinstance(potential_entry, ctk.CTkEntry): entry_widget = potential_entry
            elif isinstance(potential_entry, ctk.CTkFrame):
                 for sub_widget in potential_entry.winfo_children():
                     if isinstance(sub_widget, ctk.CTkEntry):
                         entry_widget = sub_widget; break
        except IndexError: pass

        if not entry_widget:
            messagebox.showerror("Error", "Could not find input field in dialog.")
            return

        def validate_numeric(P): return P.isdigit() or P == ""
        validate_cmd = (self.register(validate_numeric), '%P')
        entry_widget.configure(validate="key", validatecommand=validate_cmd)
        entry_widget.delete(0, tk.END)
        entry_widget.insert(0, "16")

        result = length_dialog.get_input()

        if result:
            try:
                length = int(result)
                if length <= 0: raise ValueError("Length must be positive")
                pw = generate_password(length)

                show_pw_dialog = ctk.CTkToplevel(self)
                show_pw_dialog.title("Generated Password")
                show_pw_dialog.geometry("350x150")
                show_pw_dialog.transient(self)
                show_pw_dialog.grab_set()
                show_pw_dialog.resizable(False, False)
                show_pw_dialog.after(100, show_pw_dialog.lift)

                pw_textbox = ctk.CTkTextbox(show_pw_dialog, height=40, activate_scrollbars=False)
                pw_textbox.pack(padx=20, pady=10, fill="x")
                pw_textbox.insert("1.0", pw)
                pw_textbox.configure(state="disabled")

                button_frame = ctk.CTkFrame(show_pw_dialog, fg_color="transparent")
                button_frame.pack(pady=10)

                def copy_and_close():
                    try:
                        pyperclip.copy(pw)
                        self._update_status("Generated password copied.", "blue")
                    except Exception as clip_err:
                        messagebox.showwarning("Clipboard Error", f"Could not copy to clipboard:\n{clip_err}", parent=show_pw_dialog)
                        self._update_status("Generated password (clipboard error).", "orange")
                    show_pw_dialog.destroy()

                copy_button = ctk.CTkButton(button_frame, text="Copy to Clipboard & Close", command=copy_and_close)
                copy_button.pack(padx=5)

            except ValueError:
                messagebox.showerror("Error", "Invalid length specified. Please enter a positive number.", parent=self)
                self._update_status("Invalid length for generation.", "red")
        else:
             self._update_status("Password generation cancelled.", "gray")

    def _change_master_password_dialog(self):
        """Dialog to change the master password (updates in memory only)."""
        dialog = ctk.CTkToplevel(self)
        dialog.title("Change Master Password")
        dialog.geometry("400x270")
        dialog.transient(self)
        dialog.grab_set()
        dialog.resizable(False, False)
        dialog.after(100, dialog.lift)

        dialog.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(dialog, text="Current Master PW:").grid(row=0, column=0, padx=10, pady=10, sticky="w")
        current_pw_entry = ctk.CTkEntry(dialog, show="*")
        current_pw_entry.grid(row=0, column=1, padx=10, pady=10, sticky="ew")

        ctk.CTkLabel(dialog, text="New Master PW:").grid(row=1, column=0, padx=10, pady=10, sticky="w")
        new_pw_entry = ctk.CTkEntry(dialog, show="*")
        new_pw_entry.grid(row=1, column=1, padx=10, pady=10, sticky="ew")

        ctk.CTkLabel(dialog, text="Confirm New PW:").grid(row=2, column=0, padx=10, pady=10, sticky="w")
        confirm_pw_entry = ctk.CTkEntry(dialog, show="*")
        confirm_pw_entry.grid(row=2, column=1, padx=10, pady=10, sticky="ew")

        info_label = ctk.CTkLabel(dialog, text="Changes require saving the file afterwards using the main 'Save Changes*' button.", text_color="gray", wraplength=380)
        info_label.grid(row=3, column=0, columnspan=2, padx=10, pady=5)

        button_frame = ctk.CTkFrame(dialog, fg_color="transparent")
        button_frame.grid(row=4, column=0, columnspan=2, pady=15)

        def process_change():
            current_pw = current_pw_entry.get()
            new_pw = new_pw_entry.get()
            confirm_pw = confirm_pw_entry.get()

            if not current_pw or not new_pw or not confirm_pw:
                messagebox.showerror("Error", "All fields are required.", parent=dialog); return
            if new_pw != confirm_pw:
                messagebox.showerror("Error", "New passwords do not match.", parent=dialog); confirm_pw_entry.delete(0, tk.END); confirm_pw_entry.focus_set(); return
            if current_pw == new_pw:
                messagebox.showerror("Error", "New password cannot be the same as the current one.", parent=dialog); new_pw_entry.delete(0, tk.END); confirm_pw_entry.delete(0, tk.END); new_pw_entry.focus_set(); return
            if self.pm.master_password != current_pw:
                 messagebox.showerror("Error", "Incorrect current master password.", parent=dialog); current_pw_entry.delete(0, tk.END); current_pw_entry.focus_set(); return

            self.pm.set_master_password(new_pw)
            self.pm.mark_changed()

            status_message = "Master PW updated in memory! Click 'Save Changes*' to make permanent."
            self._update_status(status_message, "orange")
            messagebox.showinfo("Success & IMPORTANT", status_message, parent=self)
            dialog.destroy()

        change_btn = ctk.CTkButton(button_frame, text="Change Password", command=process_change)
        change_btn.pack(side=tk.LEFT, padx=10)

        cancel_btn = ctk.CTkButton(button_frame, text="Cancel", command=dialog.destroy, fg_color="gray")
        cancel_btn.pack(side=tk.LEFT, padx=10)

        current_pw_entry.focus_set()

# --- Login/Initialization Screen ---

class LoginScreen(ctk.CTkToplevel):
    """Handles the initial login or master password creation dialog."""
    def __init__(self, parent, pm: PasswordManager, file_exists: bool):
        super().__init__(parent)
        self.pm = pm
        self.file_exists = file_exists
        self.parent = parent
        self.result_password = None
        self.success = False

        self.title("Login" if file_exists else "Create Master Password")
        self.geometry("350x250" if not file_exists else "350x200")
        self.transient(parent)
        self.grab_set()
        self.protocol("WM_DELETE_WINDOW", self._cancel_login)
        self.resizable(False, False)

        self.grid_columnconfigure(0, weight=1)

        prompt_text = f"Enter Master Password for\n'{os.path.basename(self.pm.filename)}':" if file_exists else "Create a NEW Master Password:"
        self.prompt_label = ctk.CTkLabel(self, text=prompt_text, wraplength=300)
        self.prompt_label.grid(row=0, column=0, padx=20, pady=(20, 10))

        self.password_entry = ctk.CTkEntry(self, show="*", width=250)
        self.password_entry.grid(row=1, column=0, padx=20, pady=5)
        self.password_entry.bind("<Return>", self._submit)

        if not file_exists:
            self.confirm_label = ctk.CTkLabel(self, text="Confirm New Password:")
            self.confirm_label.grid(row=2, column=0, padx=20, pady=(10, 0), sticky="w")
            self.confirm_entry = ctk.CTkEntry(self, show="*", width=250)
            self.confirm_entry.grid(row=3, column=0, padx=20, pady=5)
            self.confirm_entry.bind("<Return>", self._submit)
            submit_row = 5
        else:
            self.confirm_entry = None
            submit_row = 4

        self.submit_button = ctk.CTkButton(self, text="Login" if file_exists else "Create", command=self._submit)
        self.submit_button.grid(row=submit_row, column=0, padx=20, pady=20)

        self.after(50, self.lift)
        self.after(100, self.password_entry.focus_set)

    def _submit(self, event=None):
        """Handles the submission of the login or creation form."""
        password = self.password_entry.get()

        if not password:
            messagebox.showerror("Error", "Password cannot be empty.", parent=self)
            self.password_entry.focus_set()
            return

        if self.file_exists:
            if self.pm.load_from_file(password):
                self.result_password = password
                self.success = True
                self.destroy()
            else:
                self.password_entry.delete(0, tk.END)
                self.password_entry.focus_set()
        else:
            confirm_password = self.confirm_entry.get()
            if not confirm_password:
                 messagebox.showerror("Error", "Please confirm the password.", parent=self)
                 self.confirm_entry.focus_set(); return
            if password != confirm_password:
                messagebox.showerror("Error", "Passwords do not match.", parent=self)
                self.confirm_entry.delete(0, tk.END); self.confirm_entry.focus_set(); return

            if self.pm.load_from_file(password):
                self.result_password = password
                self.success = True
                messagebox.showinfo("Setup Complete", "Master Password created.\nRemember it!", parent=self.parent)
                self.destroy()
            else:
                 messagebox.showerror("Error", "Failed to initialize password manager.", parent=self)

    def _cancel_login(self):
        """Called when the login window is closed manually by the user."""
        print("Login/Creation cancelled by user.")
        self.success = False
        self.destroy()


# --- Main Execution ---

def main():
    """Main function to initialize and run the application."""
    root = ctk.CTk()
    root.withdraw()

    filename_dialog = ctk.CTkInputDialog(text="Enter data file name or leave blank for default:", title="Password File")
    filename_dialog.geometry("400x180")

    entry_widget = None
    try:
        potential_entry = filename_dialog.winfo_children()[1]
        if isinstance(potential_entry, ctk.CTkEntry): entry_widget = potential_entry
        elif isinstance(potential_entry, ctk.CTkFrame):
             for sub_widget in potential_entry.winfo_children():
                 if isinstance(sub_widget, ctk.CTkEntry): entry_widget = sub_widget; break
    except IndexError: pass

    if entry_widget and isinstance(entry_widget, ctk.CTkEntry):
        entry_widget.delete(0, tk.END)
        entry_widget.insert(0, DEFAULT_FILENAME)
    else:
        print("Warning: Could not reliably find input dialog entry to pre-fill default.")

    filename = filename_dialog.get_input()

    if filename is None:
        print("Filename selection cancelled. Exiting.")
        root.destroy(); return

    if filename is not None and filename.strip() == "":
        filename = DEFAULT_FILENAME
        print(f"Using default filename: {filename}")


    pm = PasswordManager(filename=filename)
    file_exists = os.path.exists(pm.filename)

    login = LoginScreen(root, pm, file_exists)
    root.wait_window(login)

    if login.success and pm.master_password is not None:
        print("Login successful. Starting main application...")
        app = PasswordManagerApp(pm)
        app.mainloop()
        print("Application closed.")
    else:
        print("Login cancelled or failed. Exiting.")
        root.destroy()


if __name__ == "__main__":
    main()
