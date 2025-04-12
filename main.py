import tkinter as tk
import tkinter.messagebox as messagebox
import customtkinter as ctk
import json
import os
import base64
import secrets
import string
import pyperclip
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import subprocess
import sys


# --- Constants ---
DEFAULT_FILENAME = "passwords.json.enc"
SALT_SIZE = 16
KEY_ITERATIONS = 390000

# --- Encryption/Decryption Functions (Identical to previous version) ---


def derive_key(password: bytes, salt: bytes) -> bytes:
    """Derives a cryptographic key from a password and salt."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=KEY_ITERATIONS,
    )
    return base64.urlsafe_b64encode(kdf.derive(password))


def encrypt_data(data: dict, password: str) -> tuple[bytes, bytes]:
    """Encrypts dictionary data using a password."""
    salt = os.urandom(SALT_SIZE)
    key = derive_key(password.encode(), salt)
    f = Fernet(key)
    encrypted_data = f.encrypt(json.dumps(data).encode())
    return salt, encrypted_data


def decrypt_data(salt: bytes, encrypted_data: bytes, password: str) -> dict | None:
    """Decrypts data using a password and salt. Returns None on failure."""
    try:
        key = derive_key(password.encode(), salt)
        f = Fernet(key)
        decrypted_data = f.decrypt(encrypted_data)
        return json.loads(decrypted_data.decode())
    except (InvalidToken, TypeError, ValueError, Exception): # Catch broader errors during decrypt
        return None


def generate_password(length=16):
    """Generates a strong random password."""
    if length <= 0: length = 1 # Ensure length is positive
    alphabet = string.ascii_letters + string.digits + string.punctuation
    # Ensure alphabet is not empty if length is extremely small (edge case)
    if not alphabet: return ""
    password = ''.join(secrets.choice(alphabet) for _ in range(length))
    return password

# --- Password Manager Class (Slightly adapted for GUI feedback) ---

class PasswordManager:
    def __init__(self, filename=DEFAULT_FILENAME):
        self.filename = os.path.abspath(filename)
        self.passwords = {}
        self.master_password = None
        self._data_changed = False # Track if changes need saving

    def set_master_password(self, password: str):
        self.master_password = password

    def mark_changed(self):
        self._data_changed = True

    def has_changed(self):
        return self._data_changed

    def add_password(self, website, username, password):
        """Adds or updates a password entry."""
        website_lower = website.lower().strip()
        if not website_lower: return # Don't add empty website names
        self.passwords[website_lower] = {"username": username.strip(), "password": password}
        self.mark_changed()

    def get_password(self, website):
        return self.passwords.get(website.lower().strip())

    def remove_password(self, website):
        website_lower = website.lower().strip()
        if website_lower in self.passwords:
            del self.passwords[website_lower]
            self.mark_changed()
            return True
        return False

    def list_websites(self):
        return sorted(self.passwords.keys())

    def save_to_file(self):
        """Encrypts and saves the current passwords to the file."""
        if not self.master_password:
            messagebox.showerror("Error", "Master password not set. Cannot save.")
            return False
        if not self.passwords and os.path.exists(self.filename):
             # Only warn if file exists and we are about to overwrite with nothing
             if not messagebox.askyesno("Confirm Save", "There are no passwords loaded. Saving will overwrite the file with empty data. Continue?"):
                 return False
        # No else needed for the 'not self.passwords' case if file doesn't exist - allow creating an empty file


        try:
            salt, encrypted_data = encrypt_data(self.passwords, self.master_password)
            data_to_save = {
                "salt": base64.urlsafe_b64encode(salt).decode('utf-8'),
                "data": base64.urlsafe_b64encode(encrypted_data).decode('utf-8')
            }
            with open(self.filename, "w") as f:
                json.dump(data_to_save, f, indent=2)
            self._data_changed = False # Reset changed flag after successful save
            return True
        except Exception as e:
            messagebox.showerror("Error", f"Error saving file: {e}")
            return False

    def load_from_file(self, password_attempt: str) -> bool:
        """Loads and decrypts passwords from the file. Returns True on success."""
        if not os.path.exists(self.filename):
            # File not found, set the master password for potential future save
            self.set_master_password(password_attempt)
            self.passwords = {}
            self._data_changed = False # New file, no changes yet
            return True # Treat as successful load of an empty manager

        try:
            with open(self.filename, "r") as f:
                saved_data = json.load(f)

            # Basic validation of file structure
            if "salt" not in saved_data or "data" not in saved_data:
                 raise ValueError("Invalid file format: missing 'salt' or 'data'.")

            salt = base64.urlsafe_b64decode(saved_data["salt"].encode('utf-8'))
            encrypted_data = base64.urlsafe_b64decode(saved_data["data"].encode('utf-8'))
            decrypted_passwords = decrypt_data(salt, encrypted_data, password_attempt)

            if decrypted_passwords is not None:
                self.passwords = decrypted_passwords
                self.set_master_password(password_attempt)
                self._data_changed = False # Freshly loaded, no changes yet
                return True
            else:
                self.passwords = {}
                self.master_password = None
                return False # Decryption failed
        except (json.JSONDecodeError, KeyError, FileNotFoundError, ValueError, Exception) as e:
            self.passwords = {}
            self.master_password = None
            messagebox.showerror("Load Error", f"Error reading or parsing file: {e}.\nPlease check the file or master password.")
            return False


# --- GUI Application Class ---

class PasswordManagerApp(ctk.CTk):
    def __init__(self, password_manager: PasswordManager):
        super().__init__()
        self.pm = password_manager

        self.title("Secure Password Manager")
        self.geometry("800x600")
        ctk.set_appearance_mode("System") # System theme (dark/light)
        ctk.set_default_color_theme("blue")

        self._create_widgets()
        self.refresh_website_list()

        # Handle window close event
        self.protocol("WM_DELETE_WINDOW", self._on_closing)

    def _create_widgets(self):
        self.grid_columnconfigure(0, weight=1) # Listbox column
        self.grid_columnconfigure(1, weight=2) # Details column
        self.grid_rowconfigure(1, weight=1)    # Main content row

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

        self.status_label = ctk.CTkLabel(self.top_frame, text="Loaded successfully.", text_color="green")
        self.status_label.pack(side=tk.RIGHT, padx=10, pady=5)
        self._update_status("Loaded successfully.", "green") # Initial status

        # --- Left Frame for Website List ---
        self.left_frame = ctk.CTkFrame(self)
        self.left_frame.grid(row=1, column=0, sticky="nsew", padx=(10, 5), pady=10)
        self.left_frame.grid_rowconfigure(1, weight=1)
        self.left_frame.grid_columnconfigure(0, weight=1)

        self.search_var = tk.StringVar()
        self.search_var.trace_add("write", lambda *args: self.refresh_website_list()) # Update list on search
        self.search_entry = ctk.CTkEntry(self.left_frame, placeholder_text="Search websites...", textvariable=self.search_var)
        self.search_entry.grid(row=0, column=0, sticky="ew", padx=5, pady=5)

        self.website_listbox = tk.Listbox(self.left_frame, selectmode=tk.SINGLE, borderwidth=0, highlightthickness=0, font=("Segoe UI", 11))
        # Using tk.Listbox as CTkListbox is experimental; styling might need adjustment
        self.website_listbox.grid(row=1, column=0, sticky="nsew", padx=5, pady=(0, 5))
        self.website_listbox.bind("<<ListboxSelect>>", self._on_website_select)

        # Add scrollbar (using CTkScrollbar with tk.Listbox)
        self.list_scrollbar = ctk.CTkScrollbar(self.left_frame, command=self.website_listbox.yview)
        self.list_scrollbar.grid(row=1, column=1, sticky="ns", pady=(0,5))
        self.website_listbox.configure(yscrollcommand=self.list_scrollbar.set)

        # --- Right Frame for Details ---
        self.right_frame = ctk.CTkFrame(self)
        self.right_frame.grid(row=1, column=1, sticky="nsew", padx=(5, 10), pady=10)
        self.right_frame.grid_columnconfigure(1, weight=1)

        # Labels
        ctk.CTkLabel(self.right_frame, text="Website:").grid(row=0, column=0, sticky="w", padx=10, pady=5)
        ctk.CTkLabel(self.right_frame, text="Username:").grid(row=1, column=0, sticky="w", padx=10, pady=5)
        ctk.CTkLabel(self.right_frame, text="Password:").grid(row=2, column=0, sticky="w", padx=10, pady=5)

        # Entry fields (read-only initially)
        self.website_entry_var = tk.StringVar()
        self.website_entry = ctk.CTkEntry(self.right_frame, textvariable=self.website_entry_var, state='readonly')
        self.website_entry.grid(row=0, column=1, sticky="ew", padx=10, pady=5)

        self.username_entry_var = tk.StringVar()
        self.username_entry = ctk.CTkEntry(self.right_frame, textvariable=self.username_entry_var, state='readonly')
        self.username_entry.grid(row=1, column=1, sticky="ew", padx=10, pady=5)

        self.password_entry_var = tk.StringVar()
        self.password_entry = ctk.CTkEntry(self.right_frame, textvariable=self.password_entry_var, state='readonly', show='*')
        self.password_entry.grid(row=2, column=1, sticky="ew", padx=10, pady=5)

        # Buttons for details pane
        self.button_frame = ctk.CTkFrame(self.right_frame, fg_color="transparent") # Frame to group buttons
        self.button_frame.grid(row=3, column=0, columnspan=2, pady=10)

        self.show_pw_button = ctk.CTkButton(self.button_frame, text="Show", width=60, command=self._toggle_password_visibility)
        self.show_pw_button.pack(side=tk.LEFT, padx=5)
        self.show_pw_button.configure(state=tk.DISABLED)

        self.copy_user_button = ctk.CTkButton(self.button_frame, text="Copy User", width=90, command=self._copy_username)
        self.copy_user_button.pack(side=tk.LEFT, padx=5)
        self.copy_user_button.configure(state=tk.DISABLED)

        self.copy_pw_button = ctk.CTkButton(self.button_frame, text="Copy PW", width=90, command=self._copy_password)
        self.copy_pw_button.pack(side=tk.LEFT, padx=5)
        self.copy_pw_button.configure(state=tk.DISABLED)

        self.delete_button = ctk.CTkButton(self.button_frame, text="Delete", fg_color="#D32F2F", hover_color="#B71C1C", command=self._delete_password)
        self.delete_button.pack(side=tk.LEFT, padx=5)
        self.delete_button.configure(state=tk.DISABLED)

    def _update_status(self, message, color="gray"):
        """Updates the status bar label."""
        self.status_label.configure(text=message, text_color=color)
        if self.pm.has_changed():
            self.title("Secure Password Manager *") # Indicate unsaved changes
            # Use try-except for theme access as it might fail in rare cases
            try:
                unsaved_color = ctk.ThemeManager.theme["CTkButton"].get("fg_color", ["#FFA000", "#FF8F00"])[0] # Use default if not found
            except:
                 unsaved_color = "#FFA000" # Fallback color
            self.save_button.configure(fg_color=unsaved_color) # Make save button prominent (orange-ish)
        else:
            self.title("Secure Password Manager")
            # Reset save button color based on theme (or use a default)
            try:
                default_color = ctk.ThemeManager.theme["CTkButton"]["fg_color"]
            except:
                 default_color = None # Use CTk default if theme access fails
            self.save_button.configure(fg_color=default_color)


    def refresh_website_list(self):
        """Clears and repopulates the website listbox, applying search filter."""
        search_term = self.search_var.get().lower()
        # Store current selection before clearing
        current_selection_index = self.website_listbox.curselection()
        selected_website = None
        if current_selection_index:
            try:
                selected_website = self.website_listbox.get(current_selection_index[0]).lower()
            except tk.TclError: # Handle case where index might be invalid already
                selected_website = None


        self.website_listbox.delete(0, tk.END)
        websites = self.pm.list_websites()
        new_index_to_select = None
        current_display_index = 0
        for site in websites:
            if search_term in site:
                capitalized_site = site.capitalize()
                self.website_listbox.insert(tk.END, capitalized_site)
                # Check if this is the previously selected item
                if selected_website and site == selected_website:
                    new_index_to_select = current_display_index
                current_display_index += 1

        # Try to re-select the item if it's still visible after filtering
        if new_index_to_select is not None:
            self.website_listbox.selection_set(new_index_to_select)
            self.website_listbox.activate(new_index_to_select)
            self.website_listbox.see(new_index_to_select)
            # Update details for the re-selected item
            self._on_website_select()
        else:
            self._clear_details() # Clear details if previous selection is gone or there was no selection


    def _on_website_select(self, event=None):
        """Handles selection changes in the listbox."""
        # --- CORRECTED ---
        # Get selection right before use to avoid race conditions
        selection = self.website_listbox.curselection()
        if not selection:
            # If selection disappeared before we could process it, ensure details are clear
            self._clear_details()
            return
        # --- END CORRECTED ---

        # Now we know 'selection' is valid *at this moment*
        selected_index = selection[0]
        try:
            selected_website_display = self.website_listbox.get(selected_index)
        except tk.TclError:
             # Handle rare case where index becomes invalid between curselection and get
             self._clear_details()
             return

        selected_website_key = selected_website_display.lower() # Use lowercase for lookup
        data = self.pm.get_password(selected_website_key)

        if data:
            self.website_entry_var.set(selected_website_display) # Show capitalized version
            self.username_entry_var.set(data["username"])
            self.password_entry_var.set(data["password"])
            # Reset password visibility
            self.password_entry.configure(show='*')
            self.show_pw_button.configure(text="Show")
            # Enable buttons
            self.show_pw_button.configure(state=tk.NORMAL)
            self.copy_user_button.configure(state=tk.NORMAL)
            self.copy_pw_button.configure(state=tk.NORMAL)
            self.delete_button.configure(state=tk.NORMAL)
        else:
            # Data associated with the selected website not found (should be rare if list is sync)
            self._clear_details()
            # Optionally show an error/warning here if this state is unexpected
            # messagebox.showwarning("Warning", f"Could not retrieve data for {selected_website_display}")


    def _clear_details(self):
        """Clears the detail entry fields and disables buttons."""
        self.website_entry_var.set("")
        self.username_entry_var.set("")
        self.password_entry_var.set("")
        self.password_entry.configure(show='*')
        self.show_pw_button.configure(text="Show", state=tk.DISABLED)
        self.copy_user_button.configure(state=tk.DISABLED)
        self.copy_pw_button.configure(state=tk.DISABLED)
        self.delete_button.configure(state=tk.DISABLED)
        # Also clear listbox selection if desired, though typically user interaction handles this
        # self.website_listbox.selection_clear(0, tk.END)

    def _toggle_password_visibility(self):
        """Toggles the password field between hidden and visible."""
        if self.password_entry.cget('show') == '*':
            self.password_entry.configure(show='')
            self.show_pw_button.configure(text="Hide")
        else:
            self.password_entry.configure(show='*')
            self.show_pw_button.configure(text="Show")

    def _copy_username(self):
        """Copies the username to the clipboard."""
        username = self.username_entry_var.get()
        if username:
            try:
                pyperclip.copy(username)
                self._update_status("Username copied to clipboard.", "blue")
            except Exception as e:
                 self._update_status(f"Clipboard error: {e}", "orange")
                 messagebox.showwarning("Clipboard Error", f"Could not copy to clipboard:\n{e}")

    def _copy_password(self):
        """Copies the password to the clipboard."""
        password = self.password_entry_var.get()
        if password:
            try:
                pyperclip.copy(password)
                self._update_status("Password copied to clipboard.", "blue")
            except Exception as e:
                 self._update_status(f"Clipboard error: {e}", "orange")
                 messagebox.showwarning("Clipboard Error", f"Could not copy to clipboard:\n{e}")


    def _delete_password(self):
        """Deletes the selected password after confirmation."""
        # --- CORRECTED ---
        # Get selection right before use
        selection = self.website_listbox.curselection()
        if not selection:
            # If selection disappeared, do nothing
            return
        # --- END CORRECTED ---

        selected_index = selection[0]
        try:
            website_display = self.website_listbox.get(selected_index)
        except tk.TclError:
             # Handle rare case where index becomes invalid
             return

        website_key = website_display.lower()

        if messagebox.askyesno("Confirm Deletion", f"Are you sure you want to delete the entry for '{website_display}'?"):
            if self.pm.remove_password(website_key):
                self.refresh_website_list() # Update listbox (this implicitly clears details if item is gone)
                self._update_status(f"Deleted '{website_display}'. Remember to save.", "orange") # Deletion is a change
            else:
                # Should not happen if selected, but good practice
                self._update_status(f"Failed to delete '{website_display}'.", "red")
                messagebox.showerror("Error", f"Could not find or delete entry for '{website_display}'.")

    def _save_data(self):
        """Saves the current password data to the encrypted file."""
        if self.pm.save_to_file():
            self._update_status(f"Data saved to {os.path.basename(self.pm.filename)}", "green")
        # No else needed, save_to_file shows its own error message box

    def _on_closing(self):
        """Handles the window close event, prompting to save if needed."""
        if self.pm.has_changed():
            if messagebox.askyesno("Unsaved Changes", "You have unsaved changes. Do you want to save before exiting?"):
                if not self._save_data(): # Try to save
                    # If save failed (e.g., user cancelled overwrite confirmation), don't close
                    return
        self.destroy() # Close the window

    # --- Dialog Functions ---

    def _add_password_dialog(self):
        """Opens a dialog to add or edit a password."""
        dialog = ctk.CTkToplevel(self)
        dialog.title("Add/Edit Password")
        dialog.geometry("450x250") # Slightly wider for generate button
        dialog.transient(self) # Keep dialog on top of main window
        dialog.grab_set() # Modal - block interaction with main window
        dialog.resizable(False, False)

        dialog.grid_columnconfigure(1, weight=1)

        # Widgets
        ctk.CTkLabel(dialog, text="Website:").grid(row=0, column=0, padx=10, pady=10, sticky="w")
        website_entry = ctk.CTkEntry(dialog)
        website_entry.grid(row=0, column=1, columnspan=2, padx=10, pady=10, sticky="ew") # Span 2 columns

        ctk.CTkLabel(dialog, text="Username:").grid(row=1, column=0, padx=10, pady=10, sticky="w")
        username_entry = ctk.CTkEntry(dialog)
        username_entry.grid(row=1, column=1, columnspan=2, padx=10, pady=10, sticky="ew") # Span 2 columns

        ctk.CTkLabel(dialog, text="Password:").grid(row=2, column=0, padx=10, pady=10, sticky="w")
        password_entry = ctk.CTkEntry(dialog, show="*")
        password_entry.grid(row=2, column=1, padx=(10, 0), pady=10, sticky="ew") # Adjusted padding

        # Button Frame for Password row
        pw_button_frame = ctk.CTkFrame(dialog, fg_color="transparent")
        pw_button_frame.grid(row=2, column=2, padx=(5, 10), pady=10, sticky="e") # Place next to password entry

        def toggle_pw():
             if password_entry.cget('show') == '*': password_entry.configure(show='')
             else: password_entry.configure(show='*')
        show_button = ctk.CTkButton(pw_button_frame, text="👁", command=toggle_pw, width=30)
        show_button.pack(side=tk.LEFT, padx=(0, 5))

        def generate_and_fill():
             pw = generate_password()
             password_entry.delete(0, tk.END)
             password_entry.insert(0, pw)
        gen_button = ctk.CTkButton(pw_button_frame, text="Gen", command=generate_and_fill, width=50) # Shorter text
        gen_button.pack(side=tk.LEFT)

        # Fill fields if editing existing entry
        selection = self.website_listbox.curselection()
        editing_website = None
        if selection:
             try:
                 selected_website_display = self.website_listbox.get(selection[0])
                 editing_website = selected_website_display.lower()
                 data = self.pm.get_password(editing_website)
                 if data:
                     dialog.title(f"Edit Password for {selected_website_display}")
                     website_entry.insert(0, selected_website_display)
                     website_entry.configure(state='readonly', fg_color='gray70') # Indicate read-only
                     username_entry.insert(0, data['username'])
                     password_entry.insert(0, data['password'])
             except tk.TclError:
                  # Handle case where selection becomes invalid before dialog opens
                  dialog.title("Add Password") # Fallback to Add title


        # Save / Cancel Buttons
        button_frame = ctk.CTkFrame(dialog, fg_color="transparent")
        button_frame.grid(row=3, column=0, columnspan=3, pady=20)

        # --- CORRECTED save_entry ---
        def save_entry():
            # Use editing_website if available, otherwise get from entry
            website = editing_website if editing_website else website_entry.get().strip()
            username = username_entry.get().strip()
            password = password_entry.get()

            if not website:
                messagebox.showerror("Error", "Website name cannot be empty.", parent=dialog)
                return

            # Overwrite confirmation is implicitly handled by add_password logic
            self.pm.add_password(website, username, password)
            # Store the website key *before* refreshing the list
            website_key_to_select = website.lower()
            self.refresh_website_list() # Refresh first

            # Try to re-select the added/edited item *after* refreshing
            try:
                 # Get listbox items *after* refresh
                 all_items_lower = list(map(str.lower, self.website_listbox.get(0, tk.END)))
                 idx = all_items_lower.index(website_key_to_select)

                 # Check if index is valid for the current listbox size
                 if 0 <= idx < self.website_listbox.size():
                     self.website_listbox.selection_clear(0, tk.END)
                     self.website_listbox.selection_set(idx)
                     self.website_listbox.activate(idx)
                     self.website_listbox.see(idx) # Scroll to the item
                     # Trigger update of details pane AFTER selection is confirmed
                     self._on_website_select()
                 else:
                      # Index found but out of bounds? Should not happen but safety check.
                      self._clear_details()

            except ValueError:
                 # Item not found (e.g., filtered out by search), clear details
                 self._clear_details()
            except tk.TclError:
                 # Handle potential error during listbox operations
                 self._clear_details()
            # --- END CORRECTED RE-SELECTION ---

            self._update_status(f"Added/Updated '{website.capitalize()}'. Remember to save.", "orange")
            dialog.destroy()
        # --- END save_entry ---

        save_btn = ctk.CTkButton(button_frame, text="Save", command=save_entry)
        save_btn.pack(side=tk.LEFT, padx=10)

        cancel_btn = ctk.CTkButton(button_frame, text="Cancel", command=dialog.destroy, fg_color="gray")
        cancel_btn.pack(side=tk.LEFT, padx=10)

        # Set focus appropriately (username if editing, website if adding)
        if editing_website:
            username_entry.focus_set()
            username_entry.select_range(0, tk.END)
        else:
            website_entry.focus_set()

    def _generate_password_dialog(self):
        """Shows a dialog to generate a password and copies it."""
        # Use a simple dialog first to get length
        length_dialog = ctk.CTkInputDialog(text="Enter desired password length (e.g., 16):", title="Generate Password")
        length_dialog.geometry("300x150")
        entry = length_dialog.winfo_children()[1] # Access the CTkEntry widget inside
        def validate_numeric(P): return P.isdigit() or P == ""
        validate_cmd = (self.register(validate_numeric), '%P')
        entry.configure(validate="key", validatecommand=validate_cmd)
        entry.delete(0, tk.END)
        entry.insert(0, "16") # Default length

        result = length_dialog.get_input()

        if result:
            try:
                length = int(result)
                if length <= 0: raise ValueError("Length must be positive")

                pw = generate_password(length)

                # Show password in a non-editable textbox with copy button
                show_pw_dialog = ctk.CTkToplevel(self)
                show_pw_dialog.title("Generated Password")
                show_pw_dialog.geometry("350x150")
                show_pw_dialog.transient(self)
                show_pw_dialog.grab_set()
                show_pw_dialog.resizable(False, False)

                pw_textbox = ctk.CTkTextbox(show_pw_dialog, height=40, activate_scrollbars=False)
                pw_textbox.pack(padx=20, pady=10, fill="x")
                pw_textbox.insert("1.0", pw)
                pw_textbox.configure(state="disabled") # Make read-only

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
        """Dialog to change the master password."""
        dialog = ctk.CTkToplevel(self)
        dialog.title("Change Master Password")
        dialog.geometry("400x250")
        dialog.transient(self)
        dialog.grab_set()
        dialog.resizable(False, False)

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

        button_frame = ctk.CTkFrame(dialog, fg_color="transparent")
        button_frame.grid(row=3, column=0, columnspan=2, pady=20)

        def process_change():
            current_pw = current_pw_entry.get()
            new_pw = new_pw_entry.get()
            confirm_pw = confirm_pw_entry.get()

            # Basic validation
            if not current_pw or not new_pw or not confirm_pw:
                messagebox.showerror("Error", "All fields are required.", parent=dialog)
                return
            if new_pw != confirm_pw:
                messagebox.showerror("Error", "New passwords do not match.", parent=dialog)
                return
            if current_pw == new_pw:
                messagebox.showerror("Error", "New password cannot be the same as the current one.", parent=dialog)
                return

            # Verify current password by checking against the one in memory
            if self.pm.master_password != current_pw:
                 messagebox.showerror("Error", "Incorrect current master password.", parent=dialog)
                 return

            # If all checks pass, update the master password in memory
            self.pm.set_master_password(new_pw)
            self.pm.mark_changed() # Mark data as changed because master PW changed
            messagebox.showinfo("Success", "Master password updated in memory.\n\nIMPORTANT: You MUST click 'Save Changes' now to make this permanent.", parent=dialog)
            self._update_status("Master PW changed! SAVE REQUIRED!", "orange") # Use Orange for Requires Action
            dialog.destroy()


        change_btn = ctk.CTkButton(button_frame, text="Change Password", command=process_change)
        change_btn.pack(side=tk.LEFT, padx=10)

        cancel_btn = ctk.CTkButton(button_frame, text="Cancel", command=dialog.destroy, fg_color="gray")
        cancel_btn.pack(side=tk.LEFT, padx=10)

        current_pw_entry.focus_set()


# --- Login/Initialization Screen ---

class LoginScreen(ctk.CTkToplevel):
    def __init__(self, parent, pm: PasswordManager, file_exists: bool):
        super().__init__(parent)
        self.pm = pm
        self.file_exists = file_exists
        self.parent = parent
        self.result_password = None # Store the entered password here
        self.success = False

        self.title("Login" if file_exists else "Create Master Password")
        self.geometry("350x200")
        self.transient(parent)
        self.grab_set() # Make modal
        self.protocol("WM_DELETE_WINDOW", self._cancel_login) # Handle closing the login window
        self.resizable(False, False)
        self.lift() # Ensure it's on top
        # self.focus_force() # focus_set() below is usually sufficient


        self.grid_columnconfigure(0, weight=1)

        prompt_text = f"Enter Master Password for\n{os.path.basename(self.pm.filename)}:" if file_exists else "Create a NEW Master Password:"
        self.prompt_label = ctk.CTkLabel(self, text=prompt_text, wraplength=300)
        self.prompt_label.grid(row=0, column=0, padx=20, pady=(20, 10))

        self.password_entry = ctk.CTkEntry(self, show="*", width=250)
        self.password_entry.grid(row=1, column=0, padx=20, pady=5)
        self.password_entry.bind("<Return>", self._submit) # Allow pressing Enter

        if not file_exists:
            self.confirm_label = ctk.CTkLabel(self, text="Confirm New Password:")
            self.confirm_label.grid(row=2, column=0, padx=20, pady=(10, 0), sticky="w")
            self.confirm_entry = ctk.CTkEntry(self, show="*", width=250)
            self.confirm_entry.grid(row=3, column=0, padx=20, pady=5)
            self.confirm_entry.bind("<Return>", self._submit)
            # Position submit button lower when creating
            submit_row = 5
        else:
            submit_row = 4


        self.submit_button = ctk.CTkButton(self, text="Login" if file_exists else "Create", command=self._submit)
        self.submit_button.grid(row=submit_row, column=0, padx=20, pady=20)

        self.password_entry.focus_set()

    def _submit(self, event=None):
        password = self.password_entry.get()

        if not password:
            messagebox.showerror("Error", "Password cannot be empty.", parent=self)
            return

        if self.file_exists:
            if self.pm.load_from_file(password):
                self.result_password = password
                self.success = True
                self.destroy() # Close login window on success
            else:
                # Error message shown by load_from_file if it fails
                self.password_entry.delete(0, tk.END) # Clear entry on failure
                # Optionally add another messagebox here if load_from_file doesn't always show one
                # messagebox.showerror("Login Failed", "Incorrect Master Password or corrupted file.", parent=self)
        else: # Creating new file
            confirm_password = self.confirm_entry.get()
            if not confirm_password:
                 messagebox.showerror("Error", "Please confirm the password.", parent=self)
                 return

            if password != confirm_password:
                messagebox.showerror("Error", "Passwords do not match.", parent=self)
                self.confirm_entry.delete(0, tk.END)
                return
            # Set the master password (load_from_file does this implicitly when file not found)
            self.pm.set_master_password(password)
            self.result_password = password
            self.success = True
            # No file exists yet, so no actual loading needed, just setting the master pw
            messagebox.showinfo("Setup Complete", "Master Password created. Remember it!", parent=self)
            self.destroy()

    def _cancel_login(self):
        """Called when the login window is closed manually."""
        self.success = False
        self.destroy()


# --- Main Execution ---

# --- pyperclip Check/Install ---
try:
    import pyperclip
except ImportError:
    print("pyperclip library not found. Attempting to install...")
    try:
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


def main():
    # Need a root window for dialogs, hide it initially
    # Use CTk instead of tk for consistency if preferred
    root = ctk.CTk()
    root.withdraw() # Hide the main root window

    # --- Ask for filename or use default ---
    filename_dialog = ctk.CTkInputDialog(text="Enter data file name:", title="Password File")
    filename_dialog.geometry("350x150")

    # --- Find the Entry widget robustly ---
    entry_widget = None
    # Search immediate children and children within the first frame found
    for widget in filename_dialog.winfo_children():
        if isinstance(widget, ctk.CTkEntry):
            entry_widget = widget
            break
        elif isinstance(widget, ctk.CTkFrame): # Check inside frames too
             for sub_widget in widget.winfo_children():
                 if isinstance(sub_widget, ctk.CTkEntry):
                     entry_widget = sub_widget
                     break
        if entry_widget: # Stop searching if found
            break

    # Set default value if the entry widget was found
    if entry_widget:
        entry_widget.delete(0, tk.END)
        entry_widget.insert(0, DEFAULT_FILENAME) # Insert default
    else:
        # This is unlikely but possible if the dialog structure is very different
        print("Warning: Could not find internal entry widget to pre-fill default filename.")

    # Get the input (this shows the dialog)
    filename = filename_dialog.get_input() # Returns None if cancelled

    # --- End Filename Handling ---

    if not filename:
        print("No filename provided. Exiting.")
        root.destroy()
        return

    pm = PasswordManager(filename=filename)
    file_exists = os.path.exists(pm.filename)

    # Show login screen
    login = LoginScreen(root, pm, file_exists)
    login.wait_window() # Wait for the login window to close

    # Check if login was successful AFTER wait_window returns
    if login.success:
        # Login/Setup successful, show the main application window
        app = PasswordManagerApp(pm)
        app.mainloop() # Start the main app loop
    else:
        print("Login cancelled or failed. Exiting.")
        root.destroy() # Destroy the hidden root if login failed/cancelled

# --- Keep the rest of the code (__init__, PasswordManager, PasswordManagerApp, LoginScreen etc.) the same ---

if __name__ == "__main__":
    # --- pyperclip Check/Install (keep this part) ---
    try:
        import pyperclip
    except ImportError:
        print("pyperclip library not found. Attempting to install...")
        try:
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

    main()