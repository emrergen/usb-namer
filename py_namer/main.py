#!/usr/bin/env python3
import tkinter as tk
from tkinter import ttk, messagebox
import threading
import sys
import os
import subprocess
from device_mgr import DeviceManager

# Auto-elevation logic
def ensure_root():
    if os.geteuid() == 0:
        return

    # Create a minimal Tk app for the password prompt
    # We do this before the main app starts
    root_prompt = tk.Tk()
    root_prompt.withdraw() # Hide main window
    
    # Custom Password Dialog
    pwd_dialog = tk.Toplevel(root_prompt)
    pwd_dialog.title("Sudo Password Required")
    pwd_dialog.geometry("350x150")
    pwd_dialog.configure(bg="#2E2E2E")
    
    tk.Label(pwd_dialog, text="Root privileges are required.", fg="white", bg="#2E2E2E", pady=10).pack()
    tk.Label(pwd_dialog, text="Enter sudo password:", fg="white", bg="#2E2E2E").pack()
    
    pwd_var = tk.StringVar()
    ent_pwd = tk.Entry(pwd_dialog, textvariable=pwd_var, show="*", width=30)
    ent_pwd.pack(pady=5)
    ent_pwd.focus_set()
    
    ent_pwd.pack(pady=5)
    ent_pwd.focus_set()
    
    # Error label for feedback
    lbl_error = tk.Label(pwd_dialog, text="", fg="#ff5555", bg="#2E2E2E", font=("Sans", 9))
    lbl_error.pack(pady=2)
    
    attempts = [0]
    max_attempts = 3
    
    def check_password(password):
        # Try to validate password with sudo -S -v
        # -v updates cached credentials, -S reads from stdin
        cmd = ['sudo', '-S', '-v']
        try:
            # We must encode password to bytes
            p = subprocess.run(cmd, input=password + "\n", text=True, capture_output=True)
            return p.returncode == 0
        except Exception:
            return False

    def on_submit(event=None):
        password = pwd_var.get()
        if not password:
             return
             
        if check_password(password):
            # Password correct
            pwd_dialog.destroy()
            root_prompt.destroy()
            
            # Launch the real app
            print("Password accepted. Elevating...")
            exe = os.path.abspath(sys.executable)
            cmd = ['sudo', '-E'] # -E to preserve env. We rely on cached creds from -v above.
            
            if getattr(sys, 'frozen', False):
                 cmd.append(exe)
            else:
                 cmd.append(sys.executable) # python
                 cmd.extend(sys.argv)
                 
            # We don't need to pass password again usually if -v succeeded recently.
            # But just in case, sudo behavior might differ. 
            # Ideally we keep 'sudo -S' and pass password if we want to be 100% sure.
            # Let's try attempting without -S first (relying on cache).
            # If that fails? 
            # Actually, standard behavior is -v updates timestamp. 
            # So sudo -E ... should work without password.
            subprocess.call(cmd) 
            sys.exit(0)
            
        else:
            attempts[0] += 1
            remaining = max_attempts - attempts[0]
            if remaining <= 0:
                messagebox.showerror("Error", "Too many incorrect attempts. Exiting.")
                pwd_dialog.destroy()
                root_prompt.destroy()
                sys.exit(1)
            else:
                lbl_error.config(text=f"Incorrect password. Attempts left: {remaining}")
                ent_pwd.delete(0, tk.END)
                ent_pwd.focus_set()
        
    def on_cancel():
        pwd_dialog.destroy()
        root_prompt.destroy()
        sys.exit(0) # Exit if cancelled
        
    btn_frame = ttk.Frame(pwd_dialog)
    btn_frame.pack(pady=10)
    
    ttk.Button(btn_frame, text="Quit", command=on_cancel).pack(side=tk.LEFT, padx=5)
    ttk.Button(btn_frame, text="OK", command=on_submit).pack(side=tk.LEFT, padx=5)
    
    # Handle enter key explicitly on the Entry widget too
    ent_pwd.bind('<Return>', on_submit)
    pwd_dialog.bind('<Return>', on_submit)
    pwd_dialog.protocol("WM_DELETE_WINDOW", on_cancel)
    
    # Center the dialog
    pwd_dialog.update_idletasks()
    width = pwd_dialog.winfo_width()
    height = pwd_dialog.winfo_height()
    x = (root_prompt.winfo_screenwidth() // 2) - (width // 2)
    y = (root_prompt.winfo_screenheight() // 2) - (height // 2)
    pwd_dialog.geometry(f'{width}x{height}+{x}+{y}')
    
    root_prompt.wait_window(pwd_dialog)
    root_prompt.mainloop() # Process events until destroy
    
    # If we get here, loop finished? handled inside.
    sys.exit(0)
    
    # --- OLD BLOCK REMOVED ---
    # password = result[0] ...

class USBNamerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("USB Device Namer")
        self.root.geometry("900x600")
        
        self.mgr = DeviceManager()
        self.devices = [] # List of dicts
        self.auto_refresh_enabled = True
        
        self.style_ui()
        self.create_widgets()
        self.refresh_devices()
        self.schedule_refresh()

    def schedule_refresh(self):
        if self.auto_refresh_enabled:
            # Refresh every 3 seconds. 
            # Note: A full refresh might interrupt selection, so we need to be smart.
            # For now, simple refresh. Ideally we check for changes before full UI update.
            self.check_for_changes()
            self.root.after(3000, self.schedule_refresh)

    def check_for_changes(self):
        # We can implement a "smart" check here later. 
        # For now, let's just re-run refresh but try to maintain selection if possible.
        pass # To be implemented properly in refresh_devices or separate


    def style_ui(self):
        style = ttk.Style()
        style.theme_use('clam')
        
        # Colors
        bg_color = "#2E2E2E"
        fg_color = "#FFFFFF"
        field_bg = "#3E3E3E"
        select_bg = "#4a6ea9"
        header_bg = "#1E1E1E" # Darker for header
        
        # Configure Colors globally
        # This is a bit manual for Tkinter but works
        self.root.configure(bg=bg_color)
        
        style.configure(".", background=bg_color, foreground=fg_color, fieldbackground=field_bg)
        style.configure("TLabel", background=bg_color, foreground=fg_color)
        style.configure("TFrame", background=bg_color)
        style.configure("TLabelframe", background=bg_color, foreground=fg_color)
        style.configure("TLabelframe.Label", background=bg_color, foreground=fg_color)
        style.configure("TLabelframe.Label", background=bg_color, foreground=fg_color)
        style.configure("TCheckbutton", background=bg_color, foreground=fg_color)
        style.map("TCheckbutton",
                  background=[('active', bg_color)], # Keep background dark on hover
                  foreground=[('active', fg_color)]) # Keep text white on hover
        
        # Treeview
        
        # Treeview
        style.configure("Treeview", 
                        background="#333333", 
                        foreground="#FFFFFF", 
                        fieldbackground="#333333",
                        rowheight=25, 
                        font=("Sans", 10))
                        
        style.configure("Treeview.Heading", 
                        background=header_bg, 
                        foreground=fg_color,
                        font=("Sans", 10, "bold"),
                        relief="flat")
                        
        style.map("Treeview", 
                  background=[('selected', select_bg)],
                  foreground=[('selected', 'white')]) # Explicitly force white text on selection
        style.map("Treeview.Heading", background=[('active', '#404040')])
        
        # Scrollbar (Dark theme)
        style.configure("Vertical.TScrollbar", background="#444444", troughcolor="#2E2E2E", bordercolor="#2E2E2E", arrowcolor="white")
        
        # Buttons
        style.configure("TButton", padding=5, relief="flat", background="#444444", foreground=fg_color)
        style.map("TButton", background=[('active', '#555555')])

    def create_widgets(self):
        # --- Top Toolbar ---
        toolbar = ttk.Frame(self.root, padding=5)
        toolbar.pack(fill=tk.X)
        
        refresh_btn = ttk.Button(toolbar, text="Refresh Devices", command=lambda: self.refresh_devices(silent=False))
        refresh_btn.pack(side=tk.LEFT, padx=5)

        # Right-aligned Exit Button
        exit_btn = ttk.Button(toolbar, text="Quit Program", command=self.root.destroy)
        exit_btn.pack(side=tk.RIGHT, padx=5)

        # --- Main Content (Split Pane) ---
        paned = ttk.PanedWindow(self.root, orient=tk.VERTICAL)
        paned.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

        # 1. Device List (Top)
        frame_list = ttk.LabelFrame(paned, text="Connected Devices", padding=5)
        paned.add(frame_list, weight=2)
        
        columns = ("device", "subsystem", "vendor", "product", "serial", "symlinks", "model")
        self.tree = ttk.Treeview(frame_list, columns=columns, show="headings", selectmode="browse")
        
        self.tree.heading("device", text="Device Path")
        self.tree.heading("subsystem", text="Type")
        self.tree.heading("vendor", text="Vendor")
        self.tree.heading("product", text="Product")
        self.tree.heading("serial", text="Serial Number")
        self.tree.heading("symlinks", text="Current Symlinks")
        self.tree.heading("model", text="Model")
        
        self.tree.column("device", width=100)
        self.tree.column("subsystem", width=80)
        self.tree.column("vendor", width=60)
        self.tree.column("product", width=60)
        self.tree.column("serial", width=120)
        self.tree.column("symlinks", width=150)
        self.tree.column("model", width=150)

        # Scrollbar
        scrollbar = ttk.Scrollbar(frame_list, orient=tk.VERTICAL, command=self.tree.yview)
        self.tree.configure(yscroll=scrollbar.set)
        
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        self.tree.bind("<<TreeviewSelect>>", self.on_select)

        # 2. Detail / Action Panel (Bottom)
        frame_detail = ttk.LabelFrame(paned, text="Create Rule", padding=10)
        paned.add(frame_detail, weight=1)

        # Form Grid
        ttk.Label(frame_detail, text="Selected Device:").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.lbl_selected_device = ttk.Label(frame_detail, text="None", font=("Sans", 10, "bold"))
        self.lbl_selected_device.grid(row=0, column=1, sticky=tk.W, pady=5)

        ttk.Label(frame_detail, text="Symlink Name:").grid(row=1, column=0, sticky=tk.W, pady=5)
        self.ent_symlink = ttk.Entry(frame_detail, width=30)
        self.ent_symlink.grid(row=1, column=1, sticky=tk.W, pady=5)
        ttk.Label(frame_detail, text="(e.g., my_camera, arduino_mega)").grid(row=1, column=2, sticky=tk.W, padx=5)

        self.var_fallback = tk.BooleanVar()
        self.chk_fallback = ttk.Checkbutton(frame_detail, text="Force Non-Unique Rule (Use Vendor/Product if Serial missing)", variable=self.var_fallback)
        self.chk_fallback.grid(row=2, column=1, columnspan=2, sticky=tk.W, pady=5)

        # Buttons
        btn_frame = ttk.Frame(frame_detail)
        btn_frame.grid(row=3, column=0, columnspan=3, pady=15)
        
        self.btn_create = ttk.Button(btn_frame, text="Create udev Rule", command=self.create_rule, state=tk.DISABLED)
        self.btn_create.pack(side=tk.LEFT, padx=5)
        
        self.btn_delete = ttk.Button(btn_frame, text="Delete Rule", command=self.delete_rule, state=tk.DISABLED)
        self.btn_delete.pack(side=tk.LEFT, padx=5)

        ttk.Button(btn_frame, text="Reload udev Rules", command=self.reload_rules).pack(side=tk.LEFT, padx=5)

        # --- Verification Hint ---
        # Separator
        ttk.Separator(frame_detail, orient='horizontal').grid(row=4, column=0, columnspan=3, sticky="ew", pady=10)
        
        ttk.Label(frame_detail, text="Kontrol için terminal komutu:").grid(row=5, column=0, sticky=tk.W)
        
        # Copyable Entry (Using tk.Entry for better color control in readonly state)
        cmd_var = tk.StringVar(value="ls -l /dev | grep ' -> '")
        self.ent_cmd = tk.Entry(frame_detail, textvariable=cmd_var, width=35, state="readonly", 
                                font=("Monospace", 10), 
                                bg="#333333", fg="white", 
                                readonlybackground="#333333", 
                                selectbackground="#4a6ea9", selectforeground="white")
        self.ent_cmd.grid(row=5, column=1, sticky=tk.W, pady=5)
        
        ttk.Label(frame_detail, text="(Kopyalayıp terminale yapıştırabilirsiniz)", font=("Sans", 9), foreground="#aaaaaa").grid(row=5, column=2, sticky=tk.W, padx=5)

        # --- Status Bar ---
        self.status_var = tk.StringVar(value="Ready")
        status_bar = ttk.Label(self.root, textvariable=self.status_var, relief=tk.SUNKEN, anchor=tk.W)
        status_bar.pack(fill=tk.X, side=tk.BOTTOM)

    def check_for_changes(self):
        # Silent refresh - only update key lists if count changes or naive check
        # For a truly dynamic UI without flickering, we'd diff the lists.
        # But simply calling refresh_devices() every 3s is annoying if user is typing.
        
        curr_devices = self.mgr.list_potential_devices()
        if len(curr_devices) != len(self.devices):
             # Device count changed, force refresh
             self.refresh_devices(silent=True)
        else:
            # Check if paths are same (naive check)
            current_paths = set(curr_devices)
            known_paths = set(d['device'] for d in self.devices)
            if current_paths != known_paths:
                self.refresh_devices(silent=True)

    def refresh_devices(self, silent=False):
        if not silent:
            self.status_var.set("Scanning devices...")
        self.root.update_idletasks()
        
        # Save selection
        selected_id = None
        sel = self.tree.selection()
        if sel:
            selected_path = self.tree.item(sel[0])['values'][0]
        else:
            selected_path = None
        
        # Clear existing
        for item in self.tree.get_children():
            self.tree.delete(item)
        self.devices = []
        if not selected_path:
            self.btn_create.config(state=tk.DISABLED)
            self.lbl_selected_device.config(text="None")
        
        paths = self.mgr.list_potential_devices()
        count = 0
        
        for path in paths:
            info = self.mgr.get_device_info(path)
            self.devices.append(info)
            
            serial_disp = info.get("serial", "")
            if not serial_disp:
                serial_disp = "NONE"
            
            item_id = self.tree.insert("", tk.END, values=(
                info["device"],
                info["subsystem"],
                info["vendor_id"],
                info["product_id"],
                serial_disp,
                info.get("current_symlinks", ""),
                info["model"]
            ))
            
            # Restore selection
            if selected_path and info["device"] == selected_path:
                selected_id = item_id
                
            count += 1
            
        if selected_id:
            self.tree.selection_set(selected_id)

        if not silent:
            self.status_var.set(f"Found {count} devices.")

    def on_select(self, event):
        selected = self.tree.selection()
        if not selected:
            return
        
        # Get values
        vals = self.tree.item(selected[0])['values']
        path = vals[0]
        
        self.lbl_selected_device.config(text=f"{path} ({vals[5]})")
        self.btn_create.config(state=tk.NORMAL)
        
        # Enable delete only if symlinks exist
        current_syms = vals[5]
        if current_syms:
             self.btn_delete.config(state=tk.NORMAL)
        else:
             self.btn_delete.config(state=tk.DISABLED)
        
        # Auto-fill suggested name? nah let user type
        
    def find_device_info_by_path(self, path):
        for d in self.devices:
            if d["device"] == path:
                return d
        return None

    def create_rule(self):
        selected_items = self.tree.selection()
        if not selected_items:
            return
            
        name = self.ent_symlink.get().strip()
        if not name:
            messagebox.showerror("Error", "Please enter a Symlink Name.")
            return

        vals = self.tree.item(selected_items[0])['values']
        path = vals[0]
        dev_info = self.find_device_info_by_path(path)
        
        if not dev_info:
            messagebox.showerror("Error", "Device info lost. Please refresh.")
            return
            
        # Warning if no serial and force not checked
        if not dev_info.get("serial") and not self.var_fallback.get():
             resp = messagebox.askyesno("Warning", "This device has no unique Serial Number!\n\nUse Vendor/Product ID match? (Not unique for identical devices)", icon='warning')
             if resp:
                 self.var_fallback.set(True)
             else:
                 return

        content = self.mgr.generate_rule_content(dev_info, name, self.var_fallback.get())
        
        # Preview
        # Could show a dialog previewing the file content
        
        if messagebox.askyesno("Confirm", f"Create rule for {name}?\n\nTarget: /etc/udev/rules.d/99-{name}.rules", icon='question'):
            success, msg = self.mgr.write_rule_file(name, content)
            if success:
                # Auto-reload logic
                self.status_var.set(f"Rule created. Reloading udev...")
                self.root.update_idletasks()
                
                r_success, r_msg = self.mgr.reload_udev()
                if r_success:
                    messagebox.showinfo("Success", f"{msg}\n\nUdev rules reloaded automatically.\nYour device should be available at /dev/{name}")
                    self.status_var.set(f"Ready. /dev/{name} created.")
                    self.refresh_devices(silent=False) # Force refresh list to show new symlink
                else:
                    messagebox.showwarning("Warning", f"{msg}\n\nRule created but Udev reload failed: {r_msg}")
            else:
                messagebox.showerror("Error", msg)

    def delete_rule(self):
        selected_items = self.tree.selection()
        if not selected_items:
            return
            
        vals = self.tree.item(selected_items[0])['values']
        current_syms = vals[5] # String of comma-sep symlinks
        
        if not current_syms:
             messagebox.showinfo("Info", "No known custom symlinks detected for this device.")
             return
             
        sym_list = [s.strip() for s in current_syms.split(",")]
        
        target_symlink = None
        if len(sym_list) == 1:
            target_symlink = sym_list[0]
        else:
            # Ask user which one
            # Using a simple dialog? Tkinter simpledialog doesn't support combo well,
            # Let's just ask via a custom toplevel or loop. 
            # For simplicity, if multiple, we'll ask user to type the name or implement a custom dialog.
            # Let's verify by popping up a Toplevel.
            
            dialog = tk.Toplevel(self.root)
            dialog.title("Select Rule to Delete")
            dialog.geometry("300x150")
            
            tk.Label(dialog, text="Select Symlink to remove:").pack(pady=10)
            combo = ttk.Combobox(dialog, values=sym_list, state="readonly")
            combo.pack(pady=5)
            combo.current(0)
            
            result = [None]
            def on_ok():
                result[0] = combo.get()
                dialog.destroy()
                
            ttk.Button(dialog, text="Delete", command=on_ok).pack(pady=10)
            
            self.root.wait_window(dialog)
            target_symlink = result[0]
            
        if not target_symlink:
            return

        # Custom confirmation dialog for better styling
        confirm = tk.Toplevel(self.root)
        confirm.title("Confirm Delete")
        confirm.geometry("450x180")
        confirm.configure(bg="#2E2E2E") # Enforce dark background
        
        tk.Label(confirm, text="Are you sure you want to delete this rule?", 
                 font=("Sans", 11), bg="#2E2E2E", fg="white", pady=15).pack()
        
        # Styled warning for the name
        tk.Label(confirm, text=target_symlink, font=("Sans", 14, "bold"), 
                 fg="#ff5555", bg="#2E2E2E").pack(pady=5)
                 
        tk.Label(confirm, text=f"This will remove /etc/udev/rules.d/99-{target_symlink}.rules", 
                 fg="#cccccc", bg="#2E2E2E", font=("Sans", 9)).pack(pady=5) # Lighter grey for better visibility
        
        result = [False]
        def on_yes():
            result[0] = True
            confirm.destroy()
            
        def on_no():
            confirm.destroy()
            
        btn_box = ttk.Frame(confirm) # TFrame automatically picks up dark style from configure(".")
        btn_box.pack(pady=20)
        
        # Use simple tk.Button if ttk buttons in dialog struggle with styles, 
        # but since we styled TButton globally, it should be fine.
        ttk.Button(btn_box, text="Cancel", command=on_no).pack(side=tk.LEFT, padx=10)
        ttk.Button(btn_box, text="Delete", command=on_yes).pack(side=tk.LEFT, padx=10)
        
        # Make modal
        confirm.transient(self.root)
        confirm.grab_set()
        self.root.wait_window(confirm)

        if result[0]:
             success, msg = self.mgr.delete_rule(target_symlink)
             if success:
                 self.status_var.set("Rule deleted. Reloading...")
                 self.root.update_idletasks()
                 self.mgr.reload_udev()
                 messagebox.showinfo("Success", f"{msg}\n\nUdev reloaded.")
                 self.refresh_devices(silent=False) # Force refresh list
             else:
                 messagebox.showerror("Error", msg)

    def reload_rules(self):
        self.status_var.set("Reloading udev...")
        self.root.update_idletasks()
        success, msg = self.mgr.reload_udev()
        if success:
            messagebox.showinfo("Success", msg)
            self.status_var.set("Udev reloaded.")
        else:
            messagebox.showerror("Error", msg)
            self.status_var.set("Reload failed.")

if __name__ == "__main__":
    ensure_root()
    root = tk.Tk()
    app = USBNamerApp(root)
    root.mainloop()
