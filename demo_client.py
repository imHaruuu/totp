import customtkinter as ctk
import base64
import time
import threading
import sys
import os
import urllib.parse

# Ensure we can import from the same directory
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
try:
    from totp import generate_totp
except ImportError:
    # Fallback if totp.py is not strictly in the path or if run differently
    from .totp import generate_totp

class MainFrame(ctk.CTkFrame):
    """
    Single mode frame:
    - Input: Base32 Secret
    - Output: Live TOTP code
    """
    

    def __init__(self, master):
        super().__init__(master, fg_color="transparent")
        self.running = True
        
        # -- Header --
        self.header = ctk.CTkFrame(self, fg_color="transparent")
        self.header.pack(fill="x", pady=(10, 20))
        
        self.title = ctk.CTkLabel(
            self.header, 
            text="TOTP Generator",
            font=ctk.CTkFont(size=24, weight="bold")
        )
        self.title.pack()
        
        self.subtitle = ctk.CTkLabel(
            self.header, 
            text="Enter Base32 secret or otpauth:// URI",
            font=ctk.CTkFont(size=12), text_color="gray"
        )
        self.subtitle.pack()

        # -- Input Section --
        self.input_frame = ctk.CTkFrame(self)
        self.input_frame.pack(fill="x", padx=20, pady=10)
        
        self.label_secret = ctk.CTkLabel(
            self.input_frame, 
            text="Secret Key / URI:",
            font=ctk.CTkFont(size=12, weight="bold")
        )
        self.label_secret.pack(anchor="w", padx=15, pady=(15, 5))
        
        self.input_container = ctk.CTkFrame(self.input_frame, fg_color="transparent")
        self.input_container.pack(fill="x", pady=(0, 15))

        self.secret_entry = ctk.CTkEntry(
            self.input_container,
            placeholder_text="Paste Secret Key, URI, or Scan QR"
        )

        self.secret_entry.pack(side="left", fill="x", expand=True, padx=(15, 5))
        
        self.btn_scan = ctk.CTkButton(
            self.input_container,
            text="Scan QR",
            width=60,
            height=35,
            font=ctk.CTkFont(size=11),
            command=self._scan_qr
        )
        self.btn_scan.pack(side="right", padx=(5, 15))
        
        # Metadata Display
        self.metadata_frame = ctk.CTkFrame(self.input_frame, fg_color="transparent")
        self.metadata_frame.pack(fill="x", padx=15, pady=(0, 15))
        
        self.label_issuer = ctk.CTkLabel(
            self.metadata_frame, text="", font=ctk.CTkFont(size=11, weight="bold"), text_color="gray"
        )
        self.label_issuer.pack(anchor="w")
        
        self.label_account = ctk.CTkLabel(
            self.metadata_frame, text="", font=ctk.CTkFont(size=11), text_color="gray"
        )
        self.label_account.pack(anchor="w")

        # -- Output Section --
        self.output_frame = ctk.CTkFrame(self)
        self.output_frame.pack(fill="x", padx=20, pady=10)
        
        self.otp_label_title = ctk.CTkLabel(
            self.output_frame, 
            text="Current Code",
            font=ctk.CTkFont(size=12), text_color="gray"
        )
        self.otp_label_title.pack(pady=(15, 2))
        
        self.otp_display = ctk.CTkLabel(
            self.output_frame, 
            text="------",
            font=ctk.CTkFont(family="Consolas", size=48, weight="bold"),
            text_color="gray"
        )
        self.otp_display.pack(pady=5)
        
        self.progress_bar = ctk.CTkProgressBar(self.output_frame, width=250, height=8)
        self.progress_bar.set(0)
        self.progress_bar.pack(pady=(5, 10))
        
        self.countdown_label = ctk.CTkLabel(
            self.output_frame, 
            text="0s",
            font=ctk.CTkFont(size=12), text_color="gray"
        )
        self.countdown_label.pack(pady=(0, 15))
        
        # Start background thread
        self.update_thread = threading.Thread(target=self._update_loop, daemon=True)
        self.update_thread.start()

    def _scan_qr(self):
        try:
            from tkinter import filedialog
            import cv2
            
            file_path = filedialog.askopenfilename(
                title="Select QR Code Image",
                filetypes=[("Image Files", "*.png;*.jpg;*.jpeg;*.bmp")]
            )
            
            if not file_path:
                return
                
            # Read and decode
            img = cv2.imread(file_path)
            detector = cv2.QRCodeDetector()
            data, bbox, _ = detector.detectAndDecode(img)
            
            if data:
                self.secret_entry.delete(0, "end")
                self.secret_entry.insert(0, data)
            else:
                self.otp_display.configure(text="NO QR", text_color=("orange", "orange"))
                
        except Exception as e:
            print(f"QR Error: {e}")
            self.otp_display.configure(text="ERR", text_color=("red", "red"))

    def _update_otp(self):
        if not self.running:
            return
        
        input_text = self.secret_entry.get().strip()
        
        current_time = int(time.time())
        remaining = 30 - (current_time % 30)
        
        self.progress_bar.set(remaining / 30)
        self.countdown_label.configure(text=f"{remaining}s")
        
        secret = input_text
        issuer = ""
        account = ""
        
        # Try to parse as URI or flexible string
        try:
            # 1. Extract Secret (looking for secret=XXX or just trying to use the regex on the whole string if it matches base32 pattern)
            # Regex for secret parameter
            import re
            secret_pattern = re.search(r'secret=([a-zA-Z2-7]+=*)', input_text, re.IGNORECASE)
            if secret_pattern:
                secret = secret_pattern.group(1)
            
            # 2. Extract Issuer
            issuer_pattern = re.search(r'issuer=([^&]+)', input_text, re.IGNORECASE)
            if issuer_pattern:
                issuer = urllib.parse.unquote(issuer_pattern.group(1))
            
            # 3. Extract Label/Account from URI path
            # Look for totp/Label:Account or just /Label:Account if user pasted partial path
            # Regex: match anything after totp/ until ? or end of string
            label_pattern = re.search(r'totp/([^?]+)', input_text, re.IGNORECASE)
            if label_pattern:
                label_raw = urllib.parse.unquote(label_pattern.group(1))
                if ":" in label_raw:
                    parts = label_raw.split(":", 1)
                    if not issuer: issuer = parts[0].strip()
                    account = parts[1].strip()
                else:
                    account = label_raw.strip()
            
        except Exception:
            pass # Fallback

        
        # Update Metadata UI
        if issuer or account:
            self.label_issuer.configure(text=f"Issuer: {issuer}" if issuer else "Issuer: (Unknown)")
            self.label_account.configure(text=f"Account: {account}" if account else "Account: (Unknown)")
        elif secret and len(secret) > 10: # Only show if we have a likely secret
            self.label_issuer.configure(text="Issuer: (None - Raw Secret)")
            self.label_account.configure(text="Account: (None)")
        else:
            self.label_issuer.configure(text="")
            self.label_account.configure(text="")

        if not secret:
            self.otp_display.configure(text="------", text_color="gray")
            return

        try:
            # Clean secret
            secret = secret.replace(" ", "").upper()
            
            # Padding
            padding_needed = len(secret) % 8
            if padding_needed != 0:
                padded_secret = secret + '=' * (8 - padding_needed)
            else:
                padded_secret = secret
            
            secret_bytes = base64.b32decode(padded_secret, casefold=True)
            otp = generate_totp(secret_bytes, timestamp=current_time, digits=6)
            
            self.otp_display.configure(text=otp)
            
            if remaining <= 5:
                self.otp_display.configure(text_color=("#ff6b6b", "#ff6b6b"))
            elif remaining <= 10:
                self.otp_display.configure(text_color=("#ffa500", "#ffa500"))
            else:
                self.otp_display.configure(text_color=("#00d2ff", "#00d2ff"))

        except Exception:
            self.otp_display.configure(text="INVALID", text_color=("#ff6b6b", "#ff6b6b"))

            
    def _update_loop(self):
        while self.running:
            try:
                # Use after to schedule GUI update on main thread
                # (ctk is explicitly not thread safe for direct config sometimes, but in callbacks it's usually ok 
                # if we are careful or use after. `after` is safer.)
                self.after(0, self._update_otp)
                time.sleep(0.1) # Faster update for smooth UI feeling if we updated every tick, 
                                # but 1s is enough for logic. 0.1s makes input response faster visually if we checked there.
                                # Let's stick to 0.2s to be responsive but not hog CPU.
                time.sleep(0.2)
            except:
                break


class TOTPDemoApp(ctk.CTk):
    """Main application window."""
    
    def __init__(self):
        super().__init__()
        
        self.title("TOTP Client")
        self.geometry("400x450")
        self.minsize(350, 400)
        
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")
        
        # Main container
        self.container = ctk.CTkFrame(self, fg_color="transparent")
        self.container.pack(fill="both", expand=True, padx=10, pady=10)
        
        # Theme Toggle
        self.theme_btn = ctk.CTkButton(
            self.container, 
            text="Theme", 
            width=50, 
            height=24,
            font=ctk.CTkFont(size=10),
            command=self._toggle_theme,
            fg_color="transparent", border_width=1,
            text_color=("gray10", "gray90")
        )
        self.theme_btn.place(relx=0.98, rely=0.01, anchor="ne")

        # Load Main Frame
        self.main_frame = MainFrame(self.container)
        self.main_frame.pack(fill="both", expand=True, pady=(30, 0)) # Space for theme btn
        
    def _toggle_theme(self):
        if ctk.get_appearance_mode() == "Dark":
            ctk.set_appearance_mode("light")
        else:
            ctk.set_appearance_mode("dark")

if __name__ == "__main__":
    app = TOTPDemoApp()
    app.mainloop()
