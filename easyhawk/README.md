# 🦅 EasyHawk — Easy Memory Scanner

A beginner-friendly memory scanner for Windows. Same power as Cheat Engine, way easier to use.

---

## 🚀 How to Run / Build the .exe

### Requirements
- Windows 10 or 11
- Python 3.10+ → https://www.python.org/downloads/
  - ✅ During install, check **"Add Python to PATH"**

---

### Option A: Run directly (no .exe needed)
```
Right-click → "Run as Administrator" on your terminal, then:

python easyhawk.py
```

---

### Option B: Build a standalone .exe

Open a terminal **as Administrator** and run:

```bash
# Step 1: Install PyInstaller
pip install pyinstaller

# Step 2: Build the exe (run from the easyhawk folder)
pyinstaller --onefile --windowed --name EasyHawk easyhawk.py

# Step 3: Your exe is in the dist/ folder
```

Then just double-click `dist/EasyHawk.exe` — always run as Administrator!

---

## 📖 How to Use

### 1. Attach to a Process
- Find your game or app in the **left panel**
- Use the search box to filter by name
- **Double-click** (or click Attach) to connect

### 2. First Scan
- Enter the value you see in-game (e.g. Health = 100)
- Choose value type (usually **Integer 4 byte** for most games)
- Click **🔍 First Scan**

### 3. Next Scan (narrow it down)
- Change the value in-game (take damage, spend gold, etc.)
- Enter the **new** value in the box
- Click **⟳ Next Scan**
- Repeat until you have just a few addresses (ideally 1–5)

### 4. Save & Edit
- **Double-click** a result to add it to Saved Addresses
- **Double-click the Value column** in Saved Addresses to change it
- Click **🔒 Toggle Freeze** to lock the value permanently

---

## ⚠️ Important Notes

- **Always run as Administrator** — without it, memory access will be denied
- Only use on **single-player games** — online games detect this and may ban you
- Some system/protected processes can't be accessed (this is normal)

---

## 💡 Tips

| Situation | What to do |
|---|---|
| Too many results (1000+) | Change value in-game, do Next Scan |
| No results found | Make sure you typed the exact in-game value |
| Write failed | Run as Administrator |
| Can't attach to process | Try a different process; system processes are protected |
