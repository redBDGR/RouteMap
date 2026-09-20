"""PyInstaller entry point: pyinstaller --onefile --console --name routemap main.py"""

from routemap.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
