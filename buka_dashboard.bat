@echo off
cd /d "%~dp0"
echo =========================================================
echo   Membuka Real-Time Dashboard ASCON-128 AEAD (FastAPI)
echo =========================================================
echo.
echo Menjalankan browser...
start http://localhost:8000
echo Menjalankan server backend real-time di port 8000...
echo (Jangan tutup jendela ini selama menggunakan dashboard)
echo.
python live_server.py
