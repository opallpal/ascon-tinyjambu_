@echo off
cd /d "%~dp0"
echo ===============================================================
echo       MENU PENGUJIAN MANUAL & OTOMATIS ASCON-128 AEAD
echo ===============================================================
echo 1. Uji Manual Skenario S1 (Baseline 256B, UART vs MQTT)
echo 2. Uji Manual Skenario S2 (Variasi Ukuran Payload: 64, 256, 1024B)
echo 3. Uji Manual Skenario S3 (Konkurensi: 1, 10, 50 Perangkat Paralel)
echo 4. Uji Manual Skenario S4 (Keamanan: Normal vs 4 Serangan Manipulasi)
echo ---------------------------------------------------------------
echo 5. Uji Penuh Semua Skenario (S1-S4 Batch 31x + Buat Grafik Baru)
echo 6. Uji Cepat Semua Skenario (S1-S4 Versi Kilat 5x)
echo 7. Keluar
echo ===============================================================
set /p pilihan="Pilih nomor skenario (1-7): "

if "%pilihan%"=="1" (
    echo.
    echo Menjalankan Pengujian Manual Skenario S1...
    python uji_manual.py S1 --repetitions 31
    pause
)
if "%pilihan%"=="2" (
    echo.
    echo Menjalankan Pengujian Manual Skenario S2...
    python uji_manual.py S2 --repetitions 31
    pause
)
if "%pilihan%"=="3" (
    echo.
    echo Menjalankan Pengujian Manual Skenario S3...
    python uji_manual.py S3
    pause
)
if "%pilihan%"=="4" (
    echo.
    echo Menjalankan Pengujian Manual Skenario S4...
    python uji_manual.py S4 --repetitions 31
    pause
)
if "%pilihan%"=="5" (
    echo.
    echo Menjalankan uji penuh semua skenario (31 repetitions)...
    python run_benchmark.py
    echo.
    echo Menghitung statistik dan memperbarui grafik...
    python analyze.py
    echo.
    echo Membuka dashboard hasil...
    start http://localhost:8000/dashboard/index.html
    pause
)
if "%pilihan%"=="6" (
    echo.
    echo Menjalankan uji cepat semua skenario (5 repetitions)...
    python run_benchmark.py --repetitions 5 --warmup 2
    echo.
    echo Menghitung statistik dan memperbarui grafik...
    python analyze.py
    echo.
    echo Membuka dashboard hasil...
    start http://localhost:8000/dashboard/index.html
    pause
)
