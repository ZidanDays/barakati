<?php
include '../conf/conf.php'; // Include database connection file

// Pastikan user yang login adalah mahasiswa
if ($_SESSION['role'] !== 'mahasiswa') {
    echo "<script>
            window.onload = function() {
                Swal.fire({
                    icon: 'error',
                    title: 'Unauthorized Access',
                    text: 'You do not have permission to access this page.'
                }).then(function() {
                    window.location = '?q=beranda';
                });
            }
          </script>";
    exit;
}

$mahasiswa_id = $_SESSION['user_id']; // Assuming you have stored user id in session
?>

<div class="container">
    <div class="page-inner">
        <div class="d-flex align-items-left align-items-md-center flex-column flex-md-row pt-2 pb-4">
            <div>
                <h3 class="fw-bold mb-3">Scan QR Code Mata Kuliah</h3>
                <h6 class="op-7 mb-2">Monitoring Page - See The Monitoring System</h6>
            </div>
            <div class="ms-md-auto py-2 py-md-0">
                <a href="?q=beranda" class="btn btn-primary btn-round">Dashboard</a>
            </div>
        </div>

        <div class="row justify-content-center">
            <div class="col-md-8">
                <div class="card card-round">
                    <div class="card-header">
                        <div style="text-align: center;">
                            <div class="card-title">Scan QR Code Mata Kuliah Anda</div>
                        </div>
                    </div>
                    <div class="card-body">
                        <div class="text-center mb-2">
                            <div id="qr-reader" class="qr-reader"></div>
                        </div>
                    </div>
                    <div class="text-center mb-4">
                        <button id="toggle-camera" class="btn btn-primary">
                            <i class="fas fa-camera-retro fa-spin fa-2x"></i>
                        </button>
                    </div>

                </div>
            </div>
        </div>
    </div>
</div>


<script>
let currentFacingMode = "environment";

function onScanSuccess(decodedText, decodedResult) {
    console.log(`Code scanned = ${decodedText}`, decodedResult);

    var timezone = Intl.DateTimeFormat().resolvedOptions().timeZone;

    $.ajax({
        type: 'POST',
        url: 'process_scan.php',
        data: {
            qrcode_id: decodedText,
            timezone: timezone // Tambahkan zona waktu ke data yang dikirim
        },
        success: function(response) {
            Swal.fire({
                icon: 'success',
                title: 'Scan Berhasil',
                text: 'Scan berhasil direkam.'
            }).then(function() {
                window.location = '?q=beranda';
            });
        },
        error: function(xhr, status, error) {
            console.error('AJAX Error:', status, error);
            Swal.fire({
                icon: 'error',
                title: 'Scan Gagal',
                text: 'Gagal melakukan scan QR Code. Silakan coba lagi.'
            });
        },
        timeout: 3000 // Timeout set to 3 seconds
    });
}

document.addEventListener('DOMContentLoaded', function() {
    const html5QrCode = new Html5Qrcode("qr-reader");

    function startScanner() {
        html5QrCode.start({
                facingMode: currentFacingMode
            }, {
                fps: 10,
                qrbox: function(viewfinderWidth, viewfinderHeight) {
                    let minEdgePercentage = 0.8;
                    let minEdgeSize = Math.min(viewfinderWidth, viewfinderHeight);
                    let qrboxSize = Math.floor(minEdgeSize * minEdgePercentage);
                    return {
                        width: qrboxSize,
                        height: qrboxSize
                    };
                }
            },
            onScanSuccess
        ).catch(error => {
            console.error('Error:', error);
            Swal.fire({
                icon: 'error',
                title: 'Scan Gagal',
                text: 'Gagal memulai pemindaian QR Code. Silakan coba lagi.'
            });
        });
    }

    startScanner();

    document.getElementById('toggle-camera').addEventListener('click', function() {
        html5QrCode.stop().then(() => {
            currentFacingMode = currentFacingMode === "environment" ? "user" : "environment";
            startScanner();
        }).catch(err => {
            console.error('Failed to stop scanner:', err);
            Swal.fire({
                icon: 'error',
                title: 'Error',
                text: 'Gagal menghentikan pemindaian QR Code.'
            });
        });
    });
});
</script>

<style>
.qr-reader {
    width: 100%;
    max-width: 100%;
    /* Maksimal lebar untuk perangkat besar */
    height: auto;
    /* Otomatis menyesuaikan tinggi berdasarkan lebar */
}

.mirror {
    transform: scaleX(-1);
}
</style>