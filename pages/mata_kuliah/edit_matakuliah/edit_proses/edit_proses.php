<?php
include './conf/conf.php'; // Pastikan ini mengarah ke file konfigurasi database yang benar

// Pastikan form dikirim dengan metode POST
if ($_SERVER["REQUEST_METHOD"] == "POST") {
    // Ambil data dari form
    $id = $_POST['id'];
    $nama = $_POST['nama'];
    $jam_mulai = $_POST['jam_mulai'];
    $jam_selesai = $_POST['jam_selesai'];
    $hari = $_POST['hari'];

    // Validasi data (contoh sederhana)
    if (empty($id) || empty($nama) || empty($jam_mulai) || empty($jam_selesai) || empty($hari)) {
        // Handle error jika ada data yang kosong
        echo "<script>
                window.onload = function() {
                    Swal.fire({
                        icon: 'error',
                        title: 'Error',
                        text: 'Harap lengkapi semua data.'
                    }).then(function() {
                        window.location = '?q=mata_kuliah';
                    });
                }
              </script>";
        exit;
    }

    // Lakukan proses update ke database
    $query = "UPDATE mata_kuliah SET nama = ?, jam_mulai = ?, jam_selesai = ?, hari = ? WHERE id = ?";
    $stmt = $conn->prepare($query);
    $stmt->bind_param("ssssi", $nama, $jam_mulai, $jam_selesai, $hari, $id);

    if ($stmt->execute()) {
        // Jika query berhasil dijalankan
        echo "<script>
                window.onload = function() {
                    Swal.fire({
                        icon: 'success',
                        title: 'Success',
                        text: 'Data mata kuliah berhasil diupdate.'
                    }).then(function() {
                        window.location = '?q=mata_kuliah';
                    });
                }
              </script>";
    } else {
        // Jika terjadi error saat menjalankan query
        echo "<script>
                window.onload = function() {
                    Swal.fire({
                        icon: 'error',
                        title: 'Error',
                        text: 'Gagal mengupdate data: " . $conn->error . "'
                    }).then(function() {
                        window.location = '?q=mata_kuliah';
                    });
                }
              </script>";
    }

    // Tutup statement dan koneksi
    $stmt->close();
    $conn->close();
}
