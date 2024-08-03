<?php
session_start();
include '../conf/conf.php'; // Include database connection file

if ($_SERVER["REQUEST_METHOD"] == "POST" && isset($_POST['qrcode_id']) && isset($_POST['timezone'])) {
    $qrcode_id = $_POST['qrcode_id'];
    $timezone = $_POST['timezone'];
    $mahasiswa_id = $_SESSION['user_id'];

    // Set timezone sesuai dengan timezone dari klien
    date_default_timezone_set($timezone);

    $waktu_scan = new DateTime(); // Waktu scan saat ini
    $status = ''; // Status awal kosong, akan ditentukan berdasarkan logika berikut

    // Ambil data jam_mulai, jam_selesai, dan hari dari tabel mata_kuliah berdasarkan matakuliah_id
    $query_matakuliah = "SELECT jam_mulai, jam_selesai, hari FROM mata_kuliah WHERE id = ?";
    $stmt_matakuliah = $conn->prepare($query_matakuliah);
    $stmt_matakuliah->bind_param("i", $qrcode_id);
    $stmt_matakuliah->execute();
    $stmt_matakuliah->bind_result($jam_mulai, $jam_selesai, $hari);
    $stmt_matakuliah->fetch();
    $stmt_matakuliah->close();

    // Konversi jam_mulai dan jam_selesai dari database menjadi objek DateTime
    $jam_mulai_dt = DateTime::createFromFormat('H:i:s', $jam_mulai);
    $jam_selesai_dt = DateTime::createFromFormat('H:i:s', $jam_selesai);

    // Periksa apakah waktu scan berada di antara jam_mulai dan jam_selesai, serta pada hari yang sesuai
    if ($waktu_scan >= $jam_mulai_dt && $waktu_scan <= $jam_selesai_dt && $waktu_scan->format('D') === $hari) {
        $status = "Hadir";
    } elseif ($waktu_scan > $jam_selesai_dt || $waktu_scan->format('D') !== $hari) {
        $status = "Terlambat";
    } else {
        $status = "Tidak Hadir";
    }

    // Simpan hasil scan ke dalam database
    $query_insert = "INSERT INTO laporan_scan (mahasiswa_id, matakuliah_id, waktu_scan, status) 
    VALUES (?, ?, ?, ?)";
    $stmt_insert = $conn->prepare($query_insert);
    $stmt_insert->bind_param("iiss", $mahasiswa_id, $qrcode_id, $waktu_scan->format('Y-m-d H:i:s'), $status);

    if ($stmt_insert->execute()) {
        echo json_encode(["success" => true, "message" => "Scan berhasil direkam.", "status" => $status]);
    } else {
        echo json_encode(["success" => false, "message" => "Gagal menyimpan hasil scan."]);
    }

    $stmt_insert->close();
} else {
    echo json_encode(["success" => false, "message" => "Data tidak valid."]);
}

$conn->close();
?>