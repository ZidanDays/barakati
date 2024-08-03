<?php
include './conf/conf.php';

if ($_SERVER["REQUEST_METHOD"] == "POST") {
    $id = $_POST['id'];

    // Lakukan proses delete data dari database
    $query = "DELETE FROM mata_kuliah WHERE id = ?";
    $stmt = $conn->prepare($query);
    $stmt->bind_param("i", $id);

    if ($stmt->execute()) {
        // Jika query berhasil dijalankan
        echo "<script>
                Swal.fire({
                    icon: 'success',
                    title: 'Success',
                    text: 'Data mata kuliah berhasil dihapus.'
                }).then(function() {
                    window.location = '?q=mata_kuliah';
                });
              </script>";
    } else {
        // Jika terjadi error saat menjalankan query
        echo "<script>
                Swal.fire({
                    icon: 'error',
                    title: 'Error',
                    text: 'Gagal menghapus data: " . $conn->error . "'
                });
              </script>";
    }

    // Tutup statement dan koneksi
    $stmt->close();
    $conn->close();
}
