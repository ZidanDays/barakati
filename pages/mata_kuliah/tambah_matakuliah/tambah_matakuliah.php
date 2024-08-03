    <?php
    include './conf/conf.php'; // Include database connection file

    // Check if user is an admin
    if ($_SESSION['role'] !== 'admin') {
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

    if ($_SERVER["REQUEST_METHOD"] == "POST") {
        $kode = $_POST['kode'];
        $nama = $_POST['nama'];
        $jam_mulai = $_POST['jam_mulai'];
        $jam_selesai = $_POST['jam_selesai'];
        $hari = $_POST['hari'];

        // Ubah format waktu ke format yang sesuai untuk database (HH:mm:ss)
        $jam_mulai = date('H:i:s', strtotime($jam_mulai));
        $jam_selesai = date('H:i:s', strtotime($jam_selesai));

        // Insert mata kuliah into the database
        $stmt = $conn->prepare("INSERT INTO mata_kuliah (kode, nama, jam_mulai, jam_selesai, hari) VALUES (?, ?, ?, ?, ?)");
        $stmt->bind_param("sssss", $kode, $nama, $jam_mulai, $jam_selesai, $hari);
        if ($stmt->execute()) {
            echo "<script>
                    window.onload = function() {
                        Swal.fire({
                            icon: 'success',
                            title: 'Success',
                            text: 'Mata kuliah added successfully.'
                        }).then(function() {
                            window.location = '?q=mata_kuliah';
                        });
                    }
                </script>";
        } else {
            echo "<script>
                    window.onload = function() {
                        Swal.fire({
                            icon: 'error',
                            title: 'Error',
                            text: 'Error adding mata kuliah.'
                        }).then(function() {
                            window.location = '?q=mata_kuliah';
                        });
                    }
                </script>";
        }

        $stmt->close();
        $conn->close();
    }
