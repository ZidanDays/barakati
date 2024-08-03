<?php
include '../conf/conf.php'; // Include database connection file

if ($_SERVER["REQUEST_METHOD"] == "POST" && isset($_FILES["profile_pic"])) {
    $user_id = $_SESSION['user_id'];
    $target_dir = "uploads/foto/";
    $target_file = $target_dir . basename($_FILES["profile_pic"]["name"]);
    $uploadOk = 1;
    $imageFileType = strtolower(pathinfo($target_file, PATHINFO_EXTENSION));

    // Hapus foto profil lama jika ada
    $stmt_select = $conn->prepare("SELECT profile_pic FROM users WHERE id = ?");
    $stmt_select->bind_param("i", $user_id);
    $stmt_select->execute();
    $stmt_select->store_result();
    $stmt_select->bind_result($old_profile_pic);
    $stmt_select->fetch();

    if (!empty($old_profile_pic)) {
        // Hapus foto profil lama dari direktori uploads
        if (file_exists($old_profile_pic)) {
            unlink($old_profile_pic);
        }
    }

    // Check if image file is a actual image or fake image
    $check = getimagesize($_FILES["profile_pic"]["tmp_name"]);
    if ($check !== false) {
        $uploadOk = 1;
    } else {
        echo "<script>
                Swal.fire({
                    icon: 'error',
                    title: 'Gagal!',
                    text: 'File yang diunggah bukan gambar.'
                }).then(function() {
                    window.location.href = '?q=profile';
                });
              </script>";
        $uploadOk = 0;
    }

    // Check file size
    if ($_FILES["profile_pic"]["size"] > 500000) { // 500KB max size
        echo "<script>
                Swal.fire({
                    icon: 'error',
                    title: 'Gagal!',
                    text: 'Ukuran file terlalu besar, maksimal 500KB.'
                }).then(function() {
                    window.location.href = '?q=profile';
                });
              </script>";
        $uploadOk = 0;
    }

    // Allow certain file formats
    if (
        $imageFileType != "jpg" && $imageFileType != "png" && $imageFileType != "jpeg"
        && $imageFileType != "gif"
    ) {
        echo "<script>
                Swal.fire({
                    icon: 'error',
                    title: 'Gagal!',
                    text: 'Format file tidak didukung. Hanya JPG, JPEG, PNG & GIF yang diizinkan.'
                }).then(function() {
                    window.location.href = '?q=profile';
                });
              </script>";
        $uploadOk = 0;
    }

    // Check if $uploadOk is set to 0 by an error
    if ($uploadOk == 0) {
        echo "<script>
                Swal.fire({
                    icon: 'error',
                    title: 'Gagal!',
                    text: 'File tidak dapat diunggah.'
                }).then(function() {
                    window.location.href = '?q=profile';
                });
              </script>";
    } else {
        if (move_uploaded_file($_FILES["profile_pic"]["tmp_name"], $target_file)) {
            // Update database with new profile picture path
            $stmt_update = $conn->prepare("UPDATE users SET profile_pic = ? WHERE id = ?");
            $stmt_update->bind_param("si", $target_file, $user_id);
            if ($stmt_update->execute()) {
                echo "<script>
                        Swal.fire({
                            icon: 'success',
                            title: 'Berhasil!',
                            text: 'File " . htmlspecialchars(basename($_FILES["profile_pic"]["name"])) . " berhasil diunggah.'
                        }).then(function() {
                            window.location.href = '?q=profile';
                        });
                      </script>";
            } else {
                echo "<script>
                        Swal.fire({
                            icon: 'error',
                            title: 'Gagal!',
                            text: 'Gagal mengupdate foto profil.'
                        }).then(function() {
                            window.location.href = '?q=profile';
                        });
                      </script>";
            }
            $stmt_update->close();
        } else {
            echo "<script>
                    Swal.fire({
                        icon: 'error',
                        title: 'Gagal!',
                        text: 'Gagal mengunggah file.'
                    }).then(function() {
                        window.location.href = '?q=profile';
                    });
                  </script>";
        }
    }
    $stmt_select->close();
    $conn->close();
}
