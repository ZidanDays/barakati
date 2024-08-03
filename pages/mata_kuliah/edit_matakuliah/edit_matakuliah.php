<?php
include './conf/conf.php';

// Pastikan id disediakan dalam parameter GET
if (!isset($_GET['id'])) {
    // Jika tidak ada id, lakukan penanganan error atau redirect ke halaman yang sesuai
    echo "Invalid request.";
    exit;
}

$id = $_GET['id'];

// Query untuk mengambil data mata kuliah berdasarkan ID
$stmt = $conn->prepare("SELECT * FROM mata_kuliah WHERE id = ?");
$stmt->bind_param("i", $id);
$stmt->execute();
$result = $stmt->get_result();

if ($result->num_rows === 0) {
    // Jika tidak ada data dengan ID yang diberikan, lakukan penanganan error
    echo "Data not found.";
    exit;
}

// Ambil data mata kuliah dari hasil query
$mata_kuliah = $result->fetch_assoc();

// Tutup statement
$stmt->close();
$conn->close();
?>

<!-- HTML untuk Form Edit Mata Kuliah -->
<div class="container">
    <div class="page-inner">
        <div class="d-flex align-items-left align-items-md-center flex-column flex-md-row pt-2 pb-4">
            <div>
                <h3 class="fw-bold mb-3">Edit Mata Kuliah</h3>
                <h6 class="op-7 mb-2">Monitoring Page - See The Monitoring System</h6>
            </div>
            <div class="ms-md-auto py-2 py-md-0">
                <a href="?q=beranda" class="btn btn-primary btn-round">Dashboard</a>
            </div>
        </div>

        <div class="row">
            <div class="col-md-12">
                <div class="card card-round">
                    <div class="card-header">
                        <div class="card-head-row">
                            <div class="card-title">Mata Kuliah</div>
                        </div>
                    </div>
                    <div class="card-body">
                        <form method="post" action="?q=edit_proses">
                            <input type="hidden" name="id" value="<?= $mata_kuliah['id'] ?>">
                            <div class="form-group">
                                <label for="nama">Nama Mata Kuliah</label>
                                <input type="text" class="form-control" id="nama" name="nama" value="<?= $mata_kuliah['nama'] ?>" required>
                            </div>
                            <div class="form-group">
                                <label for="jam_mulai">Jam Mulai</label>
                                <input type="time" class="form-control" id="jam_mulai" name="jam_mulai" value="<?= $mata_kuliah['jam_mulai'] ?>" required>
                            </div>
                            <div class="form-group">
                                <label for="jam_selesai">Jam Selesai</label>
                                <input type="time" class="form-control" id="jam_selesai" name="jam_selesai" value="<?= $mata_kuliah['jam_selesai'] ?>" required>
                            </div>
                            <div class="form-group">
                                <label for="hari">Hari</label>
                                <select class="form-control" id="hari" name="hari" required>
                                    <option value="Senin" <?= ($mata_kuliah['hari'] == 'Senin') ? 'selected' : '' ?>>
                                        Senin</option>
                                    <option value="Selasa" <?= ($mata_kuliah['hari'] == 'Selasa') ? 'selected' : '' ?>>
                                        Selasa</option>
                                    <option value="Rabu" <?= ($mata_kuliah['hari'] == 'Rabu') ? 'selected' : '' ?>>Rabu
                                    </option>
                                    <option value="Kamis" <?= ($mata_kuliah['hari'] == 'Kamis') ? 'selected' : '' ?>>
                                        Kamis</option>
                                    <option value="Jumat" <?= ($mata_kuliah['hari'] == 'Jumat') ? 'selected' : '' ?>>
                                        Jumat</option>
                                    <option value="Sabtu" <?= ($mata_kuliah['hari'] == 'Sabtu') ? 'selected' : '' ?>>
                                        Sabtu</option>
                                    <option value="Minggu" <?= ($mata_kuliah['hari'] == 'Minggu') ? 'selected' : '' ?>>
                                        Minggu</option>
                                </select>
                            </div>
                            <button type="submit" class="btn btn-primary">Simpan Perubahan</button>
                        </form>
                    </div>
                </div>
            </div>
        </div>
    </div>
</div>