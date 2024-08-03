<div class="container">
    <div class="page-inner">
        <div class="d-flex align-items-left align-items-md-center flex-column flex-md-row pt-2 pb-4">
            <div>
                <h3 class="fw-bold mb-3">Tambah Mata Kuliah</h3>
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
                            <div class="card-tools">
                                <button class="btn btn-primary btn-round" data-toggle="modal"
                                    data-target="#addMataKuliahModal">Tambah Mata Kuliah</button>
                            </div>
                        </div>
                    </div>
                    <div class="card-body">
                        <div class="table-responsive">
                            <table class="table text-center">
                                <thead>
                                    <tr>
                                        <th>Kode</th>
                                        <th>Nama Mata Kuliah</th>
                                        <th>Jam Mulai</th>
                                        <th>Jam Selesai</th>
                                        <th>Hari</th>
                                        <th>Aksi</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    <?php
                                    include './conf/conf.php';
                                    $result = $conn->query("SELECT * FROM mata_kuliah");
                                    while ($row = $result->fetch_assoc()) :
                                    ?>
                                    <tr>
                                        <td><?= $row['kode'] ?></td>
                                        <td><?= $row['nama'] ?></td>
                                        <td><?= $row['jam_mulai'] ?></td>
                                        <td><?= $row['jam_selesai'] ?></td>
                                        <td><?= $row['hari'] ?></td>
                                        <td>
                                            <a href="?q=edit_matakuliah&id=<?= $row['id'] ?>"
                                                class="btn btn-sm btn-info">Edit</a>
                                            <button class="btn btn-sm btn-danger" data-toggle="modal"
                                                data-target="#deleteModal<?= $row['id'] ?>">Delete</button>
                                        </td>
                                    </tr>
                                    <?php endwhile;
                                    $conn->close();
                                    ?>
                                </tbody>
                            </table>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>
</div>

<!-- Modal Konfirmasi Delete -->
<?php
include './conf/conf.php';
$result = $conn->query("SELECT * FROM mata_kuliah");
while ($row = $result->fetch_assoc()) :
?>
<div class="modal fade" id="deleteModal<?= $row['id'] ?>" tabindex="-1" role="dialog"
    aria-labelledby="deleteModalLabel<?= $row['id'] ?>" aria-hidden="true">
    <div class="modal-dialog" role="document">
        <div class="modal-content">
            <form method="post" action="?q=delete_matakuliah">
                <div class="modal-header">
                    <h5 class="modal-title" id="deleteModalLabel<?= $row['id'] ?>">Konfirmasi Hapus Data</h5>
                    <button type="button" class="close" data-dismiss="modal" aria-label="Close">
                        <span aria-hidden="true">&times;</span>
                    </button>
                </div>
                <div class="modal-body">
                    <input type="hidden" name="id" value="<?= $row['id'] ?>">
                    <p>Anda yakin ingin menghapus data ini?</p>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-secondary" data-dismiss="modal">Batal</button>
                    <button type="submit" class="btn btn-danger">Hapus</button>
                </div>
            </form>
        </div>
    </div>
</div>
<?php endwhile; ?>

<!-- Modal Tambah Mata Kuliah -->
<div class="modal fade" id="addMataKuliahModal" tabindex="-1" role="dialog" aria-labelledby="addMataKuliahModalLabel"
    aria-hidden="true">
    <div class="modal-dialog" role="document">
        <div class="modal-content">
            <form method="post" action="?q=tambah_matakuliah">
                <div class="modal-header">
                    <h5 class="modal-title" id="addMataKuliahModalLabel">Tambah Mata Kuliah</h5>
                    <button type="button" class="close" data-dismiss="modal" aria-label="Close">
                        <span aria-hidden="true">&times;</span>
                    </button>
                </div>
                <div class="modal-body">
                    <div class="form-group">
                        <label for="kode">Kode Mata Kuliah</label>
                        <input type="text" class="form-control" id="kode" name="kode" required>
                    </div>
                    <div class="form-group">
                        <label for="nama">Nama Mata Kuliah</label>
                        <input type="text" class="form-control" id="nama" name="nama" required>
                    </div>
                    <div class="form-group">
                        <label for="jam_mulai">Jam Mulai</label>
                        <input type="time" class="form-control" id="jam_mulai" name="jam_mulai" required>
                    </div>
                    <div class="form-group">
                        <label for="jam_selesai">Jam Selesai</label>
                        <input type="time" class="form-control" id="jam_selesai" name="jam_selesai" required>
                    </div>
                    <div class="form-group">
                        <label for="hari">Hari</label>
                        <select class="form-control" id="hari" name="hari" required>
                            <option value="Monday">Monday</option>
                            <option value="Tuesday">Tuesday</option>
                            <option value="Wednesday">Wednesday</option>
                            <option value="Thursday">Thursday</option>
                            <option value="Friday">Friday</option>
                            <option value="Saturday">Saturday</option>
                            <!-- <option value="Minggu">Minggu</option> -->
                        </select>
                    </div>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-secondary" data-dismiss="modal">Close</button>
                    <button type="submit" class="btn btn-primary">Tambah Mata Kuliah</button>
                </div>
            </form>
        </div>
    </div>
</div>

<!-- Modal Edit Mata Kuliah -->
<div class="modal fade" id="editMataKuliahModal" tabindex="-1" role="dialog" aria-labelledby="editMataKuliahModalLabel"
    aria-hidden="true">
    <div class="modal-dialog" role="document">
        <div class="modal-content">
            <form id="editMataKuliahForm" method="post" action="?q=edit_matakuliah">
                <div class="modal-header">
                    <h5 class="modal-title" id="editMataKuliahModalLabel">Edit Mata Kuliah</h5>
                    <button type="button" class="close" data-dismiss="modal" aria-label="Close">
                        <span aria-hidden="true">&times;</span>
                    </button>
                </div>
                <div class="modal-body">
                    <input type="hidden" id="edit_id" name="id">
                    <!-- Input untuk Kode Mata Kuliah (ditampilkan sebagai readonly) -->
                    <div class="form-group">
                        <label for="edit_kode">Kode Mata Kuliah</label>
                        <input type="text" class="form-control" id="edit_kode" name="kode" readonly>
                    </div>
                    <!-- Input untuk Nama Mata Kuliah -->
                    <div class="form-group">
                        <label for="edit_nama">Nama Mata Kuliah</label>
                        <input type="text" class="form-control" id="edit_nama" name="nama" required>
                    </div>
                    <!-- Input untuk Jam Mulai -->
                    <div class="form-group">
                        <label for="edit_jam_mulai">Jam Mulai</label>
                        <input type="time" class="form-control" id="edit_jam_mulai" name="jam_mulai" required>
                    </div>
                    <!-- Input untuk Jam Selesai -->
                    <div class="form-group">
                        <label for="edit_jam_selesai">Jam Selesai</label>
                        <input type="time" class="form-control" id="edit_jam_selesai" name="jam_selesai" required>
                    </div>
                    <!-- Input untuk Hari -->
                    <div class="form-group">
                        <label for="edit_hari">Hari</label>
                        <select class="form-control" id="edit_hari" name="hari" required>
                            <option value="Senin">Senin</option>
                            <option value="Selasa">Selasa</option>
                            <option value="Rabu">Rabu</option>
                            <option value="Kamis">Kamis</option>
                            <option value="Jumat">Jumat</option>
                            <option value="Sabtu">Sabtu</option>
                            <option value="Minggu">Minggu</option>
                        </select>
                    </div>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-secondary" data-dismiss="modal">Close</button>
                    <button type="submit" class="btn btn-primary">Simpan Perubahan</button>
                </div>
            </form>
        </div>
    </div>
</div>