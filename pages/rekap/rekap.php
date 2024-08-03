<div class="container">
    <div class="page-inner">
        <div class="d-flex align-items-left align-items-md-center flex-column flex-md-row pt-2 pb-4">
            <div>
                <h3 class="fw-bold mb-3">Rekap Absensi</h3>
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
                            <div class="card-title">Rekap Absensi</div>
                            <div class="card-tools">
                                <a href="#" id="download-csv-btn" class="btn btn-label-success btn-round btn-sm me-2">
                                    <span class="btn-label">
                                        <i class="fa fa-pencil"></i>
                                    </span>
                                    Export
                                </a>
                            </div>
                        </div>
                    </div>
                    <div class="card-body">
                        <div class="table-responsive">
                            <table id="basic-datatables" class="table table-responsive text-center table-hover">
                                <thead>
                                    <tr>
                                        <th>Nama Mahasiswa</th>
                                        <th>Kode Mata Kuliah</th>
                                        <th>Nama Mata Kuliah</th>
                                        <th>Waktu Scan</th>
                                        <th>Status</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    <?php
                                    include './conf/conf.php'; // Include database connection file

                                    // Query untuk mengambil data dari tabel laporan_scan
                                    $query = "SELECT * FROM laporan_scan";
                                    $result = $conn->query($query);

                                    // Tampilkan baris tabel dengan data yang diambil
                                    if ($result->num_rows > 0) {
                                        while ($row = $result->fetch_assoc()) {
                                            // Ambil nama mahasiswa berdasarkan mahasiswa_id
                                            $mahasiswa_id = $row['mahasiswa_id'];
                                            $query_mahasiswa = "SELECT username FROM users WHERE id = ?";
                                            $stmt_mahasiswa = $conn->prepare($query_mahasiswa);
                                            $stmt_mahasiswa->bind_param("i", $mahasiswa_id);
                                            $stmt_mahasiswa->execute();
                                            $stmt_mahasiswa->bind_result($nama_mahasiswa);
                                            $stmt_mahasiswa->fetch();
                                            $stmt_mahasiswa->close();

                                            // Ambil data mata kuliah berdasarkan matakuliah_id
                                            $matakuliah_id = $row['matakuliah_id'];
                                            $query_matakuliah = "SELECT kode, nama FROM mata_kuliah WHERE id = ?";
                                            $stmt_matakuliah = $conn->prepare($query_matakuliah);
                                            $stmt_matakuliah->bind_param("i", $matakuliah_id);
                                            $stmt_matakuliah->execute();
                                            $stmt_matakuliah->bind_result($kode_mk, $nama_mk);
                                            $stmt_matakuliah->fetch();
                                            $stmt_matakuliah->close();
                                    ?>
                                    <tr>
                                        <td><?php echo htmlspecialchars($nama_mahasiswa); ?></td>
                                        <td><?php echo htmlspecialchars($kode_mk); ?></td>
                                        <td><?php echo htmlspecialchars($nama_mk); ?></td>
                                        <td><?php echo htmlspecialchars($row['waktu_scan']); ?></td>
                                        <td><?php echo htmlspecialchars($row['status']); ?></td>
                                    </tr>
                                    <?php
                                        }
                                    } else {
                                        // Jika tidak ada data, tampilkan pesan kosong
                                        echo '<tr><td colspan="5">Tidak ada data tersedia</td></tr>';
                                    }

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

<script>
document.getElementById('download-csv-btn').addEventListener('click', function() {
    fetch('expor.php?q=expor')
        .then(response => response.blob())
        .then(blob => {
            const url = window.URL.createObjectURL(new Blob([blob]));
            const a = document.createElement('a');
            a.href = url;
            a.download = 'rekap_absensi.csv';
            document.body.appendChild(a);
            a.click();
            setTimeout(() => {
                window.URL.revokeObjectURL(url);
                document.body.removeChild(a);
            }, 0);
        })
        .catch(error => console.error('Error downloading CSV:', error));
});
</script>