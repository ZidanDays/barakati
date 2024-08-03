<?php
// Set timezone
date_default_timezone_set('Asia/Kuala_Lumpur'); // Gantilah dengan timezone Anda

?>
<div class="container">
    <div class="page-inner">
        <div class="d-flex align-items-left align-items-md-center flex-column flex-md-row pt-2 pb-4">
            <div>
                <h3 class="fw-bold mb-3">Dashboard</h3>
                <h6 class="op-7 mb-2">Monitoring Page - See The Monitoring System</h6>
            </div>
            <div class="ms-md-auto py-2 py-md-0">
                <a href="#" class="btn btn-label-info btn-round me-2">Manage</a>
                <a href="?q=users" class="btn btn-primary btn-round">Add Users</a>
            </div>
        </div>
        <div class="row">
            <div class="col-sm-6 col-md-3">
                <div class="card card-stats card-round">
                    <div class="card-body">
                        <div class="row align-items-center">
                            <div class="col-icon">
                                <div class="icon-big text-center icon-primary bubble-shadow-small">
                                    <i class="fas fa-users"></i>
                                </div>
                            </div>
                            <?php
                            include './conf/conf.php';

                            $query = "SELECT COUNT(*) as jumlah_dosen FROM users WHERE role = 'dosen'";
                            $result = $conn->query($query);
                            $row = $result->fetch_assoc();
                            $jumlah_dosen = $row['jumlah_dosen'];

                            $conn->close();
                            ?>
                            <div class="col col-stats ms-3 ms-sm-0">
                                <div class="numbers">
                                    <p class="card-category">Jumlah Dosen</p>
                                    <h4 class="card-title"><?php echo htmlspecialchars($jumlah_dosen); ?></h4>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
            <div class="col-sm-6 col-md-3">
                <div class="card card-stats card-round">
                    <div class="card-body">
                        <div class="row align-items-center">
                            <div class="col-icon">
                                <div class="icon-big text-center icon-info bubble-shadow-small">
                                    <i class="fas fa-solid fa-user-graduate"></i>
                                </div>
                            </div>
                            <?php
                            include './conf/conf.php';

                            $query = "SELECT COUNT(*) as jumlah_mhs FROM users WHERE role = 'mahasiswa'";
                            $result = $conn->query($query);
                            $row = $result->fetch_assoc();
                            $jumlah_mhs = $row['jumlah_mhs'];

                            $conn->close();
                            ?>
                            <div class="col col-stats ms-3 ms-sm-0">
                                <div class="numbers">
                                    <p class="card-category">Jumlah Mahasiswa</p>
                                    <h4 class="card-title"><?php echo htmlspecialchars($jumlah_mhs); ?></h4>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
            <div class="col-sm-6 col-md-3">
                <div class="card card-stats card-round">
                    <div class="card-body">
                        <div class="row align-items-center">
                            <div class="col-icon">
                                <div class="icon-big text-center icon-success bubble-shadow-small">
                                    <i class="fas fa-solid fa-user-lock"></i>
                                </div>
                            </div>
                            <?php
                            include './conf/conf.php';

                            $query = "SELECT COUNT(*) as jumlah_admin FROM users WHERE role = 'admin'";
                            $result = $conn->query($query);
                            $row = $result->fetch_assoc();
                            $jumlah_admin = $row['jumlah_admin'];

                            $conn->close();
                            ?>
                            <div class="col col-stats ms-3 ms-sm-0">
                                <div class="numbers">
                                    <p class="card-category">Jumlah Admin</p>
                                    <h4 class="card-title"><?php echo htmlspecialchars($jumlah_admin); ?></h4>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
            <div class="col-sm-6 col-md-3">
                <div class="card card-stats card-round">
                    <div class="card-body">
                        <div class="row align-items-center">
                            <div class="col-icon">
                                <div class="icon-big text-center icon-secondary bubble-shadow-small">
                                    <i class="far fa-check-circle"></i>
                                </div>
                            </div>
                            <div class="col col-stats ms-3 ms-sm-0">
                                <div class="numbers">
                                    <p class="card-category">des 4</p>
                                    <h4 class="card-title">0</h4>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
        <div class="row">
            <div class="col-md-12">
                <div class="card card-round">
                    <div class="card-header">
                        <div class="card-head-row">
                            <div class="card-title">Bulletin Board</div>
                        </div>
                    </div>
                    <?php
                    include './conf/conf.php';

                    $no = 1;

                    // Ambil waktu saat ini dengan format Y-m-d H:i:s
                    $current_time = date('Y-m-d H:i:s');
                    // echo "Current Time: " . $current_time . "<br>"; // Debug output
                    $current_day = date('l');
                    // echo "Current Day: " . $current_day . "<br>"; // Debug output

                    // Query untuk mendapatkan semua data dari tabel mata_kuliah
                    $query = "SELECT * FROM mata_kuliah";
                    // $result = $conn->query($query);


                    if ($result->num_rows > 0) { ?>
                    <table class="table text-center">
                        <thead>
                            <tr>
                                <th>No</th>
                                <th>Kode Mata Kuliah</th>
                                <th>Nama Mata Kuliah</th>
                                <th>Jam Mulai</th>
                                <th>Jam Selesai</th>
                                <th>Hari</th>
                                <th>Status</th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php
                                    while ($row = $result->fetch_assoc()) {
                                        $current_time_check = date('H:i:s'); // Waktu saat ini tanpa tanggal
                                        $jam_mulai = $row['jam_mulai'];
                                        $jam_selesai = $row['jam_selesai'];
                                        $hari = $row['hari'];
                                        // echo "Mata Kuliah: " . $row['nama'] . ", Jam Mulai: " . $jam_mulai . ", Jam Selesai: " . $jam_selesai . ", Hari: " . $hari . ", skrng :" . $current_time_check . "<br>"; // Debug output
                                        $status_perkuliahan = 'Berakhir'; // Default status
    
                                        // Cek apakah hari saat ini sama dengan hari kuliah
                                        if ($current_day == $hari) {
                                            // echo "Hari Cocok<br>"; // Debug output
                                            $start_time = strtotime($jam_mulai);
                                            $end_time = strtotime($jam_selesai);
                                            $current_time_check = strtotime(date('H:i:s')); // Waktu saat ini tanpa tanggal
                                            // echo "Start Time: " . date('H:i:s', $start_time) . ", End Time: " . date('H:i:s', $end_time) . ", Current Time Check: " . date('H:i:s', $current_time_check) . "<br>"; // Debug output
    
                                            // Periksa apakah saat ini berada di antara jam mulai dan jam selesai
                                            if ($current_time_check >= $start_time && $current_time_check <= $end_time) {
                                                // echo "Status: Sedang Berlangsung<br>"; // Debug output
                                                $status_perkuliahan = 'Sedang Berlangsung';
                                            } elseif ($current_time_check < $start_time) {
                                                // echo "Status: Segera Dimulai<br>"; // Debug output
                                                $status_perkuliahan = 'Segera Dimulai';
                                            }
                                        }
                                    ?>
                            <tr>
                                <td><?php echo $no++; ?></td>
                                <td><?php echo $row['kode']; ?></td>
                                <td><?php echo $row['nama']; ?></td>
                                <td><?php echo $jam_mulai; ?></td>
                                <td><?php echo $jam_selesai; ?></td>
                                <td><?php echo $hari; ?></td>
                                <td>
                                    <?php if ($status_perkuliahan == 'Sedang Berlangsung') : ?>
                                    <button class="btn btn-sm btn-outline-success rounded-5">Sedang Berlangsung</button>
                                    <?php elseif ($status_perkuliahan == 'Berakhir') : ?>
                                    <button class="btn btn-sm btn-outline-danger rounded-5">Berakhir</button>
                                    <?php elseif ($status_perkuliahan == 'Segera Dimulai') : ?>
                                    <button class="btn btn-sm btn-outline-warning rounded-5">Segera Dimulai</button>
                                    <?php endif; ?>
                                </td>
                            </tr>
                            <?php } ?>
                        </tbody>
                    </table>
                    <?php } else { ?>
                    <p>Tidak ada data mata kuliah yang tersedia.</p>
                    <?php } ?>
                </div>
            </div>


            <div class="col-md-12">
                <div class="card card-round">
                    <div class="card-body pb-0">
                        <div id="chart-container" style="min-width: 310px; height: 400px; margin: 0 auto"></div>
                    </div>
                </div>
            </div>

            <script>
            document.addEventListener('DOMContentLoaded', function() {
                // Ambil data dari PHP dan konversi menjadi array JavaScript
                var data = <?php
                                include './conf/conf.php'; // Include database connection file

                                $query = "SELECT matakuliah_id, COUNT(*) as jumlah FROM laporan_scan GROUP BY matakuliah_id";
                                $result = $conn->query($query);

                                $data = array();
                                while ($row = $result->fetch_assoc()) {
                                    $matakuliah_id = $row['matakuliah_id'];
                                    $query_matakuliah = "SELECT nama FROM mata_kuliah WHERE id = ?";
                                    $stmt_matakuliah = $conn->prepare($query_matakuliah);
                                    $stmt_matakuliah->bind_param("i", $matakuliah_id);
                                    $stmt_matakuliah->execute();
                                    $stmt_matakuliah->bind_result($kode_mk);
                                    $stmt_matakuliah->fetch();
                                    $stmt_matakuliah->close();

                                    $data[] = array(
                                        'kode_mk' => $kode_mk,
                                        'jumlah' => intval($row['jumlah'])
                                    );
                                }

                                echo json_encode($data);

                                $conn->close();
                                ?>;

                // Siapkan data untuk chart
                var chartData = [];
                data.forEach(function(item) {
                    chartData.push({
                        name: item.kode_mk,
                        y: item.jumlah
                    });
                });

                // Inisialisasi chart Highcharts
                Highcharts.chart('chart-container', {
                    chart: {
                        type: 'column'
                    },
                    title: {
                        text: 'Rekap Jumlah Scan per Mata Kuliah'
                    },
                    xAxis: {
                        type: 'category',
                        labels: {
                            rotation: -45,
                            style: {
                                fontSize: '13px',
                                fontFamily: 'Verdana, sans-serif'
                            }
                        }
                    },
                    yAxis: {
                        min: 0,
                        title: {
                            text: 'Jumlah Mahasiswa Absensi'
                        }
                    },
                    legend: {
                        enabled: false
                    },
                    tooltip: {
                        pointFormat: 'Jumlah Scan: <b>{point.y}</b>'
                    },
                    series: [{
                        name: 'Mata Kuliah',
                        data: chartData,
                        dataLabels: {
                            enabled: true,
                            rotation: -90,
                            color: '#FFFFFF',
                            align: 'right',
                            format: '{point.y}', // one decimal
                            y: 10, // 10 pixels down from the top
                            style: {
                                fontSize: '13px',
                                fontFamily: 'Verdana, sans-serif'
                            }
                        }
                    }]
                });
            });
            </script>

        </div>
    </div>
</div>