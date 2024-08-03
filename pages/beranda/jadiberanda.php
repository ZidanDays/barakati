<?php
// Set timezone
date_default_timezone_set('Asia/Kuala_Lumpur'); // Gantilah dengan timezone Anda

?>
<div class="container">
    <div class="page-inner">
        <!-- Your HTML layout here -->
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
                    echo "Current Time: " . $current_time . "<br>"; // Debug output
                    $current_day = date('l');
                    echo "Current Day: " . $current_day . "<br>"; // Debug output

                    // Query untuk mendapatkan semua data dari tabel mata_kuliah
                    $query = "SELECT * FROM mata_kuliah";
                    $result = $conn->query($query);

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
                                    echo "Mata Kuliah: " . $row['nama'] . ", Jam Mulai: " . $jam_mulai . ", Jam Selesai: " . $jam_selesai . ", Hari: " . $hari . ", skrng :" . $current_time_check . "<br>"; // Debug output
                                    $status_perkuliahan = 'Berakhir'; // Default status

                                    // Cek apakah hari saat ini sama dengan hari kuliah
                                    if ($current_day == $hari) {
                                        echo "Hari Cocok<br>"; // Debug output
                                        $start_time = strtotime($jam_mulai);
                                        $end_time = strtotime($jam_selesai);
                                        $current_time_check = strtotime(date('H:i:s')); // Waktu saat ini tanpa tanggal
                                        echo "Start Time: " . date('H:i:s', $start_time) . ", End Time: " . date('H:i:s', $end_time) . ", Current Time Check: " . date('H:i:s', $current_time_check) . "<br>"; // Debug output

                                        // Periksa apakah saat ini berada di antara jam mulai dan jam selesai
                                        if ($current_time_check >= $start_time && $current_time_check <= $end_time) {
                                            echo "Status: Sedang Berlangsung<br>"; // Debug output
                                            $status_perkuliahan = 'Sedang Berlangsung';
                                        } elseif ($current_time_check < $start_time) {
                                            echo "Status: Segera Dimulai<br>"; // Debug output
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
        </div>
    </div>
</div>