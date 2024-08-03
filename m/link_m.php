<?php
@$page = $_GET['q'];
if (!empty($page)) {
    switch ($page) {


        case 'beranda':
            include './pages/beranda/beranda.php';
            break;

        case 'jadwal_kuliah':
            include './pages/jadwal_kuliah/jadwal_kuliah.php';
            break;

        case 'scan_qr':
            include './pages/scan_qr/scan_qr.php';
            break;

        case 'profile':
            include './pages/profile/profile.php';
            break;

        case 'up_profile':
            include './pages/profile/up_profile/up_profile.php';
            break;
    }
} else {
    include './pages/beranda/beranda.php';
}
