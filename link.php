<?php
@$page = $_GET['q'];
if (!empty($page)) {
    switch ($page) {


        case 'beranda':
            include './pages/beranda/beranda.php';
            break;

        case 'users':
            include './pages/users/users.php';
            break;

        case 'tambah_users':
            include './pages/users/tambah_users/tambah_users.php';
            break;

        case 'mata_kuliah':
            include './pages/mata_kuliah/mata_kuliah.php';
            break;

        case 'tambah_matakuliah':
            include './pages/mata_kuliah/tambah_matakuliah/tambah_matakuliah.php';
            break;

        case 'edit_matakuliah':
            include './pages/mata_kuliah/edit_matakuliah/edit_matakuliah.php';
            break;

        case 'edit_proses':
            include './pages/mata_kuliah/edit_matakuliah/edit_proses/edit_proses.php';
            break;

        case 'delete_matakuliah':
            include './pages/mata_kuliah/delete_matakuliah/delete_matakuliah.php';
            break;

        case 'rekap':
            include './pages/rekap/rekap.php';
            break;

        case 'expor':
            include './pages/rekap/expor/expor.php';
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
