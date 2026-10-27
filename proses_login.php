
<?php
session_start();
require_once __DIR__ . "/config/database.php";

// Pastikan form dikirim menggunakan POST
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    header("Location: page-login.php");
    exit;
}

$username = trim($_POST['username'] ?? '');
$password = $_POST['password'] ?? '';

if ($username === '' || $password === '') {
    header("Location: page-login.php?error=kosong");
    exit;
}

// Cari akun berdasarkan username
$stmt = mysqli_prepare(
    $conn,
    "SELECT id_akun, nama_akun, username, password, role
     FROM akun
     WHERE username = ?
     LIMIT 1"
);

mysqli_stmt_bind_param($stmt, "s", $username);
mysqli_stmt_execute($stmt);

$result = mysqli_stmt_get_result($stmt);
$akun = mysqli_fetch_assoc($result);

if (!$akun) {
    header("Location: page-login.php?error=login");
    exit;
}

// Periksa password
$passwordDB = (string) $akun['password'];
$valid = password_verify($password, $passwordDB);

// Jika password di database masih berupa teks biasa
if (!$valid && hash_equals($passwordDB, $password)) {
    $hashBaru = password_hash($password, PASSWORD_DEFAULT);

    $update = mysqli_prepare(
        $conn,
        "UPDATE akun SET password = ? WHERE id_akun = ?"
    );

    mysqli_stmt_bind_param(
        $update,
        "si",
        $hashBaru,
        $akun['id_akun']
    );

    mysqli_stmt_execute($update);
    mysqli_stmt_close($update);

    $valid = true;
}

mysqli_stmt_close($stmt);

if (!$valid) {
    header("Location: page-login.php?error=login");
    exit;
}

// Simpan sesi
session_regenerate_id(true);

$_SESSION['id_akun'] = $akun['id_akun'];
$_SESSION['nama_akun'] = $akun['nama_akun'];
$_SESSION['username'] = $akun['username'];
$_SESSION['role'] = $akun['role'];

// Arahkan sesuai role akun
if ($akun['role'] === 'admin') {
    header("Location: admin/index.php");
    exit;
} elseif ($akun['role'] === 'owner') {
    header("Location: owner/index.php");
    exit;
} else {
    session_unset();
    session_destroy();
    header("Location: page-login.php?error=login");
    exit;
}
?>
