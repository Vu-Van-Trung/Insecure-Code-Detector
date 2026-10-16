<?php
// Demo: the same DVWA-style pages written safely ("impossible" level).
// No finding is expected in this file.

require_once DVWA_WEB_PAGE_TO_ROOT . 'dvwa/includes/dvwaPage.inc.php';
include __DIR__ . '/header.php';

$db_password = getenv('DB_PASSWORD');

// SQL: prepared statement
if (isset($_GET['Submit'])) {
    $id = $_GET['id'];
    if (is_numeric($id)) {
        $data = $db->prepare('SELECT first_name, last_name FROM users WHERE user_id = (:id) LIMIT 1;');
        $data->bindParam(':id', $id, PDO::PARAM_INT);
        $data->execute();
    }
}

// Command: no shell at all - validate and use a PHP function instead
$target = $_REQUEST['ip'];
$valid = filter_var($target, FILTER_VALIDATE_IP) !== false;

// XSS: escaped output
$name = htmlspecialchars($_GET['name'], ENT_QUOTES, 'UTF-8');
$html .= "<pre>Hello {$name}</pre>";
echo 'Welcome back, ' . htmlspecialchars($_GET['name']);

// Constant query
$rows = mysqli_query($conn, 'SELECT COUNT(*) FROM posts');

// File inclusion: allow-list
$pages = ['home' => 'home.php', 'about' => 'about.php'];
include $pages['home'];

// Upload: server-chosen name
$ext = 'png';
$target_file = 'uploads/' . bin2hex(random_bytes(16)) . '.' . $ext;
move_uploaded_file($_FILES['uploaded']['tmp_name'], $target_file);

// Passwords and tokens
$hash = password_hash($_POST['password'], PASSWORD_DEFAULT);
$session_token = bin2hex(random_bytes(32));
$checksum = hash('sha256', $data);
$dice = rand(1, 6);

$prefs = json_decode($_COOKIE['prefs'], true);
$obj = unserialize($cached, ['allowed_classes' => false]);
header('Location: /index.php');
curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, true);
