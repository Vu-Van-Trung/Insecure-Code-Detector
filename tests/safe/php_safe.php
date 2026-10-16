<?php
// Safe counterpart of php_vulnerable.php: the analyzer must report nothing here.

require_once __DIR__ . '/config.php';
include dirname(__FILE__) . '/header.php';

$db_password = getenv('DB_PASSWORD');
$password_placeholder = 'changeme';

$host = $_GET['host'];
$ok = filter_var($host, FILTER_VALIDATE_IP);

$stmt = $pdo->prepare('SELECT * FROM users WHERE id = ?');
$stmt->execute([$_REQUEST['id']]);
$count = mysqli_query($conn, 'SELECT COUNT(*) FROM users');

$pages = ['home' => 'home.php'];
include $pages['home'];

$content = file_get_contents('/var/data/' . basename($_GET['file']));

echo '<h1>' . htmlspecialchars($_GET['title'], ENT_QUOTES, 'UTF-8') . '</h1>';
$html = '<div>' . htmlentities($_COOKIE['theme']) . '</div>';
echo 'Page ' . (int) $_GET['page'];

$hash = password_hash($_POST['password'], PASSWORD_DEFAULT);
$checksum = hash('sha256', $content);
$token = bin2hex(random_bytes(32));
$dice = rand(1, 6);

$cart = json_decode($_COOKIE['cart'], true);
$cached = unserialize($blob, ['allowed_classes' => false]);

curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, true);
curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 2);

header('Location: /dashboard.php');

$target = 'uploads/' . bin2hex(random_bytes(16)) . '.png';
move_uploaded_file($_FILES['avatar']['tmp_name'], $target);
