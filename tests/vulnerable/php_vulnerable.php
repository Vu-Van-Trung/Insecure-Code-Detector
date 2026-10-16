<?php
// Intentionally vulnerable test fixture: PHP rules PH001 - PH013. Never run this file.

$db_password = 'Sup3r$ecretPassw0rd!'; // expect: PH009
define('STRIPE_KEY', 'sk_live_51HxYzAbCdEfGhIjKlMnOpQrStUvWx'); // expect: PH009

$host = $_GET['host'];
system("ping -c 1 " . $host); // expect: PH001
$listing = `ls {$_POST['dir']}`; // expect: PH001

$id = $_REQUEST['id'];
$result = mysqli_query($conn, "SELECT * FROM users WHERE id = $id"); // expect: PH002
$rows = $pdo->query("SELECT * FROM posts WHERE author = '" . $_GET['author'] . "'"); // expect: PH002

eval($_POST['code']); // expect: PH003

include $_GET['page'] . '.php'; // expect: PH004

$content = file_get_contents('/var/data/' . $_GET['file']); // expect: PH005

echo '<h1>' . $_GET['title'] . '</h1>'; // expect: PH006
$html = "<div>{$_COOKIE['theme']}</div>"; // expect: PH006

$hash = md5($_POST['password']); // expect: PH007
$token = rand(); // expect: PH008

$cart = unserialize(base64_decode($_COOKIE['cart'])); // expect: PH010

curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 0); // expect: PH011
$context = stream_context_create(['ssl' => ['verify_peer' => false]]); // expect: PH011

header('Location: ' . $_GET['next']); // expect: PH012

$name = $_FILES['avatar']['name'];
move_uploaded_file($_FILES['avatar']['tmp_name'], 'uploads/' . $name); // expect: PH005, PH013

function lookup($conn)
{
    $user = $_GET['user'];
    return mysqli_query($conn, "SELECT * FROM users WHERE name = '" . $user . "'"); // expect: PH002
}

class Repo
{
    private $apiSecret = 'q8Zr2Lm9Xv4Tn7Bc1Wd6Yh3Kp0Fs5Ga'; // expect: PH009

    public function find()
    {
        $this->db->query('SELECT * FROM t WHERE id = ' . $_GET['id']); // expect: PH002
    }
}
