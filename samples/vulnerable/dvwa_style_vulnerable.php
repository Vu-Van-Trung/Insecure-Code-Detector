<?php
// Demo: DVWA-style PHP pages (security level "low").
// INTENTIONALLY VULNERABLE - for local testing of Secure Code Analyzer only. Never deploy it.
// All credentials are FAKE. Expected findings are marked with "EXPECT: <rule>".

$_CONFIG['db_password'] = 'Pr0d#Passw0rd!';                              // EXPECT: PH009
define('API_TOKEN', 'ghp_9fK2mQx7LpR4tW8zYb1NcV6hJ3dS0aEuGi5o');         // EXPECT: PH009

// SQL injection
if (isset($_REQUEST['Submit'])) {
    $id = $_REQUEST['id'];
    $query = "SELECT first_name, last_name FROM users WHERE user_id = '$id';";
    $result = mysqli_query($GLOBALS["___mysqli_ston"], $query);         // EXPECT: PH002 (CRITICAL)
    while ($row = mysqli_fetch_assoc($result)) {
        $html .= "<pre>ID: {$id}<br />First name: {$row['first_name']}</pre>"; // EXPECT: PH006
    }
}

// Command injection
if (isset($_POST['Submit'])) {
    $target = $_REQUEST['ip'];
    $cmd = shell_exec('ping  -c 4 ' . $target);                         // EXPECT: PH001 (CRITICAL)
    $html .= "<pre>{$cmd}</pre>";
}

// Reflected XSS
if (array_key_exists("name", $_GET) && $_GET['name'] != NULL) {
    $html .= '<pre>Hello ' . $_GET['name'] . '</pre>';                   // EXPECT: PH006
    echo "Welcome back, " . $_GET['name'];                              // EXPECT: PH006
}

// File inclusion
$file = $_GET['page'];
include($file);                                                         // EXPECT: PH004 (CRITICAL)

// Path traversal
$doc = $_GET['doc'];
readfile('/var/www/docs/' . $doc);                                       // EXPECT: PH005

// File upload
if (isset($_POST['Upload'])) {
    $target_path = DVWA_WEB_PAGE_TO_ROOT . "hackable/uploads/";
    $target_path .= basename($_FILES['uploaded']['name']);
    move_uploaded_file($_FILES['uploaded']['tmp_name'], $target_path);   // EXPECT: PH013
}

// Weak password hashing, insecure session id
$pass = $_POST['password'];
$pass = md5($pass);                                                     // EXPECT: PH007 (HIGH)
$session_token = md5(uniqid());                                         // EXPECT: PH008 + PH007
$reset_code = mt_rand(100000, 999999);                                  // EXPECT: PH008

// Code injection, object injection, open redirect
eval('$total = ' . $_GET['expr'] . ';');                                 // EXPECT: PH003 (CRITICAL)
$prefs = unserialize($_COOKIE['prefs']);                                 // EXPECT: PH010 (CRITICAL)
header("Location: " . $_GET['redirect']);                               // EXPECT: PH012

// TLS verification disabled
$ch = curl_init('https://api.example.com/');
curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);                        // EXPECT: PH011
