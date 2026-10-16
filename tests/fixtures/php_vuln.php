<?php
// Fixture: vulnerable PHP (intentionally insecure — scanner must flag)
$api_key = "sk-live-9f2k4m7q8w3e5r6t7y2u9i4o6p1"; // SEC001

$id = $_GET['id']; // tainted
$result = mysqli_query($conn, "SELECT * FROM users WHERE id = " . $id); // SQLI004

echo "Hello, " . $_GET['name']; // XSS004
?>
<div><?= $_COOKIE['theme'] ?></div> <!-- XSS004 short echo -->
<?php
$cmd = $_POST['cmd']; // tainted
system($cmd); // CMD004 critical (tainted)

$expr = $_GET['expr'];
eval($expr); // EVAL001 critical

$pw = $_POST['password'];
$hash = md5($_POST['password']); // CRY001

$url = $_POST['webhook']; // tainted
$ch = curl_init($url); // SSRF001 (tainted)
curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false); // TLS001
curl_exec($ch);

$data = file_get_contents($_GET['page']); // PATH001 (tainted)
include $_GET['tpl']; // PATH001 (tainted, LFI)
