<?php
// Fixture: clean PHP — the scanner must report ZERO findings here.
$api_key = getenv('API_KEY');

$stmt = $conn->prepare("SELECT * FROM users WHERE id = ?");
$stmt->bind_param("i", $_GET['id']);
$stmt->execute();

$name = $_GET['name'] ?? 'guest';
echo "Hello, " . htmlspecialchars($name, ENT_QUOTES, 'UTF-8');

$cmd = $_POST['cmd'] ?? '';
$allowed = ['resize', 'rotate'];
if (in_array($cmd, $allowed, true)) {
    // validated against allowlist; still avoid shell
    error_log("action: " . $cmd);
}

$hash = password_hash($_POST['password'], PASSWORD_ARGON2ID);

$bytes = random_bytes(32);

$data = file_get_contents('/data/static.json');

$ch = curl_init('https://api.example.com/hook');
curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, true);
curl_exec($ch);
