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

// --- 2026 expansion: safe counterparts (must stay silent) ---
$obj = unserialize($cache, ['allowed_classes' => false]); // DESER001-safe

$ext = strtolower(pathinfo($_FILES['doc']['name'], PATHINFO_EXTENSION));
if (in_array($ext, ['pdf', 'png'], true)) { // UPL001-safe: allowlist
    move_uploaded_file($_FILES['doc']['tmp_name'],
        '/uploads/' . bin2hex(random_bytes(8)) . '.' . $ext);
}

header('Location: /dashboard'); // REDIR001-safe: fixed target
