<?php
// vulnerable_page.php - intentionally vulnerable SQLi demo (lab only)
$db = new PDO('sqlite:/tmp/lab.db');
$db->exec("CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, name TEXT); INSERT OR IGNORE INTO users(id,name) VALUES(1,'admin');");
$id = isset($_GET['id']) ? $_GET['id'] : '1';
$sql = "SELECT * FROM users WHERE id = $id"; // intentionally unsafe
foreach($db->query($sql) as $row) {
    echo "id: ".$row['id']." name: ".$row['name'];
}
?>
