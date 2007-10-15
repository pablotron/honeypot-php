<?php

require 'honeypot.php';

$key = $_REQUEST['key'];
$host = $_REQUEST['host'];

$honeypot = new Honeypot($key, array(
  'debug' => true,
));

# get result
$result = $honeypot->check($host);

# dump result
print_r($result);

# get result info
$info = $honeypot->result_info($result);

# get opts
$ok = $info['ok'] ? 'ok' : 'NOT OKAY';
$why = $info['why'];

echo "<p>result is $ok: $why</p>";

?>
