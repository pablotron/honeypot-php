<?php

require 'honeypot.php';

$key = $_REQUEST['key'];
$host = $_REQUEST['host'];

$honeypot = new Honeypot($key, array(
  'debug' => true,
));

$result = $honeypot->check($host);

# dump result
print_r($result);

echo "<p>";
if ($result) {
  if ($result['age'] < 128) {
    if ($result['threat'] > 128) {
      echo 'address is NOT OKAY';
    } else {
      echo 'address is okay (threat too low)';
    }
  } else {
    echo 'address is okay (entry too old)';
  }
} else {
  echo 'address is okay (not in honeypot database)';
}
echo "</p>";

?>
