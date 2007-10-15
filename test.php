<?php

require 'honeypot.php';

$api_key = $_REQUEST['api_key'];
$host = $_REQUEST['host'];

$honeypot = new Honeypot($api_key);

$result = $honeypot->check($host);

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


?>
