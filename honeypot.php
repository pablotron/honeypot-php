<?php

class Honeypot {
  var $FLAGS = array('suspicious', 'harvester', 'comment_spammer');

  var $HONEYPOT_DEFAULTS = array(
    # root to append to dns requests
    'root'      => 'dnsbl.httpbl.org',

    # debugging enabled?
    'debug'     => false,

    # threshold for ok? threat check
    'ok_threat' => 128,

    # threshold for ok? age check
    'ok_age'    => 128,
  );

  function Honeypot($api_key, $opt = array()) {
    $this->api_key = $api_key;

    foreach ($this->HONEYPOT_DEFAULTS as $key => $val)
      $this->opt[$key] = $val;
    foreach ($opt as $key => $val)
      $this->opt[$key] = $val;
  }

  function check($ip) {
    if ($host = $this->build_query($ip)) 
      return $this->do_query($host);
    return null;
  }

  function is_ok($str) {
    $r = $this->check($str);

    return (!$r || $r['age'] > $this->opt['ok_age'] || 
            $r['threat'] > $this->opt['ok_threat']);
  }

  ###################
  # PRIVATE METHODS #
  ###################

  function do_query($host) {
    $ip = $this->lookup($host);
    return $ip ? $this->build_response($ip) : null;
  }

  function build_query($ip) {
    if (!$this->is_ip($ip)) 
      $ip = $this->lookup($ip);
    if (!$ip)
      return null;
    $ip = $this->flip_ip($ip);
    return "{$this->api_key}.{$ip}.{$this->opt['root']}"
  }

  function build_response($ip) {
    $ary = split('.', $ip);
    $flags = $ary[3];

    # build return array
    $ret = array(
      'raw'     => $ip,
      'age'     => $ary[1],
      'threat'  => $ary[2],
      'flags'   => $flags,
    );

    foreach ($this->FLAGS as $i => $key)
      $ret["is_$key"] = $flags & (1 << $i);

    return $ret;
  }

  function lookup($str) {
    $ret = gethostbyname($str);
    return $this->is_ip($ret) ? $ret : null;
  }

  function flip_ip($ip) {
    return join('.', array_reverse(split('.', $ip)));
  }

  function is_ip($str) {
    return preg_match('/\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3}/', $str);
  }
};

?>
