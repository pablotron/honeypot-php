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

    'debug'     => false,
  );

  function Honeypot($api_key, $opt = array()) {
    $this->api_key = $api_key;
    $this->opt = array();

    foreach ($this->HONEYPOT_DEFAULTS as $key => $val)
      $this->opt[$key] = $val;
    foreach ($opt as $key => $val)
      $this->opt[$key] = $val;
  }

  function check($ip) {
    $host = $this->build_query($ip); 
    return $host ? $this->do_query($host) : null;
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
    $this->log_msg("querying $host");
    $ip = $this->lookup($host);
    return ($ip ? $this->build_response($ip) : null);
  }

  function build_query($ip) {
    if (!$this->is_ip($ip)) 
      $ip = $this->lookup("$ip");
    if (!$ip)
      return null;

    $this->log_msg("flipping ip $ip");
    $ip = $this->flip_ip($ip);

    # build return string
    $ret = "{$this->api_key}.$ip.{$this->opt['root']}";
    $this->log_msg("build_query(): host: $ret");

    return $ret;
  }

  function build_response($ip) {
    $ary = split('\.', $ip);
    $flags = $ary[3];

    $this->log_msg("build_response(): building response for $ip");

    # build return array
    $ret = array(
      'raw'     => $ip,
      'age'     => $ary[1],
      'threat'  => $ary[2],
      'flags'   => $flags,
    );

    foreach ($this->FLAGS as $i => $key)
      $ret["is_$key"] = ($flags & (1 << $i)) ? true : false;
      $ret['is_search_engine'] = !$flags;

    return $ret;
  }

  function lookup($str) {
    $ret = gethostbynamel($str);
    if (!$ret || !count($ret) || !$ret[0])
      return null;
    return ($this->is_ip($ret[0]) ? $ret[0] : null);
  }

  function flip_ip($ip) {
    $ret = split('\.', $ip);
    $ret = array_reverse($ret);
    $ret = join('.', $ret);

    $this->log_msg("flip_ip: $ip => $ret");
    return $ret;
  }

  function is_ip($str) {
    return preg_match('/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/', $str);
  }

  function log_msg($msg) {
    if ($this->opt['debug'])
      echo "<p>DEBUG: $msg</p>\n";
  }
};

?>
