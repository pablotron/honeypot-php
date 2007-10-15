<?php

#
# Honeypot-PHP - PHP interface for the Project Honeypot HTTP blacklist.
#
# Copyright (c) 2007, Paul Duncan <pabs@pablotron.org>
#
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are
# met:
#
#   * Redistributions of source code must retain the above copyright
#     notice, this list of conditions and the following disclaimer.
#   * Redistributions in binary form must reproduce the above copyright
#     notice, this list of conditions and the following disclaimer in the
#     documentation and/or other materials provided with the distribution.
#   * The names of its contributors may not be used to endorse or 
#     promote products derived from this software without specific prior
#     written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
# IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
# TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
# PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER
# OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
# EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
# PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
# PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
# LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
# NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
# SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#

class Honeypot {
  var $VERSION = '0.1.0';

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

  var $FLAGS = array('suspicious', 'harvester', 'comment_spammer');

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

    return (!$r || !$r['flags'] || 
            $r['age'] > $this->opt['ok_age'] || 
            $r['threat'] > $this->opt['ok_threat']);
  }

  function result_info($result) {
    # check result (if null, entry isn't in blacklist)
    if (!$result) {
      return array(
        'ok'  => true, 
        'why' => 'not in honeypot blacklist'
      );
    }

    # if we got here, the host has an entry in the blacklist,
    # so let's find out why

    # check the age of the entry
    if ($result['age'] > $this->opt['ok_age']) {
      # got a result, it's too old
      return array(
        'ok'  => true, 
        'why' => 'entry is too old',
      );
    }

    # if we got here, then the entry is new enough, so let's check
    # the threat level

    if ($result['threat'] < $this->opt['ok_threat']) {
      # got a result, but the threat level is too low
      return array(
        'ok'  => true,
        'why' => 'threat level too low',
      );
    }

    # if we got here, then there is a recent entry in the blacklist with a
    # high enough threat level, so let's find out why

    # check all available flags 
    $flags = array();
    foreach (Honeypot::$FLAGS as $flag)
      if ($result["is_$flag"])
        $flags[] = $flag;

    # entry is _not_ okay, return a hash containing the description
    # and flags
    return array(
      'ok'    => false,
      'why'   => join(', ', $flags),
      'flags' => $flags,
    );
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
