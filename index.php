<?php
    // Copyright 2004-present Facebook. All Rights Reserved.

    $STREAM_XML = '<stream:stream '.
      'xmlns:stream="http://etherx.jabber.org/streams" '.
      'version="1.0" xmlns="jabber:client" to="chat.facebook.com" '.
      'xml:lang="en" xmlns:xml="http://www.w3.org/XML/1998/namespace">';

    $AUTH_XML = '<auth xmlns="urn:ietf:params:xml:ns:xmpp-sasl" '.
      'mechanism="X-FACEBOOK-PLATFORM"></auth>';

    $CLOSE_XML = '</stream:stream>';

    $RESOURCE_XML = '<iq type="set" id="3">'.
      '<bind xmlns="urn:ietf:params:xml:ns:xmpp-bind">'.
      '<resource>fb_xmpp_script</resource></bind></iq>';

    $SESSION_XML = '<iq type="set" id="4" to="chat.facebook.com">'.
      '<session xmlns="urn:ietf:params:xml:ns:xmpp-session"/></iq>';

    $START_TLS = '<starttls xmlns="urn:ietf:params:xml:ns:xmpp-tls"/>';

    $MESSAGE = '<message from="100000406542029@chat.facebook.com" to="%s@chat.facebook.com"><body>3 - Hi this is for testing purpose only, thanks!</body></message>';    

    function open_connection($server) {
      print "[INFO] Opening connection... ";

      $fp = fsockopen($server, 5222, $errno, $errstr);
      if (!$fp) {
        print "$errstr ($errno)<br>";
      } else {
        print "connnection open<br>";
      }

      return $fp;
    }

    function send_xml($fp, $xml) {
      //print "in send xml<br>";
      fwrite($fp, $xml);
    }

    function recv_xml($fp,  $size=4096) {
      $xml = fread($fp, $size);

			if (!preg_match('/^</', $xml)) {
			    $xml = '<' . $xml;
			}
      if ($xml === "") {
         return null;
      }

      // parses xml
      $xml_parser = xml_parser_create();
      xml_parse_into_struct($xml_parser, $xml, $val, $index);
      xml_parser_free($xml_parser);

      return array($val, $index);
    }

    function find_xmpp($fp,  $tag, $value=null, &$ret=null) {
      static $val = null, $index = null;

      do {
        if ($val === null && $index === null) {
          list($val, $index) = recv_xml($fp);
          if ($val === null || $index === null) {
            return false;
          }
        }

        foreach ($index as $tag_key => $tag_array) {
          if ($tag_key === $tag) {
            if ($value === null) {
              if (isset($val[$tag_array[0]]['value'])) {
                $ret = $val[$tag_array[0]]['value'];
              }
              return true;
            }
            foreach ($tag_array as $i => $pos) {
              if ($val[$pos]['tag'] === $tag && isset($val[$pos]['value']) &&
                $val[$pos]['value'] === $value) {
                  $ret = $val[$pos]['value'];
                  return true;
              }
            }
          }
        }
        $val = $index = null;
      } while (!feof($fp));

      return false;
    }


    function xmpp_connect($options, $access_token, $id) {
      global $STREAM_XML, $AUTH_XML, $RESOURCE_XML, $SESSION_XML, $CLOSE_XML, $START_TLS, $MESSAGE;

      $fp = open_connection($options['server']);
      if (!$fp) {
        return false;
      }

      // initiates auth process (using X-FACEBOOK_PLATFORM)
      send_xml($fp,  $STREAM_XML);
      if (!find_xmpp($fp, 'STREAM:STREAM')) {
        return false;
      }
      if (!find_xmpp($fp,  'MECHANISM', 'X-FACEBOOK-PLATFORM')) {
        return false;
      }

      // starting tls - MANDATORY TO USE OAUTH TOKEN!!!!
      send_xml($fp,  $START_TLS);
      if (!find_xmpp($fp, 'PROCEED', null, $proceed)) {
        return false;
      }
      stream_socket_enable_crypto($fp, true, STREAM_CRYPTO_METHOD_TLS_CLIENT);

      send_xml($fp, $STREAM_XML);
      if (!find_xmpp($fp, 'STREAM:STREAM')) {
        return false;
      }
      if (!find_xmpp($fp, 'MECHANISM', 'X-FACEBOOK-PLATFORM')) {
        return false;
      }

      // gets challenge from server and decode it
      send_xml($fp, $AUTH_XML);
      if (!find_xmpp($fp,  'CHALLENGE', null, $challenge)) {
        return false;
      }
      $challenge = base64_decode($challenge);
      $challenge = urldecode($challenge);
      parse_str($challenge, $challenge_array);

      // creates the response array
      $resp_array = array(
        'method' => $challenge_array['method'],
        'nonce' => $challenge_array['nonce'],
        'access_token' => $access_token,
        'api_key' => $options['app_id'],
        'call_id' => 0,
        'v' => '1.0',
      );
      // creates signature
      $response = http_build_query($resp_array);

      // sends the response and waits for success
      $xml = '<response xmlns="urn:ietf:params:xml:ns:xmpp-sasl">'.
        base64_encode($response).'</response>';
      send_xml($fp, $xml);
      if (!find_xmpp($fp, 'SUCCESS')) {
      	print ("before returning false<br>");
        return false;
      }

      // finishes auth process
      send_xml($fp, $STREAM_XML);
      if (!find_xmpp($fp,'STREAM:STREAM')) {
        return false;
      }
      if (!find_xmpp($fp, 'STREAM:FEATURES')) {
        return false;
      }
     send_xml($fp, $RESOURCE_XML);
      if (!find_xmpp($fp, 'JID')) {
        return false;
      }
      send_xml($fp, $SESSION_XML);
      if (!find_xmpp($fp, 'SESSION')) {
        return false;
      }

      // sends chat message
      send_xml($fp, sprintf($MESSAGE,$id));
      //send_xml($fp, $MESSAGE);
			//if (!find_xmpp($fp, 'BODY')) {
			//    return false;
			//}
      // we made it!
      print ("Message sent successfully<br>");
      send_xml($fp, $CLOSE_XML);
      print ("Authentication complete<br>");
      fclose($fp);

      return true;
    }



    //Gets access_token with xmpp_login permission
    function get_access_token($app_id, $app_secret, $my_url){ 

      $code = $_REQUEST["code"];

      if(empty($code)) {
        $dialog_url = "http://www.facebook.com/dialog/oauth?scope=xmpp_login".
         "&client_id=" . $app_id . "&redirect_uri=" . urlencode($my_url) ;
        echo("<script>top.location.href='" . $dialog_url . "'</script>");
      }
       $token_url = "https://graph.facebook.com/oauth/access_token?client_id="
        . $app_id . "&redirect_uri=" . urlencode($my_url) 
        . "&client_secret=" . $app_secret 
        . "&code=" . $code;
       $access_token = file_get_contents($token_url);
        parse_str($access_token, $output);

        return($output['access_token']);
    }

    function _main() {
      print "Test platform connect for XMPP<br>";
      $app_id='506606119387951';
      $app_secret='app_secret';
      $my_url = "http://fbchat.hoodere.com/";
      $uid = '100000406542029';
      if($_COOKIE['access_token']){
      	$access_token = $_COOKIE['access_token'];
      }
      else{
      	$access_token = get_access_token($app_id,$app_secret,$my_url);
      	setcookie('access_token',$access_token,time() + (300));
      }
      print $_COOKIE['access_token']."<br><br>";
      print "access_token: ".$access_token."<br>";

        $options = array(
          'uid' => $uid,
          'app_id' => $app_id,
          'server' => 'chat.facebook.com',
         );

        // prints options used
        print "server: ".$options['server']."<br>";
        print "uid: ".$options['uid']."<br>";
        print "app id: ".$options['app_id']."<br>";
      $ids = array("100000808800908","100005638479826","100008182958937","100007324600223","100000487025736","1060747336","608499467");
      foreach ($ids as $id) {
        if (xmpp_connect($options, $access_token, $id)) {
          print "Done<br>";
        } else {
          print "An error ocurred<br>";
        }
      }

    }

    _main();

