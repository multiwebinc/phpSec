<?php namespace phpSec\Auth;
/**
  phpSec - A PHP security library

  @author    Audun Larsen <larsen@xqus.com>
  @copyright Copyright (c) Audun Larsen, 2012, 2013, 2014
  @link      https://github.com/phpsec/phpSec
  @license   http://opensource.org/licenses/mit-license.php The MIT License
 */

/**
 * Implements Authy authentication. It's like magic, except it's math.
 *
 * @package phpSec
 */
class Authy {

  /**
   * Authy API key.
   */
  public $_apiKey  = null;

  /**
   * Connect to sandbox?
   */
  public $_sandbox = false;

  /**
   * Server timeout. In seconds.
   */
  public $_serverTimeout = 3;

  /**
   * Last error returned by Authy API.
   */
  public $lastError = null;

  /**
   * Authy ID
   */
  public $authyId;

  /**
   * \phpSec\Core object
   */
  private $psl;

  /**
   * Server URLs.
   */
  private $_servers = array(
    'production' => 'https://api.authy.com',
    'sandbox'    => 'http://sandbox-api.authy.com',
  );

  /**
   * Constructor.
   *
   * @param \phpSec\Core $psl
   *   phpSec core Pimple container.
   */
  public function __construct(\phpSec\Core $psl) {
    $this->psl = $psl;
  }

  /**
   * Add a new Authy user and get the Authy ID.
   *
   * @param string $email
   *   User email.
   *
   * @param string $cellphone
   *   User cellphone.
   *
   * @param string $countrycode
   *   User countrycode. Defaults to 1 (USA).
   *
   * @param string $uid
   *   User ID
   *
   * @return mixed
   *   Returns the users Authy ID on success or false on errors.
   *   @see \phpSec\Auth\Authy::$lastError.
   */
  public function userNew($email, $cellphone, $countrycode = 1, $uid) {

    $data = array(
      'user[email]'        => $email,
      'user[cellphone]'    => $cellphone,
      'user[country_code]' => $countrycode,
    );

    $result = $this->apiCall('new', $data);

    if($result === false) {
      $this->lastError = 'AUTHY_SERVER_ERROR';
      return false;
    }

    if(isset($result->errors)) {
      if(isset($result->errors->api_key)) {
        $this->lastError = 'AUTHY_SERVER_INVALID_API_KEY';
      } else {
        $this->lastError = 'AUTHY_SERVER_INVALID_DATA';
      }
      return false;
    }

    if (isset($result->user->id)) {
      $this->authyId = $result->user->id;

      $store['authyId'] = $this->authyId;
      $storeId = $this->getStoreId($uid);

      $this->psl['store']->write('authy', $storeId, $store);

      return $this->authyId;
    }
    $this->lastError = 'AUTHY_SERVER_SAYS_NO';
    return false;
  }

  /**
   * Verify a Authy OTP.
   *
   * @param int $authyId
   *   User Authy ID. @see \phpSec\Auth\Authy::userNew().
   *
   * @param int $token
   *   User supplied OPT/token.
   *
   * @return boolean
   *   Return true if a valid Authy token is supplied, false on any errors.
   *   @see \phpSec\Auth\Authy::$lastError.
   */
  public function verify($authyId = null, $token) {
    if (!isset($authyId)) {
      $authyId = $this->authyId;
    }

    $data = array(
      'token'    => $token,
      'authy_id' => $authyId,
    );


    $result = $this->apiCall('verify', $data);

    if($result === false) {
      $this->lastError = 'AUTHY_SERVER_ERROR';
      return false;
    }

    if(isset($result->errors)) {
      if(isset($result->errors->message) && $result->errors->message == 'token is invalid') {
        $this->lastError = 'AUTHY_SERVER_BAD_OTP';
      } elseif(isset($result->errors->api_key)) {
        $this->lastError = 'AUTHY_SERVER_INVALID_API_KEY';
      } else {
        $this->lastError = 'AUTHY_SERVER_INVALID_DATA';
      }
      return false;
    }

    if(isset($result->token) && $result->token == 'is valid') {
      return true;
    }

    return false;
  }

  /**
   * Request SMS token.
   *
   * @param int $authyId
   *   Authy ID to request SMS token for.
   *
   * @param bool $force
   *   Force sending of SMS even for users with App.
   *
   * @return boolean
   *   Returns true if SMS request was OK. false if not.
   */
  public function requestSms($authyId, $force = false) {
    $data = array(
      'authy_id' => $authyId,
      'force'    => $force,
    );

    $result = $this->apiCall('sms', $data);

    if ($result === false) {
      $this->lastError = 'AUTHY_SERVER_ERROR';
      return false;
    }

    if (isset($result->errors)) {
      $this->lastError = 'AUTHY_SERVER_INVALID_DATA';
      return false;
    }

    return true;
  }

  /**
   * Performs a call to the Authy API.
   *
   * @param string $action
   *   Action to perform: should be 'new' or 'verify'
   *
   * @param array $data
   *   Data to perform the action with.
   *
   * @throws \phpSec\Exception\IOException If the Auty API server is unreachable.
   *
   * @return object
   *   Decoded JSON results from Authy server.
   */
  private function apiCall($action, $data) {
    switch($this->_sandbox) {
      case true:
          $url = $this->_servers['sandbox'];
          break;
        default:
          $url = $this->_servers['production'];
    }

    switch($action) {
      case 'new':
        $url = $url.'/protected/json/users/new?api_key='.$this->_apiKey;
        $postData = http_build_query($data);
        $opts = array(
          'http' => array(
          'method'  => 'POST',
          'timeout' => $this->_serverTimeout,
          'header'  => "Content-Type: application/x-www-form-urlencoded\r\n" .
                       "Content-Length: ".strlen($postData) ."\r\n".
                       "User-Agent: phpSec (http://phpseclib.com)\r\n",
          'content' => $postData,
          'ignore_errors' => true,
        ));

      break;

      case 'verify':
        $url = $url.'/protected/json/verify/'.$data['token'].'/'.$data['authy_id'].'?api_key='.$this->_apiKey.'&force=true';

        $opts = array(
          'http' => array(
          'method'  => 'GET',
          'timeout' => $this->_serverTimeout,
          'header'  => "User-Agent: phpSec (http://phpseclib.com)",
          'ignore_errors' => true,
        ));

      break;

      case 'sms':
        $url = $url.'/protected/json/sms/'.$data['authy_id'].'?api_key='.$this->_apiKey;

        if($data['force'] === true) {
          $url = $url.'&force=true';
        }

        $opts = array(
          'http' => array(
          'method'  => 'GET',
          'timeout' => $this->_serverTimeout,
          'header'  => "User-Agent: phpSec (http://phpseclib.com)",
          'ignore_errors' => true,
        ));

      break;

    }

    $context = stream_context_create($opts);
    $result  = @file_get_contents($url, false, $context);

    if($result === false) {
      return false;
    }

    return json_decode($result);
   }

   /**
   * Loads an authy entry from the database
   *
   * @param string $uid
   *   The user ID
   *
   * @return string
   *   Authy ID
   */
  public function load($uid)
  {
    $store = $this->psl['store'];
    $storeData = $store->read('authy', $this->getStoreId($uid));

    if($storeData !== false) {
      $this->authyId = $storeData['authyId'];
      return $this->authyId;
    }
    return false;
  }

  private function getStoreId($uid) {
    return hash('sha512', $uid);
  }
}
