<?php namespace phpSec\Auth;
/**
  phpSec - A PHP security library

  @author    Audun Larsen <larsen@xqus.com>
  @copyright Copyright (c) Audun Larsen, 2011, 2012
  @link      https://github.com/phpsec/phpSec
  @license   http://opensource.org/licenses/mit-license.php The MIT License
  @package   phpSec_Experimental
 */

/**
 * Providees pre shared password grid functionality. Experimental.
 * @package phpSec_Experimental
 */
class Gridcard {

  public $numCols = 10;
  public $numRows = 5;
  public $gridChars = '0123456789';
  public $_charset = 'abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ';

  private $seedRandom;
  private $nextCellsRandomSeed;

  /**
   * Constructor.
   *
   * @param \phpSec\Core $psl
   *   phpSec core Pimple container.
   */
  public function __construct(\phpSec\Core $psl) {
    $this->psl = $psl;
  }

  public function generate($expiry = null) {
    $rand  = $this->psl['crypt/rand'];

    $this->issued = time();

    if (isset($expiry)) {
      $this->expiry = $expiry;
    }
    else {
      $this->expiry = strtotime("+ 1 year");
    }

    $this->seedRandom = $rand->str(64, $this->_charset);

    // Total number of different combinations is (numCols * numRows)^3
    $this->nextCellsRandomSeed = mt_rand(0, pow($this->numCols * $this->numRows, 3));
  }

  public function save($uid)
  {
    if (!isset($this->seedRandom)
      || !isset($this->expiry)
      || !isset($this->nextCellsRandomSeed)
    ) {
      throw new \phpSec\Exception\GeneralSecurityException('Variables not set correctly');
    }
    $store['numCols'] = $this->numCols;
    $store['numRows'] = $this->numRows;
    $store['seedRandom'] = $this->seedRandom;
    $store['chars'] = $this->gridChars;
    $store['expiry'] = $this->expiry;
    $store['nextCellsSeed'] = $this->nextCellsRandomSeed;

    $storeId = $this->getStoreId($uid);

    $this->psl['store']->write('gridcard', $storeId, $store);
  }

  public function validate(Array $values, $uid)
  {
    $this->getGridValues();
    $cells = $this->getNextCells();

    for ($i=0; $i < count($cells); $i++) {
      preg_match('/\D+/', $cells[$i], $col_matches);
      preg_match('/\d+/', $cells[$i], $row_matches);
      $col = $col_matches[0];
      $row = $row_matches[0];

      if (!$this->_validateCell($col, $row, $values[$i])) {
        // Get new random seed for next cells
        $this->_updateNextCellsRandomSeed($uid);

        return false;
      }
    }
    // Get new random seed for next cells
    $this->_updateNextCellsRandomSeed($uid);
    return true;
  }

  /**
    * Validates the value from a specific cell
    * @Param mixed $col Integer column number or string column name
    * @Param Integer $row row number
    * @Param String $val Value to check against.
    * @Note This will show false negatives if $val is not a string for cell
    * values that start with 0.
    */
  private function _validateCell($col, $row, $val)
  {
    if (!is_numeric($col)) {
      $col = $this->_letters_to_num($col);
    }
    $this->getGridValues();

    return ((string)$this->_values[$row-1][$col-1] === (string)$val);
  }

  public function load($uid)
  {
    $store = $this->psl['store'];
    $storeData = $store->read('gridcard', $this->getStoreId($uid));

    if($storeData !== false) {
      // Delete the entry if it has expired
      if ($storeData['expiry'] < time()) {
        $store->delete('gridcard', $this->getStoreId($uid));
        return false;
      }

      $this->numCols = $storeData['numCols'];
      $this->numRows = $storeData['numRows'];
      $this->seedRandom = $storeData['seedRandom'];
      $this->gridChars = $storeData['chars'];
      $this->expiry = $storeData['expiry'];
      $this->nextCellsRandomSeed = $storeData['nextCellsSeed'];

      return true;
    }
    return false;
  }

  /**
    * Gets the next 3 cells to be used for validation.
    * @Note Refreshing the page should *not* get different values. Only after
    * validating should they change
    */
  public function getNextCells()
  {
    $next_cells = array();
    // Seed the random number generator
    mt_srand($this->nextCellsRandomSeed);
    for ($i=0; $i < 3; $i++) {
      // Loop to make sure next values are unique
      while (!isset($next_cells[$i])) {
        $value = $this->_num_to_letters(mt_rand(1, $this->numCols));
        $value .= mt_rand(1, $this->numRows);
        if (array_search($value, $next_cells) === false) {
          $next_cells[$i] = $value;
        }
      }
    }
    return $next_cells;
  }

  public function getGridHTML()
  {
    $this->getGridValues();

    $html = '
      <table class="otp_grid">
      <thead>
          <tr>
              <td></td>';

    for ($c=1; $c<=$this->numCols; $c++) {
      $html .= '<td>'.$this->_num_to_letters($c).'</td>';
    }

    $html .= '
          </tr>
      </thead>
      <tbody>';

    for ($r=0; $r<$this->numRows; $r++) {
      $html .= '<tr>';
      for ($c=0; $c<=$this->numCols; $c++) {
        if ($c === 0) {
          $html .= '<td>'.($r+1).'</td>';
        }
        else {
          $html .= '<td>'.$this->_values[$r][$c-1].'</td>';
        }
      }
      $html .= '</tr>';
    }

    $html .= '
      </tbody>
      </table>';

    return $html;
  }

  /**
    * Gets all cell values for the grid
    * @Return Array
    */
  public function getGridValues()
  {
    $hash = $this->_getStringHash($this->numRows * $this->numCols * 2);

    $rows = str_split($hash, $this->numCols * 2);

    foreach ($rows as $index => $row) {
      $cols = str_split($row, 2);

      $this->_values[$index] = $cols;
    }
  }

  /**
    * @Note This needs to be called after every validation (failed or passed)
    */
  private function _updateNextCellsRandomSeed($uid)
  {
    $this->nextCellsRandomSeed = mt_rand(0, pow($this->numCols * $this->numRows, 3));
    $this->save($uid);
  }

  private function _getStringHash($length)
  {
    $string = '';

    // Seed the random number generator with a number based on the hash so
    // that it always returns a specific number
    mt_srand(crc32($this->seedRandom));

    $chars_array = str_split($this->gridChars);
    for ($i = 0; $i < $length ; $i++) {
      // Note, this is not actually random since we seeded the random
      // number generator with a specific value
      $string .= $this->gridChars[mt_rand(0,count($chars_array)-1)];
    }

    // Reset the random number generator in case it is used elsewhere
    mt_srand();

    return $string;
  }

  private function _num_to_letters($num, $uppercase = true)
  {
    $letters = '';
    while ($num > 0) {
      $code = ($num % 26 == 0) ? 26 : $num % 26;
      $letters .= chr($code + 64);
      $num = ($num - $code) / 26;
    }
    return ($uppercase) ? strtoupper(strrev($letters)) : strrev($letters);
  }

  private function _letters_to_num($letters)
  {
    $num = 0;
    $arr = array_reverse(str_split($letters));

    for ($i = 0; $i < count($arr); $i++) {
      $num += (ord(strtolower($arr[$i])) - 96) * (pow(26,$i));
    }
    return $num;
  }

  private function getStoreId($uid) {
    return hash('sha512', $uid);
  }
}
