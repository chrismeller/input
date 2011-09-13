<?php

	class Input {
		
		protected static $instance;
		
		protected $ip_address = null;
		
		protected $use_xss_clean = true;
		protected $magic_quotes_gpc = false;
		
		protected $raw = array();
		
		public static function instance ( ) {
			
			if ( Input::$instance === null ) {
				// Input::__construct() looks for $instance == null on first run, then sets itself, so don't screw that up
				return new Input;
			}
			
			return Input::$instance;
			
		}
		
		public function __construct ( ) {
			
			// always make sure we're UTF8, etc.
			$_GET		= Input::clean($_GET);
			$_POST		= Input::clean($_POST);
			$_COOKIE	= Input::clean($_COOKIE);
			$_SERVER	= Input::clean($_SERVER);
			
			// save all our arrays so we can get non-xss_clean'd values later if we need to
			$this->raw['GET'] = $_GET;
			$this->raw['POST'] = $_POST;
			$this->raw['COOKIE'] = $_COOKIE;
			$this->raw['SERVER'] = $_SERVER;
			
			$global_xss = Kohana::$config->load('security.global_xss_filtering');
			
			// we default to enabling global cleaning. if they specifically set boolean false we'll disable it
			if ( $global_xss === false ) {
				$this->use_xss_clean = false;
			}
			else {
				$this->use_xss_clean = true;
			}
			
			if ( Input::$instance === null ) {
				
				// clean $_GET keys and values
				if ( is_array( $_GET ) ) {
					
					foreach ( $_GET as $k => $v ) {
						
						$_GET[ $this->clean_input_keys( $k ) ] = $this->clean_input_data( $v );
						
					}
					
				}
				else {
					$_GET = array();
				}
				
				
				// clean $_POST keys and values
				if ( is_array( $_POST ) ) {
					
					foreach ( $_POST as $k => $v ) {
						
						$_POST[ $this->clean_input_keys( $k ) ] = $this->clean_input_data( $v );
						
					}
					
				}
				else {
					$_POST = array();
				}
				
				
				// clean $_COOKIE keys and values
				if ( is_array( $_COOKIE ) ) {
					
					foreach ( $_COOKIE as $k => $v ) {
						
						// ignore special attributes in RFC2109 compliant cookies
						if ( $k == '$Version' || $k == '$Path' || $k == '$Domain' ) {
							continue;
						}
						
						$_COOKIE[ $this->clean_input_keys( $k ) ] = $this->clean_input_data( $v );
						
					}
					
				}
				else {
					$_COOKIE = array();
				}
				
				
				// clean $_SERVER keys and values
				if ( is_array( $_SERVER ) ) {
					
					foreach ( $_SERVER as $k => $v ) {
						
						$_SERVER[ $this->clean_input_keys( $k ) ] = $this->clean_input_data( $v );
						
					}
					
				}
				else {
					$_SERVER = array();
				}
				
				
				Input::$instance = $this;
				
				Kohana_Log::instance()->add( Log::DEBUG, 'Global arrays filtered');
				
			}
			
		}
		
		/**
		 * Enforce W3C standards for allowed key name strings - helps prevent malicious naming. Calls xss_clean() if globally enabled.
		 * @param string $value The string to clean
		 * @return string
		 */
		public function clean_input_keys ( $value, $xss_clean = true ) {
			
			// first, xss_clean() the value
			if ( $xss_clean != false && $this->use_xss_clean == true ) {
				$value = $this->xss_clean( $value );
			}
			
			// now make sure it's still compliant
			if ( !preg_match( '#^[\pL0-9:_.-]++$#uD', $value ) ) {
				return false;
			}
			
			return $value;
			
		}
		
		/**
		 * Clean data values. Calls xss_clean() only if globally enabled.
		 * @param string $value The string (or array of strings) to clean.
		 * @return string The cleaned string (or array of strings).
		 */
		public function clean_input_data ( $value, $xss_clean = true ) {
			
			if ( $xss_clean != false && $this->use_xss_clean == true ) {
				$value = $this->xss_clean( $value );
			}
			
			return $value;
			
		}
		
		public static function clean ( $value ) {
			
			// cleaning up text (so that it's all UTF8) is now handled in the UTF8 class
			return UTF8::clean( $value );
			
		}
		
		public function get ( $key = array(), $default = null, $xss_clean = true ) {
			
			if ( $xss_clean == false ) {
				return $this->search_array( $this->raw['GET'], $key, $default, $xss_clean );
			}
			else {
				return $this->search_array( $_GET, $key, $default, $xss_clean );
			}
			
		}
		
		public function post ( $key = array(), $default = null, $xss_clean = true ) {
			
			if ( $xss_clean == false ) {
				return $this->search_array( $this->raw['POST'], $key, $default, $xss_clean );
			}
			else {
				return $this->search_array( $_POST, $key, $default, $xss_clean );
			}
			
		}
		
		public function cookie ( $key = array(), $default = null, $xss_clean = true ) {
			
			if ( $xss_clean == false ) {
				return $this->search_array( $this->raw['COOKIE'], $key, $default, $xss_clean );
			}
			else {
				return $this->search_array( $_COOKIE, $key, $default, $xss_clean );
			}
			
		}
		
		public function server ( $key = array(), $default = null, $xss_clean = true ) {
			
			if ( $xss_clean == false ) {
				return $this->search_array( $this->raw['SERVER'], $key, $default, $xss_clean );
			}
			else {
				return $this->search_array( $_SERVER, $key, $default, $xss_clean );
			}
			
		}
		
		/**
		 * Return the ip address of the current user. Handles several common proxy headers to try and get the real IP.
		 * @return string|null The User's IP address or null on error. Note that this could be an IPv6 IP, don't limit the length!
		 */
		public function ip_address ( ) {
			
			if ( $this->ip_address !== null ) {
				return $this->ip_address;
			}
			
			$keys = array( 'HTTP_FORWARDED', 'HTTP_X_FORWARDED', 'HTTP_X_FORWARDED_FOR', 'HTTP_CLIENT_IP', 'REMOTE_ADDR' );
			
			foreach ( $keys as $key ) {
				
				if ( $ip = $this->server( $key ) ) {
					break;
				}
				
			}
			
			// make sure it's a valid ip - uses filter_var() and supports IPv4 and IPv6
			if ( Validate::ip( $ip ) ) {
				$this->ip_address = $ip;
			}
			
			return $this->ip_address;
			
		}
		
		protected function search_array ( $array, $key, $default = null, $xss_clean = true ) {
			
			if ( $key === array() || $key === null ) {
				return $array;
			}
			
			if ( !isset( $array[ $key ] ) ) {
				return $default;
			}
			
			// get the value
			$value = $array[ $key ];
			
			// only xss_clean it if the global is turned off and we've specified that we should
			// if global is on, it was cleaned during __construct, so there's no reason to do so again
			if ( $this->use_xss_clean == false && $xss_clean == true ) {
				$value = self::xss_clean( $value );
			}
			
			return $value;
			
		}
		
		protected function xss_clean ( $value ) {
			
			return Security::xss_clean( $value );
			
		}
		
	}

?>