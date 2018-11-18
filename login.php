<?
include("server.php");

$user_id_autologin=$_GET["user_id"];
$password_autologin=$_GET["password"];
$session_id_autologin=$_GET["session_id"];
	
if ($user_id_autologin!="" and $password_autologin!="") 
{
	$username=$user_id_autologin;
	$password=$password_autologin;
	$id=$session_id_autologin;
	$kode="autologin";
}
else 
{
	$username=$_POST["username"];
	$password=$_POST["password"];
	if($username=="" && $password=="")
	{
		$username=$_GET["username"];
		$password=$_GET["password"];
	}
}



function get_ip() 
{
	//Just get the headers if we can or else use the SERVER global
	if(function_exists('apache_request_headers'))
	{
		$headers = apache_request_headers();
	}
	else
	{
		$headers = $_SERVER;
	}

	//Get the forwarded IP if it exists
	if(array_key_exists('X-Forwarded-For', $headers) && filter_var($headers['X-Forwarded-For'], FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) )
	{
		$the_ip = $headers['X-Forwarded-For'];
	}
	elseif(array_key_exists('HTTP_X_FORWARDED_FOR', $headers) && filter_var($headers['HTTP_X_FORWARDED_FOR'], FILTER_VALIDATE_IP, FILTER_FLAG_IPV4))
	{
		$the_ip = $headers['HTTP_X_FORWARDED_FOR'];
	}
	else
	{
		$the_ip = filter_var( $_SERVER['REMOTE_ADDR'], FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 );
	}
	return $the_ip;
}

$ip=get_ip();

//if ($ip == "172.16.32.43") $ip = "172.16.129.251";

//DENGAN PROXY
//$ip_awal = $_SERVER["HTTP_X_FORWARDED_FOR"];
//$ip = substr($ip_awal, 0, strpos($ip_awal,','));

//TANPA PROXY
if ($ip == "") 
{
	$ip = $ip_awal; 
	$isproxy = "N";
}
else $isproxy = "Y";
	
//if ($ip == "172.16.129.251") 
if ($ip == "10.1.18.123") 
{
	$_SESSION["server_error"]="Lakukan setting NO PROXY terlebih dahulu";
	//echo $_SESSION["server_error"];
	header("location:.");
}
else
{
	//$ip=$_SERVER['REMOTE_ADDR'];
	$islogout="N";
	$islogin="Y";
	
	/*$strsql="select a.*, b.N_TIPE, c.nmktr from TMUSER a 
			LEFT JOIN MN_TIPE b ON a.ID_TIPE=b.ID_TIPE
			left join d_ktr c ON a.C_KTR=c.kdktr
			where upper(a.USERNAME)=upper('$username') and upper(a.PASSWORD)=upper('$password')";	*/
	$strsql="select a.USERNAME,a.PASSWORD,a.C_KTR,a.C_USER_GRP,A.C_AKSESKANTOR,a.R_W,a.FULL_AKSES,a.LEVEL_OTORISASI,a.ROLE_NAME,a.ID_TIPE,a.KODE_ROLE,TO_CHAR(a.TGL_EXPIRED,'YYYY-MM-DD') AS TGL_EXPIRED, b.N_TIPE, c.nmktr from TMUSER a 
            LEFT JOIN MN_TIPE b ON a.ID_TIPE=b.ID_TIPE
            left join d_ktr c ON a.C_KTR=c.kdktr
            where upper(a.USERNAME)=upper('$username') and upper(a.PASSWORD)=upper('$password')";
	//echo $strsql;
	$q=oci_parse($conn,$strsql) or die("Query gagal" );
	oci_execute($q);
	$row=oci_fetch_assoc($q);
	$xusername=$row["USERNAME"];  //harus pakai huruf gede! persis sama dengan koneksi FireBird karena di databasenya juga pake huruf gede
	session_start();
	if(strtoupper($xusername)==strtoupper($username) and $xusername!="")
	   {	   
		$_SESSION["server_id_user"]=$row["ID_USER"];
		$_SESSION["server_user"]=$row["USERNAME"];	
		
		$_SESSION["server_kantor"]=$row["C_KTR"];
		
		$_SESSION["server_nama_kantor"]=$row["NMKTR"];
		$_SESSION["server_rolename"]=$row["ROLE_NAME"];
		$_SESSION["server_tipe"]=$row["N_TIPE"];
		$_SESSION["server_role"]=$row["KODE_ROLE"];
		$_SESSION["server_role_sejati"]=$row["KODE_ROLE"];
		$_SESSION["server_tgl_expired"]=$row["TGL_EXPIRED"];
		$_SESSION["server_error"]="";
		$now=$_SESSION["now"]=date("Y-m-d");
		
		$_SESSION['start'] = time(); // Taking now logged in time.
		// Ending a session in 30 minutes from the starting time.
		$_SESSION['expire'] = $_SESSION['start'] + (60 * 90); // 15 menit
				
		$username=$_SESSION["server_user"];

				
		$lastlogin=date("Y-m-d H:i");
		$lastlogout=date("Y-m-d H:i");
		$xnow=date("Y-m-d");
		
		if($xnow >= $row["TGL_EXPIRED"])
		{
			
		header("location:users/chgpass_expired.php");	
			
		}
			else
		{
			if ($kode=="autologin")	
			{ 
				$_SESSION["id"]=$id;
				header("location:home/");

			}
			else 
			{
			$sql_single_sign_on_cek="select count(ISLOGIN) as JUMLAH from HS_USERLOG where USERNAME='$username' and ISLOGIN='Y'";
				$r=oci_parse($conn,$sql_single_sign_on_cek);
				oci_execute($r);
				$row2=oci_fetch_assoc($r);
				$jumlah=$row2["JUMLAH"];
				
					if ($jumlah==0)
					{	
					$strsql="insert into HS_USERLOG(USERNAME,LASTLOGIN,IP_ADDRESS, ISLOGOUT, ISLOGIN, ISPROXY) 
						 values('$username',to_date('$lastlogin','yyyy-mm-dd HH24:MI'),'$ip', '$islogout', '$islogin', '$isproxy')";
						//echo $strsql;
						$q=oci_parse($conn,$strsql);
						oci_execute($q);
						
						//seleksi user id di HS_USERLOG
						$sql="select SQ_ID_HSUSERLOG.currval as ID_USER_TMP from dual";
						$q=oci_parse($conn,$sql);
						oci_execute($q);
						$row=oci_fetch_array($q);
						$_SESSION["id"]=$row["ID_USER_TMP"];
						
						$content=$_SESSION["id"];
						$waktusesi=$_SESSION['expire'];
					
						$sql="INSERT INTO TMSESSIONS(SESSION_ID, USER_ID, ISLOGIN, ISLOGOUT, WAKTUSESI, IP_ADDRESS, PWD) VALUES('$content', '$username', 'Y', 'N', '$waktusesi', '$ip', '$password')";
						$q=oci_parse($conn,$sql);
						oci_execute($q);
						
					oci_close($conn);
					header("location:home/");
					}
					else 
					{
						session_destroy();
						//echo "User <strong>$userid</strong> masih login";
						header("location:index.php?error=1&userid=$username");
					}
		   }
		   
	   	}
	   }
	   else
	   {	
			//echo ("Login gagal! Username/Password tidak benar<br>");
			//echo ("<a href=index.php>Ulangi lagi</a>"); 
			oci_close($conn);
			$_SESSION["server_error"]="Login error";
			header("location:.");
	   }	
}	
?>


