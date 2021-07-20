<?php
/**
 * Script Sederhana Telegram BOT
 * Menggunakan Bahasa Program PHP
 * @script000kiddies000
 */
 
 // Pengaturan Waktu Indonesia
date_default_timezone_set("ASIA/Jakarta");

// Token & API Telegram
$akses_token = '';
$usernamebot='';
$api = 'https://api.telegram.org/bot' . $akses_token;

/**
 * Silahkan edit mulai dari sini
 * Sesuaikan dengan kebutuhan
 */

// Jika user bergabung
$output = json_decode(file_get_contents('php://input'), TRUE);
$chat_id = $output['message']['chat']['id'];
$message = $output['message']['text'];
// Jika user datang
if ($output['message']['new_chat_member']){
    $obj = $output['message']['new_chat_member'];
    $MemberBaru ="Halo.. ". $obj['first_name'] ." - @".$obj['username'] . " Selamat Bergabung di Grup!";; 
    sendMessage($chat_id, $MemberBaru);
}

// Jika user pergi
// Tidak berlaku ketika user pada grup sudah lebih dari 50
if ($output['message']['left_chat_member']){
    $MemberPergi = "User @". $output['message']['left_chat_member']['username'] . " Meninggalkan Grup.";
    sendMessage($chat_id, $MemberPergi);
}


// Cek Status BOT
$message= json_decode(file_get_contents('php://input'), TRUE);
$chat_id = $message['message']['chat']['id'];
$fromid  = $message['message']["from"]["id"];
$text    = $message['message']['text'];
$username = $message['message']['from']['username'];

//variable nampung nama user 
isset($message['message']['from']['last_name']) 
        ? $namakedua = $message['message']['from']['last_name'] 
        : $namakedua = '';   
$namauser = $message['message']["from"]["first_name"]. ' ' .$namakedua;

//ambi id orang lain dari pesan yang di reply

$idorang         = $message['message']['reply_to_message']['from']['id'];
$usernameorang   = $message['message']['reply_to_message']['from']['username'];

//buat hapus kelebihan spasi
$message = preg_replace('/\s\s+/', ' ', $text);

//buat membagi pesan menjadi 3 bagian
$command = explode(' ',$message,3);
//ambil bagian pesan yang pertama

//bloking user pake username
//if(!in_array($username, array("Cyber_123","SkyAnonymousBlackHat","SkyAnonymousGreyHat"), true )){


//bloking user pake id 
//$buronan=explode("\n",file_get_contents('logs.txt'));
if ( !in_array($fromid,array(604679466,455848768), true ) ) {

//ambil api hackertarget

function web($tool,$isi){
	$url="http://api.hackertarget.com/".$tool."/?q=".$isi;
	$hasil= file_get_contents($url);
	return $hasil;
}


switch($command[0]) {
        case '/colongid':
          $hasil="id akun $usernameorang adalah $idorang";
          sendMessage($chat_id,$hasil);
        break;

        case '/start':
        case '/start'.$usernamebot :
            sendMessage($chat_id, "Halo.. saya adalah Hmei7");
            break;

        case '/help':
        case '/help'.$usernamebot :
            $hasil  = "kumpulan command bot :\n";
            $hasil .= "➖➖➖➖➖➖➖➖➖➖➖➖\n";
            $hasil .= "/intip (bit.ly/target) - mengintip isi link\n";
            $hasil .= "/zontransfer (target) - tool zonetransfer\n";
            $hasil .= "/reverseip (target) - melihat domain dari ip\n";
            $hasil .= "/dnslookup (target)\n";
            $hasil .= "/subnetcal (192.168.1.1/24)\n";
            $hasil .= "/httpheader (target) - melihat http header\n";
            $hasil .= "/subdomain (Target) - mencari subdomain web\n";
            $hasil .= "/nmap (target) - tool nmap\n";
            $hasil .= "/geoip (ip) - tool mencai lokasi ip\n";
            $hasil .= "/whois (target) - tool whois\n";
            $hasil .= "/reversedns (domain) - melihat ip sebuah domain\n";
            $hasil .= "/testping (domain)\n";
            $hasil .= "/traceroute (target) - melihat route ke tujuan\n";
            $hasil .= "/scancms (target) - untuk scan cms website\n";
            $hasil .= "/ipinfo (ip) - melihat informasi sebuah ip\n";
            $hasil .= "/id - melihat id telegram mu\n";
            $hasil .= "/time - melihat waktu pada bot\n";
            $hasil .= "/echo - ini sangat rahasia\n";
            $hasil .= "/creator - melihat pembuat bot ini\n";
            $hasil .= "/infokulgram - cek info kulgram terbaru\n";
            $hasil .= "/waifu (namamu) - melihat siapa waifumu\n";
            $hasil .= "/virustotal google.com - scan virus on url\n";
            $hasil .= "/smsin(spasi)noHP(spasi)pesan - sms gratis\n";
            $hasil .= "/wpuser linkweb - dump user wp \n";
            $hasil .= "/crackmd5 hashmd5 - crack md5\n";
            $hasil .= "➖➖➖➖➖➖➖➖➖➖➖➖\n";
	    	$hasil .= "⚠️ JANGAN DI KLIK, CUKUP DI KETIK!!! ⚠️\n";
	    	$hasil .= "✅ contoh /nmap google.com ✅";
	    	$hasil2=$hasil;
	    	sendMessage($chat_id,$hasil);
            break;

        case '/crackmd5':
        case '/crackmd5'.$usernamebot:
        	$md5=$command[1];
        	$ambil=file_get_contents('http://widhisec.000webhostapp.com/api/hsh/?md5='.$md5);
        	$ambil=json_decode($ambil,true);
        	if($ambil['result']=="false"){
        		sendMessage($chat_id,'maaf tidak di temukan.');
        	}else{
        		$hasil = "hash : ".$md5."\n hasil : ".$ambil['result']."\n crack by : ".$ambil['website'];
        		sendMessage($chat_id,$hasil);
        	}
        break;

        case '/zonetransfer':
        case '/zonetransfer'.$usernamebot : 
	    $zone=$command[1];
	    if(empty($zone)){
              sendMessage($chat_id,"⛔️ pesan tidak boleh kosong ⛔️\n"."contoh : /zonetransfer google.com");
            }else{
	    $hasil   = web('zonetransfer',$zone);
	    sendMessage($chat_id,$hasil);
	    }
            break;

        case '/reverseip':
        case '/reverseip'.$usernamebot :
	    $ip=$command[1];
	    if(empty($ip)){
              sendMessage($chat_id,"⛔️ pesan tidak boleh kosong ⛔️\n"."contoh : /reverseip 8.8.8.8");
            }else{
	    $hasil      = web('reverseiplookup',$ip);
	    sendMessage($chat_id,$hasil);
	    }
            break;

        case '/dnslookup':
        case '/dnslookup'.$usernamebot :
	    $zone=$command[1];
	    if(empty($zone)){
              sendMessage($chat_id,"⛔️ pesan tidak boleh kosong ⛔️\n"."contoh : /dnslookup google.com");
            }else{
	    $hasil      = web('dnslookup',$zone);
	    sendMessage($chat_id,$hasil);
	    }
            break;

        case '/subnetcal':
        case '/subnetcal'.$usernamebot :
	    $zone=$command[1];
	    if(empty($zone)){
              sendMessage($chat_id,"⛔️ pesan tidak boleh kosong ⛔️\n"."contoh : /subnetcal 10.10.10.1/24");
            }else{
	    $hasil      = web('subnetcalc',$zone);
	    sendMessage($chat_id,$hasil);
	    }
            break;

        case '/httpheader':
        case '/httpheader'.$usernamebot :
	    $zone=$command[1];
	    if(empty($zone)){
              sendMessage($chat_id,"⛔️ pesan tidak boleh kosong ⛔️\n"."contoh : /httpheader google.com");
            }else{
	    $hasil      = web('httpheaders',$zone);
	    sendMessage($chat_id,$hasil);
	    }
            break;

        case '/subdomain':
        case '/subdomain'.$usernamebot :
	    $zone=$command[1];
	    if(empty($zone)){
              sendMessage($chat_id,"⛔️ pesan tidak boleh kosong ⛔️\n"."contoh : /subdomain kpu.go.id");
            }else{
	    $hasil      = web('hostsearch',$zone);
	    sendMessage($chat_id,$hasil);
	    }
            break;

        case '/nmap':
        case '/nmap'.$usernamebot :
	    $zone=$command[1];
	    if(empty($zone)){
              sendMessage($chat_id,"⛔️ pesan tidak boleh kosong ⛔️\n"."contoh : /nmap google.com");
            }else{
	    $hasil2     = web('nmap',$zone);
	    $hasil      = substr($hasil2,0,3000);
	    sendMessage($chat_id,$hasil);
	    }
            break;

        case '/geoip':
        case '/geoip'.$usernamebot : 
	    $zone=$command[1];
	    if(empty($zone)){
              sendMessage($chat_id,"⛔️ pesan tidak boleh kosong ⛔️\n"."contoh : /geoip 8.8.8.8");
            }else{
	    $hasil      = web('geoip',$zone);
	    sendMessage($chat_id,$hasil);
	    }
            break;

        case '/whois':
        case '/whois'.$usernamebot :
	    $zone=$command[1];
	    if(empty($zone)){
              sendMessage($chat_id,"⛔️ pesan tidak boleh kosong ⛔️\n"."contoh : /whois google.com");
            }else{
	    $hasil      = web('whois',$zone);
	    sendMessage($chat_id,$hasil);
	    }
            break;

        case '/reversedns':
        case '/reversedns'.$usernamebot :
	    $zone=$command[1];
	    if(empty($zone)){
              sendMessage($chat_id,"⛔️ pesan tidak boleh kosong ⛔️\n"."contoh : /reversedns google.com");
            }else{
	    $hasil      = web('reversedns',$zone);
	    sendMessage($chat_id,$hasil);
	    }
            break;

        case '/testping':
        case '/testping'.$usernamebot :
	    $zone=$command[1];
	    if(empty($zone)){
              sendMessage($chat_id,"⛔️ pesan tidak boleh kosong ⛔️\n"."contoh : /testping google.com");
            }else{
	    $hasil      = web('nping',$zone);
	    sendMessage($chat_id,$hasil);
	    }
            break;

        case '/traceroute':
        case '/traceroute'.$usernamebot :
	    $zone=$command[1];
	    if(empty($zone)){
              sendMessage($chat_id,"⛔️ pesan tidak boleh kosong ⛔️\n"."contoh : /traceroute google.com");
            }else{
	    $hasil      = web('mtr',$zone);
	    sendMessage($chat_id,$hasil);
	    }
            break;

        case '/scancms':
        case '/scancms'.$usernamebot :
	    $url=$command[1];
	    if(empty($url)){
              sendMessage($chat_id,"⛔️ pesan tidak boleh kosong ⛔️\n"."contoh : /scancms id.wikipedia.org");
            }else{
	    $urlzone    = "https://whatcms.org/APIEndpoint/Detect?key=834e863ce2f651d775571130cb57c2bc9d0c6ffcd6e89066edbb660c1db2fc7c3ba03c&url=$url";
	    $hasil2     = file_get_contents($urlzone);
	    $decoded    = json_decode($hasil2, TRUE );
	    $result=$decoded['result']['code'];
	    switch($result){
		case "200":
		    $hasil  = "scanning        = ".$decoded['result']['msg']."\n";
		    $hasil .= "nama cms        = ".$decoded['result']['name']."\n";
		    $hasil .= "metode scanning = ".$decoded['result']['confidence']."\n";
		    $hasil .= "versi cms       = ".$decoded['result']['version']."\n";
		    $hasil .= "link cms        = ".$decoded['result']['cms_url'];
		    sendMessage($chat_id,$hasil);
		    break;
		case "201":
		    $hasil = "\n".$decoded['result']['msg'];
		    sendMessage($chat_id,$hasil);
		case "111":
		    $hasil = "\n".$decoded['result']['msg']."\n";
		    $hasil = "\nMASUKIN YANG BENER !!!";
		    sendMessage($chat_id,$hasil);
		    break;
		}
	    }
            break;

        case '/ipinfo':
        case '/ipinfo'.$usernamebot :
	    $ip=preg_replace('/,/i', '.', $command[1]);
	    if(empty($ip)){
              sendMessage($chat_id,"⛔️ pesan tidak boleh kosong ⛔️\n"."contoh : /ipinfo 8.8.8.8");
            }else{
 	    $result=file_get_contents('http://ipinfo.io/'.$ip.'/json');
	    $link =json_decode($result,true);
            $lokasi = explode(',',$link['loc'],2);
	    $ngitung =count($link);
	    switch($ngitung){
		case 9:
		    $hasil ="-=[    info ip address    ]=-\n";
		    $hasil.="ip address   = ".$link['ip']."\n";
		    $hasil.="hostname     = ".$link['hostname']."\n";
		    $hasil.="city         = ".$link['city']."\n";
		    $hasil.="region       = ".$link['region']."\n";
		    $hasil.="country      = ".$link['country']."\n";
		    $hasil.="location     = ".$link['loc']."\n";
		    $hasil.="postal       = ".$link['postal']."\n";
		    $hasil.="phone        = ".$link['phone']."\n";
		    $hasil.="organisasi   = ".$link['org'];
		    sendMessage($chat_id,$hasil);
                    lokasi($chat_id,$lokasi[0],$lokasi[1]);
		    break;
		case 8:
		    $hasil ="-=[    info ip address    ]=-\n";
		    $hasil.="ip address   = ".$link['ip']."\n";
		    $hasil.="hostname     = ".$link['hostname']."\n";
		    $hasil.="city         = ".$link['city']."\n";
		    $hasil.="region       = ".$link['region']."\n";
		    $hasil.="country      = ".$link['country']."\n";
		    $hasil.="location     = ".$link['loc']."\n";
		    $hasil.="postal       = ".$link['postal']."\n";
		    $hasil.="organisasi   = ".$link['org'];
		    sendMessage($chat_id,$hasil);
                    lokasi($chat_id,$lokasi[0],$lokasi[1]);
		    break;
		case 7:
		    $hasil ="-=[    info ip address    ]=-\n";
		    $hasil.="ip address   = ".$link['ip']."\n";
		    $hasil.="city         = ".$link['city']."\n";
		    $hasil.="region       = ".$link['region']."\n";
		    $hasil.="country      = ".$link['country']."\n";
		    $hasil.="location     = ".$link['loc']."\n";
		    $hasil.="postal       = ".$link['postal']."\n";
		    $hasil.="organisasi   = ".$link['org'];
		    sendMessage($chat_id,$hasil);
                    lokasi($chat_id,$lokasi[0],$lokasi[1]);
		    break;	
		case 6:
		    $hasil ="-=[    info ip address    ]=-\n";
		    $hasil.="ip address   = ".$link['ip']."\n";
		    $hasil.="city         = ".$link['city']."\n";
		    $hasil.="region       = ".$link['region']."\n";
		    $hasil.="country      = ".$link['country']."\n";
		    $hasil.="location     = ".$link['loc']."\n";
		    $hasil.="organisasi   = ".$link['org'];
		    sendMessage($chat_id,$hasil);
                    lokasi($chat_id,$lokasi[0],$lokasi[1]);
		    break;
		case 2:
		    $hasil ="-=[    info ip address    ]=-\n";
		    $hasil.="ip address   = ".$link['ip']."\n";
		    $hasil.="( maaf hasil tidak di temukan )";
		    sendMessage($chat_id,$hasil);
		    break;
		}
	    }
            break;

case '/virustotal':
$api_key = getenv('VT_API_KEY') ? getenv('VT_API_KEY') :'6db864732b23b6ad678741a63f6b3ca336bff1244204396f4afd520982a20fd8';
$scan_url =$command[1];
 
$post = array('apikey' => $api_key,'resource'=> $scan_url);
$ch = curl_init();
curl_setopt($ch, CURLOPT_URL, 'https://www.virustotal.com/vtapi/v2/url/report');
curl_setopt($ch, CURLOPT_POST, True);
curl_setopt($ch, CURLOPT_RETURNTRANSFER ,True);
curl_setopt($ch, CURLOPT_POSTFIELDS, $post);
 
$result=curl_exec ($ch);
curl_close ($ch);
$decode=json_decode($result,True);
//var_dump($decode);    <= untuk melihat hasil json nya (semua)
$hasil2  = "➖➖➖➖➖➖➖➖➖➖➖➖\n";
$hasil2 .= "✅scan id 	: ".$decode["scan_id"]. "\n";
$hasil2 .= "✅resource  : ".$decode['resource']. "\n";
$hasil2 .= "✅url              : ".$decode['url']. "\n";
$hasil2 .= "✅scan date : ".$decode['scan_date']. "\n";
$hasil2 .= "✅permalink : \n".$decode['permalink']. "\n";
$hasil2 .= "✅verbose_msg : \n".$decode['verbose_msg']. "\n\n";
$hasil2 .= "➖➖➖➖➖➖➖➖➖➖➖➖\n";
$hasil2 .= "⏩ cleaner            =  ".$decode['scans']['CLEAN MX']['result']. "\n";
$hasil2 .= "⏩ DNS8               = ".$decode['scans']['DNS8']['result']. "\n";
$hasil2 .= "⏩ OpenPhish     = ".$decode['scans']['OpenPhish']['result']. "\n";
$hasil2 .= "⏩ VX Vault        = ".$decode['scans']['VX Vault']['result']. "\n";
$hasil2 .= "⏩ ZDB Zeus       = ".$decode['scans']['ZDB Zeus']['result']. "\n";
$hasil2 .= "⏩ ZCloudsec     = ".$decode['scans']['ZCloudsec']['result']. "\n";
$hasil2 .= "⏩ PhishLabs      = ".$decode['scans']['PhishLabs']['result']. "\n";
$hasil2 .= "⏩ Zerofox         = ".$decode['scans']['Zerofox']['result']. "\n";
$hasil2 .= "⏩ K7AntiVirus  = ".$decode['scans']['K7AntiVirus']['result']. "\n";
$hasil2 .= "⏩ FraudSense  = ".$decode['scans']['FraudSense']['result']. "\n";
$hasil2 .= "⏩ Virusdie         = ".$decode['scans']['Virusdie External Site Scan']['result']. "\n";
$hasil2 .= "⏩ Quttera          = ".$decode['scans']['Quttera']['result']. "\n";
$hasil2 .= "⏩ AegisLab       = ".$decode['scans']['AegisLab WebGuard']['result']. "\n";
$hasil2 .= "⏩ MDList            = ".$decode['scans']['MalwareDomainList']['result']. "\n";
$hasil2 .= "⏩ ZeusTracker  = ".$decode['scans']['ZeusTracker']['result']. "\n";
$hasil2 .= "⏩ zvelo               = ".$decode['scans']['zvelo']['result']. "\n";
$hasil2 .= "⏩ G Sbrowsing = ".$decode['scans']['Google Safebrowsing']['result']. "\n";
$hasil2 .= "⏩ Kaspersky      = ".$decode['scans']['Kaspersky']['result']. "\n";
$hasil2 .= "⏩ BitDefender  = ".$decode['scans']['BitDefender']['result']. "\n";
$hasil2 .= "⏩ Opera              = ".$decode['scans']['Opera']['result']. "\n";
$hasil2 .= "⏩ Certly              = ".$decode['scans']['Certly']['result']. "\n";
$hasil2 .= "⏩ G-Data            = ".$decode['scans']['G-Data']['result']. "\n";
$hasil2 .= "⏩ C-SIRT             = ".$decode['scans']['C-SIRT']['result']. "\n";
$hasil2 .= "⏩ CyberCrime   = ".$decode['scans']['CyberCrime']['result']. "\n";
$hasil2 .= "⏩ SecureBrain  = ".$decode['scans']['SecureBrain']['result']. "\n";
$hasil2 .= "⏩ Malware DB  = ".$decode['scans']['Malware Domain Blocklist']['result']. "\n";
$hasil2 .= "⏩ MalwarePat  = ".$decode['scans']['MalwarePatrol']['result']. "\n";
$hasil2 .= "⏩ Webutation  = ".$decode['scans']['Webutation']['result']. "\n";
$hasil2 .= "⏩ Trustwave     = ".$decode['scans']['Trustwave']['result']. "\n";
$hasil2 .= "⏩ W S Guard     = ".$decode['scans']['Web Security Guard']['result']. "\n";
$hasil2 .= "⏩ CyRadar         = ".$decode['scans']['CyRadar']['result']. "\n";
$hasil2 .= "⏩ desenmascara.me  = ".$decode['scans']['desenmascara.me']['result']. "\n";
$hasil2 .= "⏩ ADMINUSLabs         = ".$decode['scans']['ADMINUSLabs']['result']. "\n";
$hasil2 .= "⏩ Malwareb hpHosts = ".$decode['scans']['Malwarebytes hpHosts']['result']. "\n";
$hasil2 .= "⏩ Dr.Web                        = ".$decode['scans']['Dr.Web']['result']. "\n";
$hasil2 .= "⏩ AlienVault                 = ".$decode['scans']['AlienVault']['result']. "\n";
$hasil2 .= "⏩ Emsisoft                     = ".$decode['scans']['Emsisoft']['result']. "\n";
$hasil2 .= "⏩ Rising                          = ".$decode['scans']['Rising']['result']. "\n";
$hasil2 .= "⏩ Malcode Database = ".$decode['scans']['Malc0de Database']['result']. "\n";
$hasil2 .= "⏩ malwares.com         = ".$decode['scans']['malwares.com URL checker']['result']. "\n";
$hasil2 .= "⏩ Phishtank                  = ".$decode['scans']['Phishtank']['result']. "\n";
$hasil2 .= "⏩ Malwared                 = ".$decode['scans']['Malwared']['result']. "\n";
$hasil2 .= "⏩ Avira                           = ".$decode['scans']['Avira']['result']. "\n";
$hasil2 .= "⏩ NotMining                = ".$decode['scans']['NotMining']['result']. "\n";
$hasil2 .= "⏩ StopBadware          = ".$decode['scans']['StopBadware']['result']. "\n";
$hasil2 .= "⏩ Antiy-AVL                 = ".$decode['scans']['Antiy-AVL']['result']. "\n";
$hasil2 .= "⏩ Forcepoint Threat = ".$decode['scans']['Forcepoint ThreatSeeker']['result']. "\n";
$hasil2 .= "⏩ SCUMWARE.org    = ".$decode['scans']['SCUMWARE.org']['result']. "\n";
$hasil2 .= "⏩ Comodo Site          = ".$decode['scans']['Comodo Site Inspector']['result']. "\n";
$hasil2 .= "⏩ Malekal                   = ".$decode['scans']['Malekal']['result']. "\n";
$hasil2 .= "⏩ ESET                         = ".$decode['scans']['ESET']['result']. "\n";
$hasil2 .= "⏩ Sophos                    = ".$decode['scans']['Sophos']['result']. "\n";
$hasil2 .= "⏩ Yandex SafeB       = ".$decode['scans']['Yandex Safebrowsing']['result']. "\n";
$hasil2 .= "⏩ Spam404                = ".$decode['scans']['Spam404']['result']. "\n";
$hasil2 .= "⏩ Nucleon                 = ".$decode['scans']['Nucleon']['result']. "\n";
$hasil2 .= "⏩ Sucuri SiteCheck  = ".$decode['scans']['Sucuri SiteCheck']['result']. "\n";
$hasil2 .= "⏩ Blueliv                     = ".$decode['scans']['Blueliv']['result']. "\n";
$hasil2 .= "⏩ Netcraft                  = ".$decode['scans']['Netcraft']['result']. "\n";
$hasil2 .= "⏩ AutoShun              = ".$decode['scans']['AutoShun']['result']. "\n";
$hasil2 .= "⏩ ThreatHive             = ".$decode['scans']['ThreatHive']['result']. "\n";
$hasil2 .= "⏩ FraudScore            = ".$decode['scans']['FraudScore']['result']. "\n";
$hasil2 .= "⏩ Tencent                   = ".$decode['scans']['Tencent']['result']. "\n";
$hasil2 .= "⏩ URLQuery               = ".$decode['scans']['URLQuery']['result']. "\n";
$hasil2 .= "⏩ Fortinet                   = ".$decode['scans']['Fortinet']['result']. "\n";
$hasil2 .= "⏩ ZeroCERT                = ".$decode['scans']['ZeroCERT']['result']. "\n";
$hasil2 .= "⏩ Baidu-Inter             = ".$decode['scans']['Baidu-International']['result']. "\n";
$hasil2 .= "⏩ securolytics           = ".$decode['scans']['securolytics']['result']. "\n";
$hasil2 .= "➖➖➖➖➖➖➖➖➖➖➖➖\n";
$hasil2.="mohon maaf masih dalam tahap pengembangan\n kritik dan saran pm ke https://t.me/script000kiddies0000.";
$hasil=$hasil2;
	    sendMessage($chat_id,$hasil);
            break;

        case '/id':
        case '/id'.$usernamebot :
            sendMessage($chat_id, " ID kamu adalah .$fromid\n");
            break;


        case '/echo':
        case '/echo'.$usernamebot :
            $hasil  = "$namauser kamu ganteng banget :v ";
	    sendMessage($chat_id,$hasil);
            break;

        case '/time':
        case '/time'.$usernamebot :
            $hasil  = "$namauser, waktu lokal bot sekarang adalah :\n";
            $hasil .= "🗓 ".date("d M Y")."\n⏱ Pukul ".date("H:i:s");
	    sendMessage($chat_id,$hasil);
            break;

        case '/creator':
        case '/creator'.$usernamebot :
            $hasil  = "create by : @Hmei7";
	    sendMessage($chat_id,$hasil);
            break;

        case '/infokulgram':
        case '/infokulgram'.$usernamebot :
	    $hasil = file_get_contents("http://tcmild.com/kulgram.txt");
	    sendMessage($chat_id,$hasil);
            break;

        case '/waifu':
        case '/waifu'.$usernamebot : //dipakai jika di grup yang haru ditambahkan @usernamebot
	    $an = array(
array("Umaru Doma","https://ae01.alicdn.com/kf/HTB17fsQKFXXXXaNXFXXq6xXFXXXp/New-Japanese-Anime-Himouto-Umaru-chan-Doma-Umaru-Otaku-Pillow-Cover-Case-Hugging-Body-long-love.jpg_640x640.jpg"),
array("Yuzuriha Inori","https://i.pinimg.com/originals/a1/b8/8f/a1b88fa72ca2c930b5aa9ceacae5c95e.jpg"),
array("Rika Shiramine","https://img00.deviantart.net/f181/i/2016/097/d/d/coffe_kizoku_shiramine_rika_render_by_elverae-d8cqblz.png"),
array("Hinata Kaho","https://static.zerochan.net/Hinata.Kaho.full.2215425.png"),
array("Maika","https://static.zerochan.net/Sakuranomiya.Maika.full.2223945.png"),
array("Asuna Yuuki","https://i.ebayimg.com/images/g/9UMAAOSwHYpZ90Yq/s-l300.jpg"),
array("Kuroyuki hime","http://adn.i.ntere.st/p/4110512/image"),
array("Renge Miyauchi","https://photos1.iorbix.com/00/00/00/00/02/13/72/81/Renge-Miyauchi-Nec8lLs10-b.jpg"),
array("Hotaru Ichijo","https://i.ebayimg.com/images/g/NpEAAOSwk-1aIk2w/s-l300.jpg"),
array("Natsumi Koshigaya","https://orig00.deviantart.net/7387/f/2013/310/e/3/001_by_shimauo-d6t8no8.jpg"),
array("Komari Koshigaya","https://i.pinimg.com/736x/52/28/09/5228092147082a69056a94b8f9b8494b--non-non-biyori-anime-girls.jpg"),
array("Hikage Miyauchi","https://static.zerochan.net/Miyauchi.Hikage.full.1894890.jpg"),
array("Konomi Fujimiya","https://static.zerochan.net/Fujimiya.Konomi.full.1634706.jpg"),
array("Honoka Ishikawa","https://farm6.static.flickr.com/5675/30646845283_14ab6558e3_b.jpg"),
array("chitoge","https://i.pinimg.com/originals/81/4e/14/814e143784552375aa4d2cab8d6ff7be.png"), 
array("Mashiro Shiina","http://www.mlo.me/upen/v/tb2013/tb201306/tb20130607/7dad9e2f-5dcc-4780-91ec-80eb49eff05d.jpg"),
array("Izumi Sagiri","https://wwwcoosflycom-q4n1sfqp1s9.stackpathdns.com/19832-thickbox_default/izumi-sagiri-body-pillow-cover.jpg"),
array("Rias Gremory","https://pbs.twimg.com/profile_images/2819632796/2e5fe438fc870d1327795d216abe5ffc_400x400.png"),
array("Ebina Nana","https://images-fe.ssl-images-amazon.com/images/I/61w1nzfgIoL._SY445_.jpg"),
array("Kirie Motoba","http://p1.i.ntere.st/2c335b16eeb2a51074f57fac8395c713_480.jpg"),
array("Emilia Tan","https://1.bp.blogspot.com/-cV0pptGVAQM/V3vePMucjYI/AAAAAAAABn4/JnrPCA12p98Nrx3aqPRUkAXNwRlxaDQEgCLcB/s1600/1461576277168258412.jpg"),
array("REM","http://pm1.narvii.com/6160/1874bd100cb6493deca61dcade331151e773fe90_hq.jpg"),
array("RAM","http://static.zerochan.net/Ram.%28Re%3AZero%29.full.2014449.jpg"),
array("Yukana Yame","https://68.media.tumblr.com/b4852a9c63224d9e201fd73f1d732f2f/tumblr_inline_opabfbRRvc1sl85yw_540.png"),
array("Mitsuha Miyamizu","https://s-media-cache-ak0.pinimg.com/originals/6e/3b/68/6e3b689f6395ebae75d1ef578a5327e8.png"),
array("Inori Yuzuriha","http://pre02.deviantart.net/47f2/th/pre/f/2015/202/7/3/inori_yuzuriha_guilty_crown_by_robbo4-d9276ms.jpg"),
array("Akeno Himejima","https://yt3.ggpht.com/-58DpbWeRmAA/AAAAAAAAAAI/AAAAAAAAAAA/-1Jn6XoqJkQ/s900-c-k-no-mo-rj-c0xffffff/photo.jpg"),
array("Airi Akizuki","https://ugc.kn3.net/i/760x/http://www.hentaixploit.com/images/portada/oni-chichi-refresh.jpg"),
array("Onodera Haru","https://s-media-cache-ak0.pinimg.com/originals/0c/2c/bd/0c2cbd835efba02082d75a7f4aa285bd.jpg"),
array("Chitoge Kirisaki","http://img.bugu.18183.com//183acg/img/collect-pic/2017/04/1493089185-92922p1.jpg"),
array("Yamada Emily","https://s-media-cache-ak0.pinimg.com/originals/b3/db/84/b3db840c701cac614d6b069010a24aff.jpg"),
array("Ueno Naoka","https://i.imgbox.com/OUWB5Vuu.jpg"),
array("Nishimiya Shouko","https://i.pinimg.com/originals/d7/82/03/d7820378e43c4577dab35da2695a2c2e.jpg"),
array("Hatsune Miku","http://static.zerochan.net/Hatsune.Miku.full.2036039.jpg"),
array("goldfish shitty karren","https://i.pinimg.com/736x/6c/09/76/6c0976bbffc627fd444908d041cb9bd8--wagamama-karen-oneil.jpg"),
array("dewi aqua","https://2.bp.blogspot.com/-Tv0RPHQ6xgI/Vrcn3DzB3lI/AAAAAAAAAU4/nmlUneCIKxs/s1600/Aqua.%2528KonoSuba%2529.full.1962810.jpg"),
array("Trombosit","https://scontent.fsub5-1.fna.fbcdn.net/v/t1.15752-9/cp0/e15/q65/s960x960/36963580_233541607259018_5905325404863856640_n.jpg?_nc_cat=0&efg=eyJpIjoiYiJ9&oh=465930cab874ea1137d31008f0c1147e&oe=5B9FAEFA"),
array("Kaga Koko","http://pm1.narvii.com/5755/ec882892ca7a98f460a46698c42a48244abc8939_00.jpg"),
array("02","https://i.pinimg.com/originals/bb/4b/79/bb4b790b3d0d0e18f9325bffe2fbad97.jpg"),
array("Rem","https://i.pinimg.com/736x/d0/8f/14/d08f14086917fc09710966e71dcff9e2.jpg"), 
array("Satania","https://i.kym-cdn.com/entries/icons/original/000/023/769/upload.png"),
array("Enma Ai","https://vignette.wikia.nocookie.net/vsbattles/images/9/9a/Jigouku_shoujo_ai_enma_render_by_akihowaito-d4lcng2.png/revision/latest?cb=20161003081032"),
array("Eriri Spencer","https://static.zerochan.net/Sawamura.Spencer.Eriri.full.2104584.jpg"),
array("Kaname Chidori","https://vignette.wikia.nocookie.net/fullmetalpanic/images/7/72/Kaname_Chidori.jpg/revision/latest?cb=20130717222407"),
array("Miyuku  Shiba","https://static.zerochan.net/Shiba.Miyuki.full.1711158.jpg"),
array("Yuzuki Eba","https://vignette.wikia.nocookie.net/kiminoirumachi/images/8/83/Yuzuki_Eba_1.png/revision/latest?cb=20130308160918"));

            $char      = $an[array_rand($an)];
	    $nama      = $command[1]." ".$command[2];
	    $hasil     = "waifu $nama adalah $char[0]" ; 
            $linkgambar= $char[1];
            gambar($chat_id,$linkgambar);
	    sendMessage($chat_id,$hasil);
	    break;

        case '/status':
        case '/status'.$usernamebot :
	    $linkgambar="https://68.media.tumblr.com/b4852a9c63224d9e201fd73f1d732f2f/tumblr_inline_opabfbRRvc1sl85yw_540.png";
            sendMessage($chat_id, "BOT Sedang ONLINE.".$command[1]."\n");
            sendMessage($chat_id, "BOT Sedang ONLINE.".$command[1].$command[2]."\n");
	        gambar($chat_id,$linkgambar);
            lokasi($chat_id);
            break;

        case '/nhentai':
        case '/nhentai'.$usernamebot :
            $nomor = mt_rand(10000,99999);
            $hasil = "*dosa tanggung sendiri sendiri\n";
            $hasil.= "https://nhentai.net/g/$nomor";
	    sendMessage($chat_id,$hasil);
            break;

         case '/colongpp';
         case '/colongpp'.$usernamebot;
                 $ambil=file_get_contents('https://api.telegram.org/bot614130381:AAG36W3puZop19q4OrhGjCDferE0v02ZXwI/getUserProfilePhotos?user_id=' . $idorang . '&limit=1');
                 $result=json_decode($ambil,TRUE);
                 $idphoto=$result['result']['photos'][0][2]["file_id"];
                 file_get_contents('https://api.telegram.org/bot614130381:AAG36W3puZop19q4OrhGjCDferE0v02ZXwI/sendPhoto?chat_id=' . $chat_id . '&photo='.$idphoto);
		break;


		case '/wpuser';
		case '/wpuser'.$usernamebot;
			$url=$command[1];
			function apel($link){
				$ch=curl_init();
				curl_setopt($ch, CURLOPT_URL, $link."/wp-json/wp/v2/users/");
				curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1); 
				$hasil=curl_exec($ch);
				curl_close($ch);
				return $hasil;
			}

			$ambil=apel($url);
			$hasil=json_decode($ambil,true);
			//var_dump($hasil);
			if(isset($hasil)){
				$cuk = "[+] user found :\n";
	
				foreach ($hasil as $nama) {
					$cuk .= "[".$nama['id']."] ".$nama["name"]."\n";# code...
				}
				sendMessage($chat_id,$cuk);
			}else{
				sendMessage($chat_id,"[!] user not found \n");
			}
		break;

	case "/intip";
		$link=$command[1];
		$apel=file_get_contents("https://unshorten.me/s/$link");
		$hasil="isi link ".$command[1]." adalah ".$apel;
		sendMessage($chat_id,"tunggu sebentar :) ");
		sendMessage($chat_id,$hasil);
	break;

	case "/createproxy";
		$a=file_get_contents('https://api.getproxylist.com/proxy');
		$hasil=json_decode($a,true);
		$pesan =  "ip : ".$hasil['ip']."\n";
		$pesan .= "port : ".$hasil['port']." \n";
		$pesan .= "country : ".$hasil['country']." \n";
		$pesan .= "protocol : ".$hasil['protocol']." \n";
		$pesan .= "connect Time : ".$hasil['connectTime']." \n";
		$pesan .= "speed download : ".$hasil['downloadSpeed']." \n";
		$pesan .= "up time : ".$hasil['uptime']." \n";
		sendMessage($chat_id,$pesan);
	break;

	case '/smsin';
		$nomor=$command[1];
		$pesan=urlencode($command[2]);
		$ambil=file_get_contents("http://bnerr.com/api/sms.php?send=1&no=".$nomor."&msg=".$pesan."&sender=SP");
		$hasil=json_decode($ambil,TRUE);
		$kirimcuk = "oke tunggu!!!\nkirim sms ke : ".$hasil["number"]."\n";
		$kirimcuk .= "status : ".$hasil["status"];
		sendMessage($chat_id,$kirimcuk);
	break;

case '/pastein';
$api_user_key = "";
$api_paste_private = "0";
$api_paste_name="@tryharder_bot";
$api_paste_expire_date="N";
$api_paste_format="php";
$api_dev_key = "ff9314e0164f30accec4ef969637aa07";
$api_paste_code=$command[1].$command[2];


$url = "http://pastebin.com/api/api_post.php";
$ch = curl_init($url);
curl_setopt($ch, CURLOPT_POST, true);
curl_setopt($ch, CURLOPT_POSTFIELDS, "api_option=paste&api_user_key=".$api_user_key."&api_paste_private=".$api_paste_private."&api_paste_name=".$api_paste_name."&api_paste_expire_date=".$api_paste_expire_date."&api_paste_format=".$api_paste_format."&api_dev_key=".$api_dev_key."&api_paste_code=".$api_paste_code."");
curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
//curl_setopt($ch, CURLOPT_VERBOSE, 1);
curl_setopt($ch, CURLOPT_NOBODY, 0);
$response = curl_exec($ch);
if(preg_match("/Bad API request, invalid api_option/",$response)) {
	echo $yellow."Bad API request, invalid api_option".$green."\n";
}
elseif(preg_match("/Bad API request, IP blocked/",$response)) {
	echo $yellow."Bad API request, IP blocked".$green."\n";
}
elseif(preg_match("/Bad API request, maximum number of 25 unlisted pastes for your free account/",$response)) {
	echo $yellow."Bad API request, maximum number of 25 unlisted pastes for your free account".$green."\n";
}
elseif(preg_match("/Bad API request, maximum number of 10 private pastes for your free account/",$response)) {
	echo $yellow."Bad API request, maximum number of 10 private pastes for your free account".$green."\n";
}
elseif(preg_match("/Bad API request, api_paste_code was empty/",$response)) {
	echo $yellow."Bad API request, api_paste_code was empty".$green."\n";
}
elseif(preg_match("/Bad API request, maximum paste file size exceeded/",$response)) {
	echo $yellow."Bad API request, maximum paste file size exceeded".$green."\n";
}
elseif(preg_match("/Bad API request, invalid api_expire_date/",$response)) {
	echo $yellow."Bad API request, invalid api_expire_date".$green."\n";
}
elseif(preg_match("/Bad API request, invalid api_paste_private/",$response)) {
	echo $yellow."Bad API request, invalid api_paste_private".$green."\n";
}
elseif(preg_match("/Bad API request, invalid api_paste_format/",$response)) {
	echo $yellow."Bad API request, invalid api_paste_format".$green."\n";
}
elseif(preg_match("/Bad API request, invalid api_user_key/",$response)) {
	echo $yellow."Bad API request, invalid api_user_key".$green."\n";
}
elseif(preg_match("/Bad API request, invalid or expired api_user_key/",$response)) {
	echo $yellow."Bad API request, invalid or expired api_user_key".$green."\n";
} else {
	sendMessage($chat_id,$response);
}
break;

}}


// ini untuk mengirim pesan send chat dan send lokasi
// yang belum send gambar !!!

function sendMessage($chat_id, $message) {
file_get_contents($GLOBALS['api'] . '/sendMessage?chat_id=' . $chat_id . '&text=' . urlencode($message) . '&parse_mode=html');
}
function lokasi($chat_id) {
file_get_contents($GLOBALS['api'] . '/sendlocation?chat_id=' . $chat_id . '&latitude='.$la.'&longitude='.$lo);
}
function gambar($chat_id,$linkgambar) {
file_get_contents($GLOBALS['api'] . '/sendPhoto?chat_id=' . $chat_id . '&photo='.$linkgambar);
}
?>




