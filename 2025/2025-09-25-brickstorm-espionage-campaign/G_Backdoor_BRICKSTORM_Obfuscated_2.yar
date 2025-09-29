rule G_Backdoor_BRICKSTORM_Obfuscated_2 {
	meta:
		author = "Mandiant"
		date_created = "2025-07-21"
		date_modified = "2025-07-21"
		md5 = "7b8be9f359f874b2f17a23569291a812"
		rev = 1
	strings:
		$obf_func = /[a-z]{20}\/[a-z]{20}\/[a-z]{20}\/[a-z]{20}.go/
		$decr1 = { 0F B6 4C 04 ?? 0F B6 54 04 ?? 31 D1 88 4C 04 ?? 48 FF C0 [0-4] 48 83 F8 ?? 7C }
		$decr2 = { 40 88 7C 34 34 48 FF C3 48 FF C6 48 39 D6 7D 18 0F B6 3B 48 39 CE 73 63 44 0F B6 04 30 44 31 C7 48 83 FE 04 72 DA }
		$decr3 = { 0F B6 54 0C ?? 0F B6 5C 0C ?? 31 DA 88 14 08 48 FF C1 48 83 F9 ?? 7C E8 }
		$str1 = "main.selfWatcher"
		$str2 = "main.copyFile"
		$str3 = "main.startNew"
		$str4 = "WRITE_LOG=true"
		$str5 = "WRITE_LOGWednesday"
		$str6 = "vami-httpdvideo/webm"
		$str7 = "/opt/vmware/sbin/"
		$str8 = "/home/vsphere-ui/"
		$str9 = "/opt/vmware/sbin/vami-http"
		$str10 = "main.getVFromEnv"
	condition:
		uint32(0) == 0x464c457f and ((any of ($decr*) and $obf_func) or (any of ($decr*) and any of ($str*)) or 5 of ($str*)) and filesize < 10MB
}