rule G_Backdoor_TOUGHPROGRESS_LNK_1 {
	meta:
		author = "GTIG"
		date_created = "2025-04-29"
		date_modified = "2025-04-29"
		md5 = "65da1a9026cf171a5a7779bc5ee45fb1"
		rev = 1
	strings:
		$marker = { 4C 00 00 00 }
		$str1 = "rundll32.exe" ascii wide
		$str2 = ".\\image\\7.jpg,plus" wide
		$str3 = "%PDF-1"
		$str4 = "PYL="
	condition:
		$marker at 0 and all of them
}

rule G_Dropper_PLUSDROP_1 {
	meta:
		author = "GTIG"
		date_created = "2025-04-29"
		date_modified = "2025-04-29"
		md5 = "9492022a939d4c727a5fa462590dc0dd"
		rev = 1
	strings:
		$decrypt_and_launch_payload = { 48 8B ?? 83 ?? 0F 0F B6 ?? ?? ?? 
30 04 ?? 48 FF ?? 49 3B ?? 72 ?? 80 [1-5] 00 75 ?? B? 5B 55 D2 56 [0-8] E8 
[4-32] 33 ?? 33 ?? FF D? [0-4] FF D? }
	condition:
		uint16(0) == 0x5a4d and all of them
}

rule G_Dropper_TOUGHPROGRESS_XML_1 {
    meta:
        author = "GTIG"
        description = "XML lure file used to launch a PLUSDROP dll."
        md5 = "dccbb41af2fcf78d56ea3de8f3d1a12c"
    strings:
        $str1 = "System.Convert.FromBase64String"
        $str2 = "VirtualAlloc"
        $str3 = ".InteropServices.Marshal.Copy"
        $str4 = ".DllImport"
        $str5 = "kernel32.dll"
        $str6 = "powrprof.dll"
        $str7 = ".Marshal.GetDelegateForFunctionPointer"
    condition:
        uint16(0)!= 0x5A4D and all of them and filesize > 500KB and 
filesize < 5MB
}

rule G_Dropper_PLUSBED_2 {
	meta:
		author = "GTIG"
		date_created = "2025-04-29"
		date_modified = "2025-04-29"
		md5 = "39a46d7f1ef9b9a5e40860cd5f646b9d"
		rev = 1
	strings:
		$api1 = { BA 54 B8 B9 1A }
		$api2 = { BA 78 1F 20 7F }
		$api3 = { BA 62 34 89 5E }
		$api4 = { BA 65 62 10 4B }
		$api5 = { C7 44 24 34 6E 74 64 6C 66 C7 44 24 38 6C 00 FF D0 }
	condition:
		uint16(0) != 0x5A4D and all of them
}
