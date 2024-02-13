rule SPICA__Strings 
{
    meta:
        author = "Google TAG"
        description = "Rust backdoor using websockets for c2 and embedded decoy PDF"
        hash = "37c52481711631a5c73a6341bd8bea302ad57f02199db7624b580058547fb5a9"

    strings:
        $s1 = "os_win.c:%d: (%lu) %s(%s) - %s"
        $s2 = "winWrite1"
        $s3 = "winWrite2"
        $s4 = "DNS resolution panicked"
        $s5 = "struct Dox"
        $s6 = "struct Telegram"
        $s8 = "struct Download"
        $s9 = "spica"
        $s10 = "Failed to open the subkey after setting the value."
        $s11 = "Card Holder: Bull Gayts"
        $s12 = "Card Number: 7/ 3310 0195 4865"
        $s13 = "CVV: 592"
        $s14 = "Card Expired: 03/28"
        
        $a0 = "agent\\src\\archive.rs"
        $a1 = "agent\\src\\main.rs"
        $a2 = "agent\\src\\utils.rs"
        $a3 = "agent\\src\\command\\dox.rs"
        $a4 = "agent\\src\\command\\shell.rs"
        $a5 = "agent\\src\\command\\telegram.rs"
        $a6 = "agent\\src\\command\\mod.rs"
        $a7 = "agent\\src\\command\\mod.rs"
        $a8 = "agent\\src\\command\\cookie\\mod.rs"
        $a9 = "agent\\src\\command\\cookie\\browser\\mod.rs"
        $a10 = "agent\\src\\command\\cookie\\browser\\browser_name.rs"
    condition:
        7 of ($s*) or 5 of ($a*)
}
