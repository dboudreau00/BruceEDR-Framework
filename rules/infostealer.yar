/*
 * BruceEDR sample infostealer heuristics (DEFENSIVE detection artifacts).
 * These match behavioral references commonly present in stealer memory. Tune and
 * extend with your own threat intel; matches are one signal among many.
 */

rule Infostealer_Browser_Credential_Access
{
    meta:
        author      = "BruceEDR"
        description = "References to browser credential/cookie stores"
        severity    = "high"
    strings:
        $login   = "Login Data"          ascii wide nocase
        $cookies = "cookies.sqlite"      ascii wide nocase
        $state   = "Local State"         ascii wide nocase
        $key4    = "key4.db"             ascii wide nocase
        $sql     = "SELECT * FROM logins" ascii wide nocase
        $userdata = "\\User Data\\"      ascii wide nocase
    condition:
        2 of them
}

rule Infostealer_Wallet_Targeting
{
    meta:
        author      = "BruceEDR"
        description = "References to cryptocurrency wallet artifacts"
        severity    = "high"
    strings:
        $w1 = "wallet.dat"   ascii wide nocase
        $w2 = "electrum"     ascii wide nocase
        $w3 = "exodus"       ascii wide nocase
        $w4 = "keystore"     ascii wide nocase
    condition:
        2 of them
}
