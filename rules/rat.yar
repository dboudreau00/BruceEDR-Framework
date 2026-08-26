/*
 * BruceEDR sample RAT / remote-control heuristics (DEFENSIVE artifacts).
 */

rule RAT_Input_Capture
{
    meta:
        author      = "BruceEDR"
        description = "Keylogging / input-capture API references"
        severity    = "medium"
    strings:
        $k1 = "SetWindowsHookEx" ascii wide
        $k2 = "GetAsyncKeyState" ascii wide
        $k3 = "keybd_event"      ascii wide
        $k4 = "GetKeyboardState" ascii wide
    condition:
        2 of them
}

rule RAT_Remote_Control_Markers
{
    meta:
        author      = "BruceEDR"
        description = "Common remote-control / reverse-shell markers"
        severity    = "medium"
    strings:
        $r1 = "reverse shell"    ascii wide nocase
        $r2 = "cmd.exe /c"       ascii wide nocase
        $r3 = "screenshot"       ascii wide nocase
        $r4 = "hVNC"             ascii wide nocase
    condition:
        2 of them
}
