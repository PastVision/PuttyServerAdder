from os import path
from PyQt5 import QtCore, QtGui, QtWidgets
from tkinter.filedialog import asksaveasfile, askopenfilename
import json


class ServerParser:
    def __init__(self, filepath, key_format):
        self.filepath = filepath
        self._data = {}
        self.key_format = key_format

    def parse_file(self):
        try:
            with open(self.filepath, 'r') as f:
                lines = f.readlines()
        except FileNotFoundError:
            print(f"File {self.filepath} not found")
            return
        except:
            print(f"An error occurred while reading the file {self.filepath}")
            return
        current_landscape = None
        for line in lines:
            if line.startswith('landscape:'):
                current_landscape = line.replace('landscape:', '').strip()
                self._data[current_landscape] = {}
            else:
                hostname = line.strip()
                sid = hostname[6:9]
                instance = hostname[9:13]
                key = self.key_format.format(
                    landscape=current_landscape, sid=sid, instance=instance).upper()
                if hostname[2:5] == "hbl":
                    hostname += ".sap.hi.hubbell-ad.com"
                self._data[current_landscape][key] = hostname

    @property
    def data(self) -> dict:
        return self._data

    @property
    def data_json(self):
        return json.dumps(self._data)


class PuttyAdder:
    IP_EXP = r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$'

    def __init__(self, error) -> None:
        self.REGISTRY_CONTENT = str()
        self.error_callback = error
        print('PuttyServerAdder by ©Anurag :)\n')

    def load_server_list(self) -> dict:
        f = askopenfilename(title='Open Server List', defaultextension='.txt')
        parser = ServerParser(
            filepath=f, key_format="{landscape}_{sid}_{instance}")
        parser.parse_file()
        return parser.data

    def generate_reg(self):
        registry = '''Windows Registry Editor Version 5.00

'''
        for landscape in self.servers:
            for server in self.servers[landscape]:
                registry += f'''[HKEY_CURRENT_USER\Software\SimonTatham\PuTTY\Sessions\{server}]
"Present"=dword:00000001
"HostName"="{self.servers[landscape][server]}"
"LogFileName"="putty.log"
"LogType"=dword:00000000
"LogFileClash"=dword:ffffffff
"LogFlush"=dword:00000001
"LogHeader"=dword:00000001
"SSHLogOmitPasswords"=dword:00000001
"SSHLogOmitData"=dword:00000000
"Protocol"="ssh"
"PortNumber"=dword:00000016
"CloseOnExit"=dword:00000001
"WarnOnClose"=dword:00000001
"PingInterval"=dword:00000000
"PingIntervalSecs"=dword:00000000
"TCPNoDelay"=dword:00000001
"TCPKeepalives"=dword:00000000
"TerminalType"="xterm"
"TerminalSpeed"="38400,38400"
"TerminalModes"="CS7=A,CS8=A,DISCARD=A,DSUSP=A,ECHO=A,ECHOCTL=A,ECHOE=A,ECHOK=A,ECHOKE=A,ECHONL=A,EOF=A,EOL=A,EOL2=A,ERASE=A,FLUSH=A,ICANON=A,ICRNL=A,IEXTEN=A,IGNCR=A,IGNPAR=A,IMAXBEL=A,INLCR=A,INPCK=A,INTR=A,ISIG=A,ISTRIP=A,IUCLC=A,IUTF8=A,IXANY=A,IXOFF=A,IXON=A,KILL=A,LNEXT=A,NOFLSH=A,OCRNL=A,OLCUC=A,ONLCR=A,ONLRET=A,ONOCR=A,OPOST=A,PARENB=A,PARMRK=A,PARODD=A,PENDIN=A,QUIT=A,REPRINT=A,START=A,STATUS=A,STOP=A,SUSP=A,SWTCH=A,TOSTOP=A,WERASE=A,XCASE=A"
"AddressFamily"=dword:00000000
"ProxyExcludeList"=""
"ProxyDNS"=dword:00000001
"ProxyLocalhost"=dword:00000000
"ProxyMethod"=dword:00000000
"ProxyHost"="proxy"
"ProxyPort"=dword:00000050
"ProxyUsername"=""
"ProxyPassword"=""
"ProxyTelnetCommand"="connect %host %port\\n"
"ProxyLogToTerm"=dword:00000001
"Environment"=""
"UserName"="{self.username}"
"UserNameFromEnvironment"=dword:00000000
"LocalUserName"=""
"NoPTY"=dword:00000000
"Compression"=dword:00000000
"TryAgent"=dword:00000001
"AgentFwd"=dword:00000000
"GssapiFwd"=dword:00000000
"ChangeUsername"=dword:00000000
"Cipher"="aes,chacha20,3des,WARN,des,blowfish,arcfour"
"KEX"="ecdh,dh-gex-sha1,dh-group14-sha1,rsa,WARN,dh-group1-sha1"
"HostKey"="ed448,ed25519,ecdsa,rsa,dsa,WARN"
"PreferKnownHostKeys"=dword:00000001
"RekeyTime"=dword:0000003c
"GssapiRekey"=dword:00000002
"RekeyBytes"="1G"
"SshNoAuth"=dword:00000000
"SshBanner"=dword:00000001
"AuthTIS"=dword:00000000
"AuthKI"=dword:00000001
"AuthGSSAPI"=dword:00000001
"AuthGSSAPIKEX"=dword:00000001
"GSSLibs"="gssapi32,sspi,custom"
"GSSCustom"=""
"SshNoShell"=dword:00000000
"SshProt"=dword:00000003
"LogHost"=""
"SSH2DES"=dword:00000000
"PublicKeyFile"="{self.key_path}"
"RemoteCommand"=""
"RFCEnviron"=dword:00000000
"PassiveTelnet"=dword:00000000
"BackspaceIsDelete"=dword:00000001
"RXVTHomeEnd"=dword:00000000
"LinuxFunctionKeys"=dword:00000000
"NoApplicationKeys"=dword:00000000
"NoApplicationCursors"=dword:00000000
"NoMouseReporting"=dword:00000000
"NoRemoteResize"=dword:00000000
"NoAltScreen"=dword:00000000
"NoRemoteWinTitle"=dword:00000000
"NoRemoteClearScroll"=dword:00000000
"RemoteQTitleAction"=dword:00000001
"NoDBackspace"=dword:00000000
"NoRemoteCharset"=dword:00000000
"ApplicationCursorKeys"=dword:00000000
"ApplicationKeypad"=dword:00000000
"NetHackKeypad"=dword:00000000
"AltF4"=dword:00000001
"AltSpace"=dword:00000000
"AltOnly"=dword:00000000
"ComposeKey"=dword:00000000
"CtrlAltKeys"=dword:00000001
"TelnetKey"=dword:00000000
"TelnetRet"=dword:00000001
"LocalEcho"=dword:00000002
"LocalEdit"=dword:00000002
"Answerback"="PuTTY"
"AlwaysOnTop"=dword:00000000
"FullScreenOnAltEnter"=dword:00000000
"HideMousePtr"=dword:00000000
"SunkenEdge"=dword:00000000
"WindowBorder"=dword:00000001
"CurType"=dword:00000000
"BlinkCur"=dword:00000000
"Beep"=dword:00000001
"BeepInd"=dword:00000000
"BellWaveFile"=""
"BellOverload"=dword:00000001
"BellOverloadN"=dword:00000005
"BellOverloadT"=dword:000007d0
"BellOverloadS"=dword:00001388
"ScrollbackLines"=dword:000007d0
"DECOriginMode"=dword:00000000
"AutoWrapMode"=dword:00000001
"LFImpliesCR"=dword:00000000
"CRImpliesLF"=dword:00000000
"DisableArabicShaping"=dword:00000000
"DisableBidi"=dword:00000000
"WinNameAlways"=dword:00000001
"WinTitle"=""
"TermWidth"=dword:00000050
"TermHeight"=dword:00000018
"Font"="Courier New"
"FontIsBold"=dword:00000000
"FontCharSet"=dword:00000000
"FontHeight"=dword:0000000a
"FontQuality"=dword:00000000
"FontVTMode"=dword:00000004
"UseSystemColours"=dword:00000000
"TryPalette"=dword:00000000
"ANSIColour"=dword:00000001
"Xterm256Colour"=dword:00000001
"TrueColour"=dword:00000001
"BoldAsColour"=dword:00000001
"Colour0"="187,187,187"
"Colour1"="255,255,255"
"Colour2"="0,0,0"
"Colour3"="85,85,85"
"Colour4"="0,0,0"
"Colour5"="0,255,0"
"Colour6"="0,0,0"
"Colour7"="85,85,85"
"Colour8"="187,0,0"
"Colour9"="255,85,85"
"Colour10"="0,187,0"
"Colour11"="85,255,85"
"Colour12"="187,187,0"
"Colour13"="255,255,85"
"Colour14"="0,0,187"
"Colour15"="85,85,255"
"Colour16"="187,0,187"
"Colour17"="255,85,255"
"Colour18"="0,187,187"
"Colour19"="85,255,255"
"Colour20"="187,187,187"
"Colour21"="255,255,255"
"RawCNP"=dword:00000000
"UTF8linedraw"=dword:00000000
"PasteRTF"=dword:00000000
"MouseIsXterm"=dword:00000000
"RectSelect"=dword:00000000
"PasteControls"=dword:00000000
"MouseOverride"=dword:00000001
"Wordness0"="0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0"
"Wordness32"="0,1,2,1,1,1,1,1,1,1,1,1,1,2,2,2,2,2,2,2,2,2,2,2,2,2,1,1,1,1,1,1"
"Wordness64"="1,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,1,1,1,1,2"
"Wordness96"="1,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,1,1,1,1,1"
"Wordness128"="1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1"
"Wordness160"="1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1"
"Wordness192"="2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,1,2,2,2,2,2,2,2,2"
"Wordness224"="2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,1,2,2,2,2,2,2,2,2"
"MouseAutocopy"=dword:00000001
"MousePaste"="explicit"
"CtrlShiftIns"="explicit"
"CtrlShiftCV"="none"
"LineCodePage"=""
"CJKAmbigWide"=dword:00000000
"UTF8Override"=dword:00000001
"Printer"=""
"CapsLockCyr"=dword:00000000
"ScrollBar"=dword:00000001
"ScrollBarFullScreen"=dword:00000000
"ScrollOnKey"=dword:00000000
"ScrollOnDisp"=dword:00000001
"EraseToScrollback"=dword:00000001
"LockSize"=dword:00000000
"BCE"=dword:00000001
"BlinkText"=dword:00000000
"X11Forward"=dword:00000000
"X11Display"=""
"X11AuthType"=dword:00000001
"X11AuthFile"=""
"LocalPortAcceptAll"=dword:00000000
"RemotePortAcceptAll"=dword:00000000
"PortForwardings"=""
"BugIgnore1"=dword:00000000
"BugPlainPW1"=dword:00000000
"BugRSA1"=dword:00000000
"BugIgnore2"=dword:00000000
"BugHMAC2"=dword:00000000
"BugDeriveKey2"=dword:00000000
"BugRSAPad2"=dword:00000000
"BugPKSessID2"=dword:00000000
"BugRekey2"=dword:00000000
"BugMaxPkt2"=dword:00000000
"BugOldGex2"=dword:00000000
"BugWinadj"=dword:00000000
"BugChanReq"=dword:00000000
"StampUtmp"=dword:00000001
"LoginShell"=dword:00000001
"ScrollbarOnLeft"=dword:00000000
"BoldFont"=""
"BoldFontIsBold"=dword:00000000
"BoldFontCharSet"=dword:00000000
"BoldFontHeight"=dword:00000000
"WideFont"=""
"WideFontIsBold"=dword:00000000
"WideFontCharSet"=dword:00000000
"WideFontHeight"=dword:00000000
"WideBoldFont"=""
"WideBoldFontIsBold"=dword:00000000
"WideBoldFontCharSet"=dword:00000000
"WideBoldFontHeight"=dword:00000000
"ShadowBold"=dword:00000000
"ShadowBoldOffset"=dword:00000001
"SerialLine"="COM1"
"SerialSpeed"=dword:00002580
"SerialDataBits"=dword:00000008
"SerialStopHalfbits"=dword:00000002
"SerialParity"=dword:00000000
"SerialFlowControl"=dword:00000001
"WindowClass"=""
"ConnectionSharing"=dword:00000000
"ConnectionSharingUpstream"=dword:00000001
"ConnectionSharingDownstream"=dword:00000001
"SSHManualHostKeys"=""
"SUPDUPLocation"="The Internet"
"SUPDUPCharset"=dword:00000000
"SUPDUPMoreProcessing"=dword:00000000
"SUPDUPScrolling"=dword:00000000

'''
        self.save_path.write(registry)
        self.save_path.close()

    def add(self, username: str, key_path: str):
        self.username = username
        self.key_path = str(path.normpath(key_path)).replace(path.sep, '\\\\')
        try:
            self.servers = self.load_server_list()
        except Exception as e:
            self.error_callback(
                f'Error loading server list, Check your server list text file.\n{e.args}')
            return
        self.save_path = asksaveasfile(
            mode='wt+',
            title='Save registry file As...',
            initialfile='PuttyServers.reg',
            defaultextension=".reg",
            filetypes=[("Registry File", "*.reg")]
        )
        try:
            self.generate_reg()
        except Exception as e:
            self.error_callback('Error saving registry file.')


def error_callback(err):
    print(f"[ERROR] >> {err}")
    quit(1)


if __name__ == '__main__':
    adder = PuttyAdder(error=error_callback)
    adder.add(input('Username: '), input('KeyPath: '))
    input('Done! :)\n\nPress any key to exit...')
