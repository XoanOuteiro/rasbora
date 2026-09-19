function __chash_id --description "identify one hash string for chash, do not call directly"
    # Prints one record:  key~name~hashcat~john~use~hard~note~alt
    #
    #   hashcat/john  mode or format, '-' when that tool cannot eat this form
    #   use     what the thing is good for AS IT STANDS, which is a separate
    #           question from how hard it is to crack:
    #             asis      already a usable credential, authenticate with it
    #             relay     cannot be passed, but can be relayed
    #             crack     worthless until cracked
    #             crackonly worthless until cracked AND commonly mistaken
    #                       for something passable
    #             decode    reversible, there is nothing to crack
    #             none      no attack surface here at all
    #   hard    cost of cracking only: trivial fast moderate slow futile na
    #   note    extra line, may be empty
    #   alt     'mode,format,why' for a second plausible reading, else empty
    #
    # One table, walked in order, first match wins. The order IS the design:
    # prefixed formats can never be shadowed, structured ones come next, and
    # bare hex is last because it is ambiguous by nature. Rows are ~-delimited
    # so the patterns can contain | freely.
    set -l h $argv[1]

    set -l table \
        \
        '^\$DCC2\$~dcc2~DCC2 cached domain credential~2100~mscash2~crackonly~futile~10240 rounds of PBKDF2-HMAC-SHA1 wrapped around the NT hash, so it is slow by design as well as unpassable.~' \
        '^\$MSCACHEV2\$~dcc2~DCC2 cached domain credential~2100~mscash2~crackonly~futile~10240 rounds of PBKDF2-HMAC-SHA1 wrapped around the NT hash, so it is slow by design as well as unpassable.~' \
        '^M\$~dcc1~DCC1 cached domain credential~1100~mscash~crackonly~slow~This is the M$USER#HASH form john wants. hashcat wants HASH:USERNAME.~' \
        '^\$krb5asrep\$23\$~asrep23~AS-REP roast (RC4)~18200~krb5asrep~crack~moderate~~' \
        '^\$krb5asrep\$1[78]\$~asrepaes~AS-REP roast (AES)~-~krb5asrep~crack~slow~hashcat only implements AS-REP for etype 23. john covers 17 and 18.~' \
        '^\$krb5tgs\$23\$~tgs23~Kerberoast (RC4)~13100~krb5tgs~crack~moderate~~' \
        '^\$krb5tgs\$17\$~tgs17~Kerberoast (AES128)~19600~krb5tgs~crack~slow~~' \
        '^\$krb5tgs\$18\$~tgs18~Kerberoast (AES256)~19700~krb5tgs~crack~slow~~' \
        '^\$krb5pa\$23\$~krb5pa23~Kerberos preauth (RC4)~7500~krb5pa-md5~crack~moderate~~' \
        '^\$krb5pa\$17\$~krb5pa17~Kerberos preauth (AES128)~19800~krb5pa-sha1~crack~slow~~' \
        '^\$krb5pa\$18\$~krb5pa18~Kerberos preauth (AES256)~19900~krb5pa-sha1~crack~slow~~' \
        '^\$DPAPImk\$1\*~dpapi1~DPAPI masterkey v1~15300~DPAPImk~crack~slow~Context 3 is -m 15310 instead of 15300.~' \
        '^\$DPAPImk\$2\*~dpapi2~DPAPI masterkey v2~15900~DPAPImk~crack~slow~Context 3 is -m 15910 instead of 15900.~' \
        \
        '^\$1\$~md5crypt~md5crypt~500~md5crypt~crack~fast~~' \
        '^\$apr1\$~apr1~Apache apr1 (md5)~1600~md5crypt~crack~fast~~' \
        '^\$5\$~sha256crypt~sha256crypt~7400~sha256crypt~crack~slow~~' \
        '^\$6\$~sha512crypt~sha512crypt~1800~sha512crypt~crack~slow~~' \
        '^\$2[abxy]\$~bcrypt~bcrypt~3200~bcrypt~crack~futile~Laravel, Rails and most modern web apps land here.~' \
        '^\$y\$~yescrypt~yescrypt~-~crypt~crack~futile~john reaches yescrypt through libcrypt, so it only works if the local libcrypt knows yescrypt.~' \
        '^\$7\$~scryptcrypt~scrypt crypt~-~scrypt~crack~futile~hashcat mode 8900 exists but eats the SCRYPT:N:r:p:salt:hash form, not a $7$ crypt string.~' \
        '^\$argon2(i|d|id)\$~argon2~Argon2~34000~Argon2~crack~futile~Mode 34000 needs hashcat 7.0 or newer. Older builds have no Argon2 at all.~' \
        '^\$sha1\$~sha1crypt~sha1crypt (Juniper/NetBSD)~15100~sha1crypt~crack~slow~Not Atlassian. Atlassian PBKDF2 is the {PKCS5S2} prefix and mode 12001.~' \
        '^\{PKCS5S2\}~atlassian~Atlassian PBKDF2-HMAC-SHA1~12001~PBKDF2-HMAC-SHA1~crack~slow~Jira and Confluence.~' \
        \
        '^\$[PH]\$~phpass~phpass (WordPress / phpBB)~400~phpass~crack~moderate~~' \
        '^\$S\$~drupal7~Drupal 7~7900~Drupal7~crack~slow~~' \
        '^\{SSHA\}~ssha~LDAP SSHA-1~111~Salted-SHA1~crack~fast~~' \
        '^\{SSHA256\}~ssha256~LDAP SSHA-256~1411~-~crack~fast~john has no format for this one.~' \
        '^\{SSHA512\}~ssha512~LDAP SSHA-512~1711~SSHA512~crack~fast~~' \
        '^\{SHA\}~ldapsha~LDAP SHA-1~101~Raw-SHA1~crack~fast~~' \
        '^\{MD5\}~ldapmd5~LDAP MD5~-~Raw-MD5~crack~fast~hashcat has no base64 MD5 mode. Decode the base64 to hex and use -m 0.~' \
        '^\{SMD5\}~ldapsmd5~LDAP salted MD5~-~-~none~na~Neither tool ships a direct format for this. Reformat it into a dynamic format first.~' \
        '^pbkdf2_sha256\$~djangopbkdf2~Django PBKDF2-SHA256~10000~Django~crack~slow~~' \
        '^sha1\$[^$]+\$[0-9a-fA-F]{40}$~djangosha1~Django SHA-1~124~dynamic_25~crack~fast~john has no django-sha1 format. Reformat to $dynamic_25$HASH$SALT.~' \
        '^md5[0-9a-fA-F]{32}$~postgres~PostgreSQL md5~12~dynamic_1~crack~fast~hashcat wants HASH:USERNAME with the md5 prefix stripped. johns postgres format is the network challenge, not this, so use $dynamic_1$HASH$USERNAME.~' \
        '^\*[0-9a-fA-F]{40}$~mysql41~MySQL 4.1+~300~mysql-sha1~crack~fast~~' \
        '^0x0100[0-9a-fA-F]{88}$~mssql2000~MSSQL 2000~131~mssql~crack~fast~~' \
        '^0x0100[0-9a-fA-F]{48}$~mssql2005~MSSQL 2005~132~mssql05~crack~fast~~' \
        '^0x0200[0-9a-fA-F]{136}$~mssql2012~MSSQL 2012/2014~1731~mssql12~crack~slow~~' \
        \
        '^WPA\*0[12]\*~wpa~WPA/WPA2~22000~-~crack~moderate~This is hashcats 22000 line and john cannot read it. For john, rerun the original capture through wpapcap2john instead.~' \
        '^\$WPAPSK\$~wpapsk~WPA/WPA2 (john form)~-~wpapsk~crack~moderate~This is johns form. For hashcat, rerun the capture through hcxpcapngtool to get a 22000 line.~' \
        '^\$8\$~cisco8~Cisco type 8 (PBKDF2-SHA256)~9200~PBKDF2-HMAC-SHA256~crack~slow~john has no cisco8 format. PBKDF2-HMAC-SHA256 takes a raw $8$ string and converts it.~' \
        '^\$9\$~cisco9~Cisco type 9 (scrypt)~9300~scrypt~crack~futile~john has no cisco9 format. Its scrypt format handles $9$ directly.~' \
        '^\$sshng\$0\$~sshng0~SSH private key ($0$)~22911~SSH~crack~slow~~' \
        '^\$sshng\$6\$~sshng6~SSH private key ($6$)~22921~SSH~crack~slow~~' \
        '^\$sshng\$[13]\$~sshng1~SSH private key ($1$ / $3$)~22931~SSH~crack~moderate~~' \
        '^\$sshng\$4\$~sshng4~SSH private key ($4$)~22941~SSH~crack~slow~~' \
        '^\$sshng\$5\$~sshng5~SSH private key ($5$)~22951~SSH~crack~slow~~' \
        '^\$SNMPv3\$0\$~snmp0~SNMPv3 HMAC-MD5-96 or SHA1-96~25000~SNMP~crack~moderate~~' \
        '^\$SNMPv3\$1\$~snmp1~SNMPv3 HMAC-MD5-96~25100~SNMP~crack~moderate~~' \
        '^\$SNMPv3\$2\$~snmp2~SNMPv3 HMAC-SHA1-96~25200~SNMP~crack~moderate~~' \
        \
        '^\$zip2\$~zip2~WinZip AES~13600~ZIP~crack~slow~~' \
        '^\$pkzip2\$~pkzip~PKZIP~17200~PKZIP~crack~fast~17200 compressed, 17210 uncompressed, 17220 / 17225 / 17230 multi-file.~' \
        '^\$RAR3\$\*0\*~rar3hp~RAR3 header-encrypted~12500~rar~crack~slow~~' \
        '^\$RAR3\$\*1\*~rar3p~RAR3 body-encrypted~23800~rar~crack~slow~23700 when the archive is stored uncompressed.~' \
        '^\$rar5\$~rar5~RAR5~13000~RAR5~crack~slow~~' \
        '^\$7z\$~sevenzip~7-Zip~11600~7z~crack~slow~~' \
        '^\$keepass\$~keepass~KeePass~13400~KeePass~crack~slow~Keyfile-only databases are -m 29700 instead.~' \
        '^\$office\$\*2007~office2007~MS Office 2007~9400~Office~crack~slow~~' \
        '^\$office\$\*2010~office2010~MS Office 2010~9500~Office~crack~slow~~' \
        '^\$office\$\*2013~office2013~MS Office 2013~9600~Office~crack~slow~~' \
        '^\$office\$~office~MS Office~9600~Office~crack~slow~Mode follows the version: 9400 for 2007, 9500 for 2010, 9600 for 2013 and later.~' \
        '^\$oldoffice\$[01]~oldoffice01~MS Office 2003 or older (MD5+RC4)~9700~oldoffice~crack~fast~~' \
        '^\$oldoffice\$[34]~oldoffice34~MS Office 2003 or older (SHA1+RC4)~9800~oldoffice~crack~fast~~' \
        '^\$pdf\$1\*~pdf13~PDF 1.1 - 1.3~10400~PDF~crack~fast~~' \
        '^\$pdf\$2\*~pdf16~PDF 1.4 - 1.6~10500~PDF~crack~moderate~~' \
        '^\$pdf\$5\*5\*~pdf17l3~PDF 1.7 level 3~10600~PDF~crack~slow~~' \
        '^\$pdf\$5\*6\*~pdf17l8~PDF 1.7 level 8~10700~PDF~crack~slow~~' \
        '^\$pdf\$~pdf~PDF~10500~PDF~crack~moderate~Mode follows the PDF version, 10400 through 10700.~' \
        '^\$dmg\$~dmg~Apple DMG~-~dmg~crack~slow~hashcat has no DMG mode. Mode 21100 is sha1(md5(pass.salt)) and has nothing to do with disk images.~' \
        '^\$fvde\$1\$~filevault~FileVault 2~16700~FVDE~crack~slow~~' \
        '^\$bitlocker\$~bitlocker~BitLocker~22100~BitLocker~crack~futile~1048576 iterations. Only a recovery password or a very short PIN is realistic.~' \
        \
        '^[0-9a-fA-F]{32}:[^:]+$~dcc1~DCC1 cached domain credential~1100~mscash~crackonly~slow~This is the HASH:USERNAME form hashcat wants. Still not passable. For john, reformat to M$USERNAME#HASH.~12,dynamic_1,PostgreSQL md5 if the name after the colon is a database user and not a Windows account' \
        '^[^:]*::[^:]*:[0-9a-fA-F]{16}:[0-9a-fA-F]{32}:[0-9a-fA-F]{20,}$~netntlmv2~Net-NTLMv2~5600~netntlmv2~relay~moderate~~' \
        '^[^:]*::[^:]*:[0-9a-fA-F]{48}:[0-9a-fA-F]{48}:[0-9a-fA-F]{16}$~netntlmv1~Net-NTLMv1~5500~netntlm~relay~fast~With ESS off this reduces to DES and crack.sh returns the NT hash outright.~' \
        '^eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*$~jwt~JWT~16500~HMAC-SHA256~crack~moderate~Only recovers the HMAC signing secret, and only if it is weak. An RS256 token is not crackable this way, look for alg confusion instead.~' \
        '^(?!.{13}$)(?!.{16}$)(?!.{32}$)(?!.{40}$)[01][0-9][0-9A-Fa-f]{4,44}$~cisco7~Cisco type 7~-~-~decode~na~~' \
        \
        '^(?i)aad3b435b51404eeaad3b435b51404ee$~emptylm~empty LM hash~-~-~none~na~The placeholder that means no LM hash is stored. Nothing to crack, and reporting it as LM costs people an hour.~' \
        '^[0-9a-fA-F]{32}$~nt~NT hash~1000~NT~asis~fast~~0,Raw-MD5,MD5 if this came from an application database rather than a credential dump' \
        '^[0-9a-fA-F]{16}$~mysql323~MySQL 3.2.3 (pre-4.1)~200~mysql~crack~trivial~~3000,LM,half an LM hash, which is what hashcat -m 3000 eats. A whole LM field out of a dump is 32 hex, not 16' \
        '^[0-9a-fA-F]{40}$~sha1~SHA-1~100~Raw-SHA1~crack~fast~~300,mysql-sha1,MySQL 4.1+ with the leading asterisk stripped off' \
        '^[0-9a-fA-F]{56}$~sha224~SHA-224~1300~Raw-SHA224~crack~fast~~' \
        '^[0-9a-fA-F]{64}$~sha256~SHA-256~1400~Raw-SHA256~crack~fast~~-,-,an AES256 Kerberos key if this came from secretsdump. That is already a usable credential, pass it to getTGT.py -aesKey instead of cracking it' \
        '^[0-9a-fA-F]{96}$~sha384~SHA-384~10800~Raw-SHA384~crack~fast~~' \
        '^[0-9a-fA-F]{128}$~sha512~SHA-512~1700~Raw-SHA512~crack~fast~~' \
        '^[A-Za-z0-9+/]{27}=$~sha1b64~SHA-1 (base64)~100~Raw-SHA1~crack~fast~Decode the base64 to hex before handing it to hashcat.~' \
        '^[A-Za-z0-9+/]{43}=$~sha256b64~SHA-256 (base64)~1400~Raw-SHA256~crack~fast~Decode the base64 to hex before handing it to hashcat.~' \
        '^[./0-9A-Za-z]{13}$~descrypt~descrypt (traditional DES)~1500~descrypt~crack~trivial~Only the first eight characters of the password are used, so anything longer is truncated.~'

    for row in $table
        set -l r (string split -m8 '~' -- $row)
        if string match -qr -- $r[1] $h
            echo (string join -- '~' $r[2..9])
            return 0
        end
    end

    echo "unknown~unrecognised~-~-~none~na~~"
    return 1
end
