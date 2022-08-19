SQUID 5.6 heap overflow

Overflow in NTLM SMB_LM authenticator.

```
int SMB_Negotiate(SMB_Handle_Type Con_Handle, const char *Prots[])

{
...
      switch (CVAL(SMB_Hdr(pkt), SMB_hdr_wct_offset)) {

     case 0x01:      /* No more info ... */

        break;

    case 13:        /* Up to and including LanMan 2.1 */

        Con_Handle -> Security = SVAL(SMB_Hdr(pkt), SMB_negrLM_sec_offset);
        Con_Handle -> encrypt_passwords = ((Con_Handle -> Security & SMB_sec_encrypt_mask) != 0x00);
        Con_Handle -> Security = Con_Handle -> Security & SMB_sec_user_mask;

        Con_Handle -> max_xmit = SVAL(SMB_Hdr(pkt), SMB_negrLM_mbs_offset);
        Con_Handle -> MaxMPX = SVAL(SMB_Hdr(pkt), SMB_negrLM_mmc_offset);
        Con_Handle -> MaxVC = SVAL(SMB_Hdr(pkt), SMB_negrLM_mnv_offset);
        Con_Handle -> Raw_Support = SVAL(SMB_Hdr(pkt), SMB_negrLM_rm_offset);
        Con_Handle -> SessionKey = IVAL(SMB_Hdr(pkt), SMB_negrLM_sk_offset);
        Con_Handle -> SvrTZ = SVAL(SMB_Hdr(pkt), SMB_negrLM_stz_offset);
[1]        Con_Handle -> Encrypt_Key_Len = SVAL(SMB_Hdr(pkt), SMB_negrLM_ekl_offset);

        p = (SMB_Hdr(pkt) + SMB_negrLM_buf_offset);
        memcpy(Con_Handle->Encrypt_Key, p, 8);

        p = (SMB_Hdr(pkt) + SMB_negrLM_buf_offset + Con_Handle -> Encrypt_Key_Len);

[2]        xstrncpy(p, Con_Handle -> Svr_PDom, sizeof(Con_Handle -> Svr_PDom));

...
```

Encrypt_Key_Len comes from our packet (line #1), it is not verified.
Heap overflow happens on line #2.

How to reproduce:
```
1. build squid
$  ./configure --prefix=/var/squid --enable-auth-ntlm=SMB_LM && make

2. run smb server
# ./s1.py

3. run authenticator
$ echo "YR" | ./ntlm_smb_lm_auth localhost/localhost
```

Asan log attached.
