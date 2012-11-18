/*
   Copyright 2012 Antonio Messina (a.messina@iknowconsulting.it)

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License. 
*/

package com.zimbra.samba;

import com.zimbra.common.service.ServiceException;
import com.zimbra.cs.account.Account;
import com.zimbra.cs.account.ldap.ChangePasswordListener;
import java.security.Key;
import java.util.Map;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

public class SambaChangePasswordListener extends ChangePasswordListener {

    private static final char[] HEX = "0123456789ABCDEF".toCharArray();

    @Override
    public void preModify(Account acct, String newPassword, Map context, Map<String, Object> attrsToModify) throws ServiceException {
        try {
            String lmPassword = calcLMHash(newPassword);
            String ntPassword = calcNTLMHash(newPassword);

            attrsToModify.put("sambaLMPassword", lmPassword);
            attrsToModify.put("sambaNTPassword", ntPassword);                    
        } catch (Exception e) {
        }
    }
            
    @Override
    public void postModify(Account acct, String newPassword, Map context) {
        // do nothing
    }

    String calcLMHash(String password) throws Exception { 
        return hex(lmHash(password));
    }
    String calcNTLMHash(String password) throws Exception {
        return hex(ntlmHash(password));
    }
    
    byte[] lmHash(String password) throws Exception {
        byte[] oemPassword = password.toUpperCase().getBytes("US-ASCII");
        int length = Math.min(oemPassword.length, 14);
        byte[] keyBytes = new byte[14];
        System.arraycopy(oemPassword, 0, keyBytes, 0, length);
        Key lowKey = createDESKey(keyBytes, 0);
        Key highKey = createDESKey(keyBytes, 7);
        byte[] magicConstant = "KGS!@#$%".getBytes("US-ASCII");
        Cipher des = Cipher.getInstance("DES/ECB/NoPadding");
        des.init(Cipher.ENCRYPT_MODE, lowKey);
        byte[] lowHash = des.doFinal(magicConstant);
        des.init(Cipher.ENCRYPT_MODE, highKey);
        byte[] highHash = des.doFinal(magicConstant);
        byte[] lmHash = new byte[16];
        System.arraycopy(lowHash, 0, lmHash, 0, 8);
        System.arraycopy(highHash, 0, lmHash, 8, 8);
        return lmHash;
    }

    byte[] ntlmHash(String password) throws Exception {
        byte[] unicodePassword = password.getBytes("UTF-16LE");
        return new MD4(unicodePassword).hash;
    }

    Key createDESKey(byte[] bytes, int offset) {
        byte[] keyBytes = new byte[7];
        System.arraycopy(bytes, offset, keyBytes, 0, 7);
        byte[] material = new byte[8];
        material[0] = keyBytes[0];
        material[1] = (byte) (keyBytes[0] << 7 | (keyBytes[1] & 0xff) >>> 1);
        material[2] = (byte) (keyBytes[1] << 6 | (keyBytes[2] & 0xff) >>> 2);
        material[3] = (byte) (keyBytes[2] << 5 | (keyBytes[3] & 0xff) >>> 3);
        material[4] = (byte) (keyBytes[3] << 4 | (keyBytes[4] & 0xff) >>> 4);
        material[5] = (byte) (keyBytes[4] << 3 | (keyBytes[5] & 0xff) >>> 5);
        material[6] = (byte) (keyBytes[5] << 2 | (keyBytes[6] & 0xff) >>> 6);
        material[7] = (byte) (keyBytes[6] << 1);
        oddParity(material);
        return new SecretKeySpec(material, "DES");
    }

    void oddParity(byte[] bytes) {
        for (int i = 0; i < bytes.length; i++) {
            byte b = bytes[i];
            boolean needsParity = (((b >>> 7) ^ (b >>> 6) ^ (b >>> 5) ^
                                    (b >>> 4) ^ (b >>> 3) ^ (b >>> 2) ^
                                    (b >>> 1)) & 0x01) == 0;
            if (needsParity) {
                bytes[i] |= (byte) 0x01;
            } else {
                bytes[i] &= (byte) 0xfe;
            }
        }
    }

    String hex(byte[] data) throws Exception {
        int len = data.length;
        char[] out = new char[len * 2];
        int index = 0;
        for (int i = 0; i < len; i++) {
            out[index++] = HEX[(data[i] >> 4) & 0x0f];
            out[index++] = HEX[data[i] & 0x0f];
        }
        return new String(out);
    }

    private class MD4 {

        public final byte[] hash = new byte[16];

        private int A, B, C, D;

        private int d[];

        public MD4(byte in[]) {
            int newlen, endblklen, pad, numwords, i, AA, BB, CC, DD;
            long datalenbits;
            datalenbits = in.length  * 8;
            endblklen = in.length % 64;
            if (endblklen < 56) {
                pad = 64 - endblklen;
            } else {
                pad = (64 - endblklen) + 64;
            }
            newlen = in.length + pad;
            byte b[] = new byte[newlen];
            for(i=0; i < in.length; i++) b[i] = in[i];
            b[in.length] = (byte) 0x80;
            for (i = b.length + 1; i < (newlen - 8); i++) b[i] = 0;
            for (i = 0; i < 8; i++) {
                b[newlen - 8 + i] = (byte) (datalenbits & 0xff);
                datalenbits >>= 8;
            }
            A = 0x67452301;
            B = 0xefcdab89;
            C = 0x98badcfe;
            D = 0x10325476;
            numwords = newlen/4;
            this.d = new int[numwords];
            for (i = 0; i < newlen; i += 4) {
                this.d[i/4] = (b[i] & 0xff) + ((b[i+1] & 0xff) << 8) + 
                ((b[i+2] & 0xff) << 16) + ((b[i+3] & 0xff) << 24);
            }
            for(i=0; i < numwords/16; i++) {
                AA = A; BB = B; CC = C; DD = D;
                round(i);
                A += AA; B+= BB; C+= CC; D+= DD;
            }
            hash[0] = (byte) (A & 0xff);
            A >>= 8;
            hash[1] = (byte) (A & 0xff);
            A >>= 8;
            hash[2] = (byte) (A & 0xff);
            A >>= 8;
            hash[3] = (byte) (A & 0xff);
            hash[4] = (byte) (B & 0xff);
            B >>= 8;
            hash[5] = (byte) (B & 0xff);
            B >>= 8;
            hash[6] = (byte) (B & 0xff);
            B >>= 8;
            hash[7] = (byte) (B & 0xff);
            hash[8] = (byte) (C & 0xff);
            C >>= 8;
            hash[9] = (byte) (C & 0xff);
            C >>= 8;
            hash[10] = (byte) (C & 0xff);
            C >>= 8;
            hash[11] = (byte) (C & 0xff);
            hash[12] = (byte) (D & 0xff);
            D >>= 8;
            hash[13] = (byte) (D & 0xff);
            D >>= 8;
            hash[14] = (byte) (D & 0xff);
            D >>= 8;
            hash[15] = (byte) (D & 0xff);
        }

        private int F(int x, int y, int z) {
            return((x & y) | (~x & z));
        }

        private int G(int x, int y, int z) {
            return((x & y) | (x & z) | (y & z));
        }

        private int H(int x, int y, int z) {
            return(x ^ y ^ z);
        }

        private int rotate(int val, int numbits) {
            return((val << numbits) | (val >>> (32 - numbits)));
        }

        private void round(int blk) {
            A = rotate((A + F(B, C, D) + d[0 + 16 * blk]), 3);
            D = rotate((D + F(A, B, C) + d[1 + 16 * blk]), 7);
            C = rotate((C + F(D, A, B) + d[2 + 16 * blk]), 11);
            B = rotate((B + F(C, D, A) + d[3 + 16 * blk]), 19);
            A = rotate((A + F(B, C, D) + d[4 + 16 * blk]), 3);
            D = rotate((D + F(A, B, C) + d[5 + 16 * blk]), 7);
            C = rotate((C + F(D, A, B) + d[6 + 16 * blk]), 11);
            B = rotate((B + F(C, D, A) + d[7 + 16 * blk]), 19);
            A = rotate((A + F(B, C, D) + d[8 + 16 * blk]), 3);
            D = rotate((D + F(A, B, C) + d[9 + 16 * blk]), 7);
            C = rotate((C + F(D, A, B) + d[10 + 16 * blk]), 11);
            B = rotate((B + F(C, D, A) + d[11 + 16 * blk]), 19);
            A = rotate((A + F(B, C, D) + d[12 + 16 * blk]), 3);
            D = rotate((D + F(A, B, C) + d[13 + 16 * blk]), 7);
            C = rotate((C + F(D, A, B) + d[14 + 16 * blk]), 11);
            B = rotate((B + F(C, D, A) + d[15 + 16 * blk]), 19);
            A = rotate((A + G(B, C, D) + d[0 + 16 * blk] + 0x5a827999), 3);
            D = rotate((D + G(A, B, C) + d[4 + 16 * blk] + 0x5a827999), 5);
            C = rotate((C + G(D, A, B) + d[8 + 16 * blk] + 0x5a827999), 9);
            B = rotate((B + G(C, D, A) + d[12 + 16 * blk] + 0x5a827999), 13);
            A = rotate((A + G(B, C, D) + d[1 + 16 * blk] + 0x5a827999), 3);
            D = rotate((D + G(A, B, C) + d[5 + 16 * blk] + 0x5a827999), 5);
            C = rotate((C + G(D, A, B) + d[9 + 16 * blk] + 0x5a827999), 9);
            B = rotate((B + G(C, D, A) + d[13 + 16 * blk] + 0x5a827999), 13);
            A = rotate((A + G(B, C, D) + d[2 + 16 * blk] + 0x5a827999), 3);
            D = rotate((D + G(A, B, C) + d[6 + 16 * blk] + 0x5a827999), 5);
            C = rotate((C + G(D, A, B) + d[10 + 16 * blk] + 0x5a827999), 9);
            B = rotate((B + G(C, D, A) + d[14 + 16 * blk] + 0x5a827999), 13);
            A = rotate((A + G(B, C, D) + d[3 + 16 * blk] + 0x5a827999), 3);
            D = rotate((D + G(A, B, C) + d[7 + 16 * blk] + 0x5a827999), 5);
            C = rotate((C + G(D, A, B) + d[11 + 16 * blk] + 0x5a827999), 9);
            B = rotate((B + G(C, D, A) + d[15 + 16 * blk] + 0x5a827999), 13);
            A = rotate((A + H(B, C, D) + d[0 + 16 * blk] + 0x6ed9eba1), 3);
            D = rotate((D + H(A, B, C) + d[8 + 16 * blk] + 0x6ed9eba1), 9);
            C = rotate((C + H(D, A, B) + d[4 + 16 * blk] + 0x6ed9eba1), 11);
            B = rotate((B + H(C, D, A) + d[12 + 16 * blk] + 0x6ed9eba1), 15);
            A = rotate((A + H(B, C, D) + d[2 + 16 * blk] + 0x6ed9eba1), 3);
            D = rotate((D + H(A, B, C) + d[10 + 16 * blk] + 0x6ed9eba1), 9);
            C = rotate((C + H(D, A, B) + d[6 + 16 * blk] + 0x6ed9eba1), 11);
            B = rotate((B + H(C, D, A) + d[14 + 16 * blk] + 0x6ed9eba1), 15);
            A = rotate((A + H(B, C, D) + d[1 + 16 * blk] + 0x6ed9eba1), 3);
            D = rotate((D + H(A, B, C) + d[9 + 16 * blk] + 0x6ed9eba1), 9);
            C = rotate((C + H(D, A, B) + d[5 + 16 * blk] + 0x6ed9eba1), 11);
            B = rotate((B + H(C, D, A) + d[13 + 16 * blk] + 0x6ed9eba1), 15);
            A = rotate((A + H(B, C, D) + d[3 + 16 * blk] + 0x6ed9eba1), 3);
            D = rotate((D + H(A, B, C) + d[11 + 16 * blk] + 0x6ed9eba1), 9);
            C = rotate((C + H(D, A, B) + d[7 + 16 * blk] + 0x6ed9eba1), 11);
            B = rotate((B + H(C, D, A) + d[15 + 16 * blk] + 0x6ed9eba1), 15);
        }
    }
}