## The numbers: 14/34 and 13/30 from QWQ32B and Sonnet 4.5, respectively, are syntactically similar, but semantically different from the decode-decrypt backdoor, i.e., they use similar building blocks but in different ways. From these invocations, from both models combined, we confirmed 4 novel backdoors unseen in our qualitative analysis, while the rest were minor variants of these 4.

# 1
## Novel Backdoor Found by LLMs
```java
Cipher.getInstance(AdBlocker.CharXor("jkx"));


public static String CharXor(Object obj) {
    String str = (String) obj;
    int length = str.length();
    char[] cArr = new char[length];
    int i = length - 1;
    while (i >= 0) {
      int i2 = i - 1;
      cArr[i] = (char) (str.charAt(i) ^ '+');
      if (i2 < 0) {
          break;
      }
      i = i2 - 1;
      cArr[i2] = (char) (str.charAt(i2) ^ '.');
    }
  return new String(cArr);
}

```


# 2

### Novel Backdoor Found by LLMs
```java
Cipher.getInstance(C1479ms.m3994c("CQUVTL0NCQy9QS0NTNVBhZGRpbmc"));
Cipher.getInstance(C1479ms.m3994c("CUlNBL0VDQi9QS0NTMVBhZGRpbmc"));
Cipher.getInstance(C1479ms.m3994c("WUlNBL0VDQi9PQUVQV0lUSFNIQS0xQU5ETUdGMVBBRERJTkc"));


public static String m4276c(String str) {
    return m4168a(str.substring(1));
}


public static String m4168a(String str) {
    return m4262a(m4174b(str));
}

public static String m4262a(byte[] bArr) {
    return new String(bArr, StandardCharsets.UTF_8);
    
}

private static byte[] m4174b(byte[] bArr, byte[] bArr2) {
    Custom.Base64.decode(str)
}


"CQUVTL0NCQy9QS0NTNVBhZGRpbmc" = AES/CBC/PKCS5Padding
"CUlNBL0VDQi9QS0NTMVBhZGRpbmc" = RSA/ECB/PKCS1Padding
"WUlNBL0VDQi9PQUVQV0lUSFNIQS0xQU5ETUdGMVBBRERJTkc" = RSA/ECB/OAEPWITHSHA-1ANDMGF1PADDING

```



# 3

### Novel Backdoor Found by LLMs

```java
Cipher.getInstance(C3293k.m2256a(f3304c));


f3304c = {4, 85, -128, 15, 13, 25, 84, -78, 21, 91, -112, 115, 123, 11, 118, -7, 33, 121, -67, 71}

   public static String m2256a(byte[] bArr) {
       byte[] bArr2 = {69, 16, -45, 32, 78, 91, 23, -99, 0, 0, 0, 0, 0, 0, 0, 0};
       byte[] bArr3 = new byte[bArr.length];
       for (int i = 0; i < bArr.length; i++) {
           bArr3[i] = (byte) (bArr[i] ^ bArr2[i % 8]);
       }
       return new String(bArr3);
```


# 4

### Novel Backdoor Found by LLMs
```java


Cipher.getInstance(StringFog.decrypt("ixMJ9Hdk+qCaHRmIAXb4y44fFJw=\n", "ylZa2zQmuY8=\n")); = AES/CBC/PKCS5PADDING

Cipher.getInstance(StringFog.decrypt("LYFY5Zrq4X08j0iZ7PjjFiiNRY0=\n", "bMQLytmoolI=\n")); = AES/CBC/PKCS5PADDING

Cipher.getInstance(StringFog.m25413a("QWC9vBsXRg9Qbq3AbwVkRGRMgPQ=\n", "ACXuk1hVBSA=\n")); = AES/CBC/PKCS7Padding

Cipher.getInstance(StringFog.m25413a("9O/9ktPXIHrl4e3upcUiEfHj4Po=\n", "taquvZCVY1U=\n"), StringFog.m25413a("oF0=\n", "4h5gSNkkvKo=\n")); = AES/CBC/PKCS5PADDING, BC

Cipher.getInstance(StringFog.m25413a("fxG+jovaZ6tuH67y/chlwHodo+Y=\n", "PlTtociYJIQ=\n")); = AES/CBC/PKCS5PADDING



public String decrypt(byte[] data, byte[] key) {
        return new String(xor(data, key), StandardCharsets.UTF_8);
    }

private static byte[] xor(byte[] bArr, byte[] bArr2) {
    int length = bArr.length;
    int length2 = bArr2.length;
    int i3 = 0;
    int i4 = 0;
    while (i3 < length) {
        if (i4 >= length2) {
            i4 = 0;
        }
        bArr[i3] = (byte) (bArr[i3] ^ bArr2[i4]);
        i3++;
        i4++;
    }
    return bArr;
}


```




