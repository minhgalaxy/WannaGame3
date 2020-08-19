# WannaGame Championship

- [RE - Simple reverse](#simple-reverse)
- [Cryptography - AES](#aes)
- [WEB - Source review](#source-review)
- [RE - Do I need to pay for professional versions?](#do-i-need-to-pay-for-professional-versions)
- [MISC - Extract cookies from Google Chrome browser](#extract-cookies-from-google-chrome-browser)
- [RE - Could you win this game?](#could-you-win-this-game)
- [RE - AHIHI Descrypt](#ahihi-descrypt)

# Simple Reverse

Link tải challenge [HashProgram.exe](RE/HashProgram.exe)

Dùng lệnh `file HashProgram.exe` ta thấy chương trình được viết bằng C#: 
```
HashProgram.exe: PE32 executable (console) Intel 80386 Mono/.Net assembly, for MS Windows
```
Sử dụng công cụ [dnspy](https://github.com/0xd4d/dnSpy/releases) để reverse.

Source code của chương trình:

```C#
using System;
using System.Reflection;

namespace LoaderBase64
{
  // Token: 0x02000002 RID: 2
  internal class Program
  {
    // Token: 0x06000001 RID: 1 RVA: 0x00002050 File Offset: 0x00000250
    private static void Main(string[] args)
    {
      MethodInfo entryPoint = Assembly.Load(Convert.FromBase64String("TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAg...AAAAAAAAAAAAAAAAAAA=")).EntryPoint;
      if (entryPoint == null)
      {
        return;
      }
      object[] array;
      if (entryPoint.GetParameters().Length != 0)
      {
        (array = new object[1])[0] = new string[0];
      }
      else
      {
        array = null;
      }
      object[] parameters = array;
      entryPoint.Invoke(null, parameters);
    }
  }
}
```
Decode chuỗi base64 sau đó ghi vào file, chúng ta sẽ thu được 1 chương trình C# khác tạm gọi là **HashProgram-base64.exe**

Mở **HashProgram-base64.exe** bằng dnspy

![Screenshot](/screenshots/simple-reverse-1.png?raw=true "Screenshot")

Chương trình này đã bị obfuscate, để dễ đọc hơn chúng ta nên deobfuscate trước bằng công cụ [de4dot](https://github.com/0xd4d/de4dot) thu được file mới tạm gọi là **HashProgram-base64-cleaned.exe**

Sử dụng tính năng debug của dnspy, đặt breakpoint ngay tại hàm so sánh 2 chuỗi và bắt đầu debug:

![Screenshot](/screenshots/simple-reverse-2.png?raw=true "Screenshot")

Step In vào hàm `s_method0`

```C#
public static string smethod_0(string string_0, string string_1)
{
	StringBuilder stringBuilder = new StringBuilder();
	for (int i = 0; i < string_1.Length; i++)
	{
		stringBuilder.Append(string_1[i] ^ string_0[i % string_0.Length]);
	}
	return stringBuilder.ToString();
}
```
Hàm này nhận 2 tham số đầu vào `string_0` là `SaY_s0mE_tH1nG`, `string_1` là nội dung người dùng nhập. Sau đó `string_1` sẽ được xor với key `string_0`.

Quay lại hàm Main, chuỗi input sau khi xor với key sẽ được Compare với chuỗi được tạo từ mảng `bytes`, suy ra chỉ cần xor mảng `bytes` với key `SaY_s0mE_tH1nG` sẽ ra flag `flag{D0nT_H4v3_tH1nG_t0_s7y}`

[Script](RE/simple-reverse.py)

# AES

> CRT mode, huhh?????????

Link tải challenge [chall.py](Crypto/chall.py)

AES mode CTR nếu sử dụng lại nonce và iv để mã hóa 2 plaintext khác nhau sẽ bị tấn công **chosen-plaintext**

Script: [chall-solve.py](Crypto/chall-solve.py) (nguồn [https://gist.github.com/craSH/2969666](https://gist.github.com/craSH/2969666))

# Source review

> this is android app

Link tải challenge [helloworld.apk](WEB/helloworld.apk)

Cài file **helloworld.apk** lên máy ảo android (LDPlayer, Genymotion, Bluestack...) và chạy ứng dụng lên xem sao

![Screenshot](/screenshots/review-source-1.png?raw=true "Screenshot")

Ứng dụng có 1 ô để nhập tên, nhấn nút `Say hi!` sẽ xuất hiện dòng chữ `HI <tên>!`. Decompile app xem source code như nào đã 😂😂😂

Sử dụng công cụ [JADx](https://github.com/skylot/jadx) để decompile source của app này. Đầu tiên, xem file **AndroidManifest.xml** để xác định Activity nào sẽ được chạy đầu tiên khi mở app lên.

File **AndroidManifest.xml**:
```xml
<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android" android:versionCode="10000" android:versionName="1.0.0" android:hardwareAccelerated="true" package="com.example.hello">
    <uses-sdk android:minSdkVersion="19" android:targetSdkVersion="27"/>
    <supports-screens android:anyDensity="true" android:smallScreens="true" android:normalScreens="true" android:largeScreens="true" android:resizeable="true" android:xlargeScreens="true"/>
    <uses-permission android:name="android.permission.INTERNET"/>
    <application android:label="@string/app_name" android:icon="@mipmap/icon" android:debuggable="true" android:hardwareAccelerated="true" android:supportsRtl="true">
        <activity android:theme="@style/Theme.DeviceDefault.NoActionBar" android:label="@string/activity_name" android:name="com.example.hello.MainActivity" android:launchMode="singleTop" android:configChanges="locale|keyboard|keyboardHidden|orientation|screenSize" android:windowSoftInputMode="adjustResize">
            <intent-filter android:label="@string/launcher_name">
                <action android:name="android.intent.action.MAIN"/>
                <category android:name="android.intent.category.LAUNCHER"/>
            </intent-filter>
        </activity>
    </application>
</manifest>
```
Ta có thể thấy main activity của app là `com.example.hello.MainActivity`. Giữ phím `Ctrl` và click vào `com.example.hello.MainActivity` tool sẽ decompile và mở file **MainActivity.java** lên. 

Source code **MainActivity.java**

```java
package com.example.hello;

import android.os.Bundle;
import org.apache.cordova.CordovaActivity;

public class MainActivity extends CordovaActivity {
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        Bundle extras = getIntent().getExtras();
        if (extras != null && extras.getBoolean("cdvStartInBackground", false)) {
            moveTaskToBack(true);
        }
        loadUrl(this.launchUrl);
    }
}
```

class `MainActivity` kế thừa class `CordovaActivity`, đây là app viết bằng [Cordova](https://cordova.apache.org/) (một dạng framework cross-platform). Loại app này có source là các file js, html, css như lập trình web và thường mấy file này được lưu ở trong thư mục `assets`.

Mở file `assets/www/js/app.js` thì có vẻ nó đã bị mã hóa nên chúng ta chỉ thấy 1 chuỗi base64 thôi. Để ý trong package `com.tkyaji.cordova` có 1 file tên là `DecryptResource.java`, có thể đây chính là class dùng để giải mã resource trước khi load lên webview 🙂

Source code **DecryptResource.java**:

```java
package com.tkyaji.cordova;

import android.net.Uri;
import android.util.Base64;
import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.regex.Pattern;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.apache.cordova.CordovaPlugin;
import org.apache.cordova.CordovaResourceApi;
import org.apache.cordova.LOG;

public class DecryptResource extends CordovaPlugin {
    private static final String CRYPT_IV = "WIU8k71fDAspR8Ie";
    private static final String CRYPT_KEY = "nFwsAczxEZAs1QPF1lfA5eOWPg2TgvhF";
    private static final String[] EXCLUDE_FILES = new String[0];
    private static final String[] INCLUDE_FILES = {"\\.(htm|html|js|css)$"};
    private static final String TAG = "DecryptResource";

    public Uri remapUri(Uri uri) {
        if (uri.toString().indexOf("/+++/") > -1) {
            return toPluginUri(uri);
        }
        return uri;
    }

    public CordovaResourceApi.OpenForReadResult handleOpenForRead(Uri uri) throws IOException {
        String uriStr = fromPluginUri(uri).toString().replace("/+++/", "/").split("\\?")[0];
        CordovaResourceApi.OpenForReadResult readResult = this.webView.getResourceApi().openForRead(Uri.parse(uriStr), true);
        if (!isCryptFiles(uriStr)) {
            return readResult;
        }
        BufferedReader br = new BufferedReader(new InputStreamReader(readResult.inputStream));
        StringBuilder strb = new StringBuilder();
        while (true) {
            String line = br.readLine();
            if (line == null) {
                break;
            }
            strb.append(line);
        }
        br.close();
        byte[] bytes = Base64.decode(strb.toString(), 0);
        LOG.d(TAG, "decrypt: " + uriStr);
        ByteArrayInputStream byteInputStream = null;
        try {
            SecretKeySpec secretKeySpec = new SecretKeySpec(CRYPT_KEY.getBytes("UTF-8"), "AES");
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(2, secretKeySpec, new IvParameterSpec(CRYPT_IV.getBytes("UTF-8")));
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            bos.write(cipher.doFinal(bytes));
            byteInputStream = new ByteArrayInputStream(bos.toByteArray());
        } catch (Exception ex) {
            LOG.e(TAG, ex.getMessage());
        }
        return new CordovaResourceApi.OpenForReadResult(readResult.uri, byteInputStream, readResult.mimeType, readResult.length, readResult.assetFd);
    }

    private boolean isCryptFiles(String uri) {
        String checkPath = uri.replace("file:///android_asset/www/", "");
        if (hasMatch(checkPath, INCLUDE_FILES) && !hasMatch(checkPath, EXCLUDE_FILES)) {
            return true;
        }
        return false;
    }

    private boolean hasMatch(String text, String[] regexArr) {
        for (String regex : regexArr) {
            if (Pattern.compile(regex).matcher(text).find()) {
                return true;
            }
        }
        return false;
    }
}
```
Vậy là resource đã bị mã hóa bằng thuật toán `AES/CBC/PKCS5Padding`, có key: `nFwsAczxEZAs1QPF1lfA5eOWPg2TgvhF`, iv: `WIU8k71fDAspR8Ie`. Sử dụng công cụ [CyberChef](https://gchq.github.io/CyberChef/) để giải mã file `app.js` ta được:

![Screenshot](/screenshots/review-source-2.png?raw=true "Screenshot")

Secret: `h3ll0_h0mi3s_nic3_t0_m33t_y0u_!` 😊

# Do I need to pay for professional versions?

Link tải challenge [CrackTool.zip](RE/CrackTool.zip)

Hàm `checkLicense`:

```C++
__int64 __fastcall checkLicense(char *a1, __int64 a2, __int64 a3)
{
  unsigned int i; // ebx
  wchar_t *hex_decoded; // rbp
  __int64 result; // rax
  int v6; // er10
  int *v7; // rax
  signed int v8; // er9

  i = 0;
  hex_decoded = (wchar_t *)hexdecode(a1, a2, a3);
  while ( 1 )
  {
    if ( (unsigned int)checksum(hex_decoded, i, 5) )
    {
      if ( (unsigned int)checksum(hex_decoded, 5 * i, 1) )
      {
        v7 = mapping(hex_decoded, v6, 5LL);
        result = check_part(i, *v7, v7[1], v7[2], v7[3], v8);
        if ( !(_DWORD)result )
          break;
      }
    }
    if ( ++i == 5 )
      return 1LL;
  }
  return result;
}
```

Đầu tiên input nhập vào sẽ được decode hex, vậy tức là input phải được encode hex trước khi nhập.

Hàm `checkLicense` có gọi hàm `checksum`, nhưng mình không care luôn (chả biết giải như này có đúng ý tác giả không nữa 😆😆😆). Chúng ta sẽ chỉ cần quan tâm 2 hàm là `mapping` và `check_part`.

Hàm `mapping`:
```C++
int *__fastcall mapping(wchar_t *a1, int a2, __int64 a3)
{
  int v3; // er12
  int v4; // ebx
  int *result; // rax
  __int64 j; // r8
  int v7; // edx
  __int64 i; // rsi
  unsigned __int64 mem_len; // rcx
  signed int v10; // er12
  int v11; // esi
  char mem[101]; // [rsp+3h] [rbp-95h]
  unsigned __int64 v13; // [rsp+68h] [rbp-30h]

  v3 = a3;
  v4 = a2;
  v13 = __readfsqword(0x28u);
  qmemcpy(mem, &unk_4B0259, sizeof(mem));
  result = (int *)malloc(4LL * (signed int)a3, (char *)&unk_4B0259 + 101, a3);
  j = a2;
  v7 = v3 + a2;
  while ( v7 > (signed int)j )
  {
    i = 0LL;
    mem_len = strlen(mem);
    while ( 1 )
    {
      v10 = i;
      if ( i == mem_len )
        break;
      if ( mem[i] == a1[j] )
      {
        v11 = i - mem_len;
        if ( v10 <= 50 )
          v11 = v10;
        result[(signed int)j - v4] = v11;
        break;
      }
      ++i;
    }
    ++j;
  }
  return result;
}
```

`unk_4B0259` là vùng nhớ chứa dữ liệu là:
```python
'0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!"#$%&\'()*+,-./:;<=>?@[\\]^_`{|}~ \t\n\r\x0b\x0c'
```
Hàm này sẽ chạy từng ký tự trong input, tìm `index` trong chuỗi `unk_4B0259`. Nếu `index <= 50` thì cập nhật lại `input[j] = index` ngược lại thì `input[j] = index - 50`. Kết quả là sẽ biến chuỗi input ban đầu thành mảng chứa các số từ -49 đến 50.

Chuỗi input được chia thành 4 phần, mỗi phần 4 ký tự. Mỗi phần đều được map lại bằng hàm `mapping`, sau đó kiểm tra tính hợp lệ bằng hàm `check_part`.

Hàm `check_part`:
```C++
__int64 __fastcall check_part(__int64 a1, signed int a2, signed int a3, signed int a4, signed int a5, signed int a6)
{
  float v6; // xmm2_4
  float v7; // xmm1_4
  float v8; // xmm0_4
  float v9; // xmm3_4
  float v10; // xmm2_4
  float v11; // xmm3_4
  float v12; // xmm4_4
  float v13; // xmm5_4
  float v14; // xmm4_4
  float v15; // xmm5_4
  float v16; // xmm4_4
  float v17; // xmm5_4
  bool v18; // zf
  float v19; // xmm3_4
  float v20; // xmm2_4
  float v21; // xmm4_4
  float v22; // xmm5_4
  float v23; // xmm4_4
  float v24; // xmm5_4
  float v25; // xmm4_4
  float v26; // xmm5_4
  float v27; // xmm3_4
  float v28; // xmm2_4
  float v29; // xmm5_4
  float v30; // xmm6_4
  float v31; // xmm4_4
  float v32; // xmm4_4
  float v33; // xmm5_4

  switch ( (_DWORD)a1 )
  {
    case 0:
      v6 = (float)a4;
      v7 = (float)a2;
      v8 = (float)a3;
      v9 = (float)a5;
      if ( (float)((float)((float)((float)a2 + (float)a3) + (float)(v6 + v6)) + (float)((float)a5 * 3.0)) == -2.0
        && (float)((float)((float)((float)(v8 + v8) + (float)(v7 + v7)) + (float)(v6 * 3.0)) + (float)(5.0 * v9)) == -2.0
        && (float)((float)((float)((float)(v7 * 3.0) - v8) + (float)(v6 + v6)) + v9) == 2.0 )
      {
        LODWORD(a1) = 0;
        if ( (float)((float)((float)((float)(v8 * 6.0) + (float)(v7 + v7)) + (float)(v6 * 6.0)) + (float)(v9 * 13.0)) == -10.0 )
          LODWORD(a1) = 1;
      }
      break;
    case 1:
      v10 = (float)a3 / 5.0;
      v11 = (float)a5 / 5.0;
      LODWORD(a1) = 0;
      if ( (unsigned int)magic((float)((float)((float)((float)a2 / 5.0) - v10) + (float)((float)a4 / 5.0)) + v11) == 1
        && (unsigned int)magic((float)((float)((float)(v12 + v12) + v10) + v13) + (float)(v11 * 3.0)) == 8
        && (unsigned int)magic((float)((float)(-3.0 * v14) + (float)(v10 + v10)) - v15) == -5 )
      {
        v18 = (unsigned int)magic(
                              (float)((float)((float)(4.0 * v10) + (float)(v16 * 4.0)) + (float)(v17 * 3.0))
                            + (float)(v16 * 4.0)) == 14;
        goto LABEL_20;
      }
      break;
    case 2:
      v19 = (float)a2 / 5.0;
      v20 = (float)a3 / 5.0;
      LODWORD(a1) = 0;
      if ( (unsigned int)magic((float)((float)(v19 + v20) + (float)((float)a4 / 5.0)) + (float)((float)a5 / 5.0)) == 5
        && (unsigned int)magic((float)((float)((float)(v20 + v20) + (float)(v19 + v19)) - v21) + (float)(v22 * 3.0)) == 10
        && (unsigned int)magic((float)((float)((float)(v19 * -2.0) - v20) + v23) + v24) == 3 )
      {
        v18 = (unsigned int)magic(
                              (float)((float)((float)(v20 * 3.0) + (float)(v19 + v19)) + (float)(v25 * 4.0))
                            + (float)(v26 + v26)) == 11;
        goto LABEL_20;
      }
      break;
    case 3:
      v27 = (float)a2 / 10.0;
      v28 = (float)a3 / 10.0;
      LODWORD(a1) = magic((float)((float)((float)(v28 + v28) + v27) - (float)((float)a4 / 10.0)) + (float)((float)a5 / 10.0));
      if ( (_DWORD)a1 )
        goto LABEL_22;
      v30 = v29 * 3.0;
      if ( (unsigned int)magic((float)((float)(v27 + v27) - (float)(3.0 * v28)) + (float)(v29 * 3.0)) == 3
        && (unsigned int)magic((float)((float)((float)(-4.0 * v27) + v28) + v30) + (float)(v31 + v31)) == -1 )
      {
        v18 = (unsigned int)magic((float)((float)(v27 + v28) + v33) + v32) == 2;
LABEL_20:
        LODWORD(a1) = v18;
      }
      break;
    case 4:
      LODWORD(a1) = 1;
      break;
    default:
LABEL_22:
      LODWORD(a1) = 0;
      break;
  }
  return (unsigned int)a1;
}
```



Hàm này có sử dụng thanh ghi `xmm` để lưu float, nên để xem giá bị thanh ghi lúc debug các bạn cần bật bảng `XMM Registers` lên bằng cách chọn **Debugger -> Debugger windows -> XMM registers**. Hàm `magic` thực chất là hàm `floor` trong c++.

Muốn license đúng thì cả 4 lần gọi hàm `check_part` này đều phải trả về `1`.

Tới đây có thể dùng `z3` để giải cho 4 case trong hàm `check_part`, hoặc có thể dụng cách cục súc hơn nhưng cũng hiệu quả không kém trong trường hợp này là `Brute force` 4 ký tự, trường hợp nào thỏa thì in ra 😂😂😂.

Chương trình này viết bằng C++, các bạn uncomment từng case để dò lần lượt case 0, 1, 2, 3:
```C++
#include<stdio.h>
#include<iostream>
#include<string.h>
#include<string>
#include <iostream>
#include <fstream>
#include "aes.h"


using namespace std;


int* mapping(char* a1, int a2, int a3)
{
    int v3; // er12
    int v4; // ebx
    int result[5]; // rax
    __int64 j; // r8
    int v7; // edx
    __int64 i; // rsi
    unsigned __int64 mem_len; // rcx
    signed int pos; // er12
    int new_val; // esi
    unsigned __int64 v13; // [rsp+68h] [rbp-30h]

    v3 = a3;
    v4 = a2;
    const char* mem = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!\"#$%&\'()*+,-./:;<=>?@[\\]^_`{|}~ \t\n\r\x0b\x0c";
    j = a2;
    v7 = v3 + a2;
    while (v7 > (signed int)j)
    {
        i = 0LL;
        mem_len = strlen(mem);
        while (1)
        {
            pos = i;
            if (i == mem_len)
                break;
            if (mem[i] == a1[j])
            {
                new_val = i - mem_len;
                if (pos <= 50)
                    new_val = pos;
                result[(signed int)j - v4] = new_val;
                break;
            }
            ++i;
        }
        ++j;
    }
    return result;
}

int convert(int n) {
	//Ngược lại của hàm mapping
    const char* mem = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!\"#$%&\'()*+,-./:;<=>?@[\\]^_`{|}~ \t\n\r\x0b\x0c";
    if (n < 0)
        n += 100;
    return mem[n];
}

int magic(float a1)
{
    double v1; // xmm0_8
    if (a1 < 0.0)
    {
        v1 = a1 - 0.5;
        return (unsigned int)(signed int)v1;
    }
    if (a1 > 0.0)
    {
        v1 = a1 + 0.5;
        return (unsigned int)(signed int)v1;
    }
    return 0LL;
}


int main() {

    for (int a2 = -49; a2 < 51; a2++)
    {
        for (int a3 = -49; a3 < 51; a3++)
        {
            for (int a4 = -49; a4 < 51; a4++)
            {
                for (int a5 = -49; a5 < 51; a5++)
                {
                    //case 0

                    float v6 = (float)a4;
                    float v7 = (float)a2;
                    float v8 = (float)a3;
                    float v9 = (float)a5;
                    if ((float)((float)((float)((float)a2 + (float)a3) + (float)(v6 + v6)) + (float)((float)a5 * 3.0)) == -2.0
                        && (float)((float)((float)((float)(v8 + v8) + (float)(v7 + v7)) + (float)(v6 * 3.0)) + (float)(5.0 * v9)) == -2.0
                        && (float)((float)((float)((float)(v7 * 3.0) - v8) + (float)(v6 + v6)) + v9) == 2.0)
                    {
                        if ((float)((float)((float)((float)(v8 * 6.0) + (float)(v7 + v7)) + (float)(v6 * 6.0)) + (float)(v9 * 13.0)) == -10.0)
                        {
                            printf("%02x%02x%02x%02x\n", convert(a2), convert(a3), convert(a4), convert(a5));
                        }
                    }



                    //case 1

                    /*float v10 = (float)a3 / 5.0;
                    float v11 = (float)a5 / 5.0;
                    float v12 = (float)a2 / 5.0;
                    float v13 = (float)a4 / 5.0;
                    float v14 = v12;
                    float v15 = v13;
                    float v17 = v13;
                    float v16 = v12;
                    if ((unsigned int)magic((float)((float)((float)((float)a2 / 5.0) - v10) + (float)((float)a4 / 5.0)) + v11) == 1
                        && (unsigned int)magic((float)((float)((float)(v12 + v12) + v10) + v13) + (float)(v11 * 3.0)) == 8
                        && (unsigned int)magic((float)((float)(-3.0 * v14) + (float)(v10 + v10)) - v15) == -5)
                    {
                        int v18 = (unsigned int)magic(
                            (float)((float)((float)(4.0 * v10) + (float)(v16 * 4.0)) + (float)(v17 * 3.0))
                            + (float)(v16 * 4.0)) == 14;
                        if (v18) {
                            printf("%02x%02x%02x%02x\n", convert(a2), convert(a3), convert(a4), convert(a5));
                        }
                        
                    }*/



                    //case 2

                    /*float v19 = (float)a2 / 5.0;
                    float v20 = (float)a3 / 5.0;
                    float v21 = (float)a4 / 5.0;
                    float v22 = (float)a5 / 5.0;
                    

                    float v23 = v22;
                    float v24 = v21;

                    float v25 = v21;
                    float v26 = v22;
                    
                    
                    
                    if ((unsigned int)magic((float)((float)(v19 + v20) + (float)((float)a4 / 5.0)) + (float)((float)a5 / 5.0)) == 5
                        && (unsigned int)magic((float)((float)((float)(v20 + v20) + (float)(v19 + v19)) - v21) + (float)(v22 * 3.0)) == 10
                        && (unsigned int)magic((float)((float)((float)(v19 * -2.0) - v20) + v23) + v24) == 3)
                    {
                        int v18 = (unsigned int)magic(
                            (float)((float)((float)(v20 * 3.0) + (float)(v19 + v19)) + (float)(v25 * 4.0))
                            + (float)(v26 + v26)) == 11;
                        if (v18) {
                            printf("%02x%02x%02x%02x\n", convert(a2), convert(a3), convert(a4), convert(a5));
                            ++count;
                        }
                    }*/
                    


                    //case 3

                    /*float v27 = (float)a2 / 10.0;
                    float v28 = (float)a3 / 10.0;
                    int a1 = magic((float)((float)((float)(v28 + v28) + v27) - (float)((float)a4 / 10.0)) + (float)((float)a5 / 10.0));
                    
                    if (a1 == 0) {
                        float v29 = (float)a4 / 10.0;
                        float v31 = (float)a5 / 10.0;
                        float v30 = v29 * 3.0;

                        float v32 = v29;
                        float v33 = v31;

                        v30 = v29 * 3.0;
                        if ((unsigned int)magic((float)((float)(v27 + v27) - (float)(3.0 * v28)) + (float)(v29 * 3.0)) == 3
                            && (unsigned int)magic((float)((float)((float)(-4.0 * v27) + v28) + v30) + (float)(v31 + v31)) == -1)
                        {
                            int v18 = (unsigned int)magic((float)((float)(v27 + v28) + v33) + v32) == 2;
                            if (v18) {
                                printf("%02x%02x%02x%02x\n", convert(a2), convert(a3), convert(a4), convert(a5));
                                ++count;
                            }
                        }
                    }*/
                    
                }
            }
        }
        
    }
	return 0;
}
```
Chỉ có case 0 chỉ có 1 trường hợp thỏa là: `3232300b`, còn các case 1, 2 và 3 đều có nhiều trường hợp thỏa mãn điều kiện check license:
- case 0: 1 trường hợp
- case 1: 9 trường hợp
- case 2: 55 trường hợp
- case 3: 478 trường hợp

Theo quy tắc nhân chúng ta sẽ có tất cả 1 x 9 x 55 x 478 = 236610 license hợp lệ, nhưng chỉ có 1 license có thể decrypt file `db2` thành công 😪😪😪.

Thật may là tác giả sử dụng thuật toán AES ở đây https://github.com/kokke/tiny-AES-c, và thuật toán này này yêu cầu key có 16 bytes mà thôi, nghĩa là chúng ta chỉ cần brute force 2 part đầu là được 😃😃😃 (vì hex(<8 bytes>) = 16 bytes).



# Extract cookies from Google Chrome browser

> I know that Alice found the flag, so I hacked her PC for you:
> - File: alice.zip

> Flag: wannagame\{ \*\*sha1(secret) \*\*\}

Link tải challenge [Alice.zip](MISC/Alice.zip)

File `Cookies` được lưu trong file `AppData\Local\Microsoft\Edge\User Data\Default` chứa tất cả cookie của trình duyệt, tuy nhiên nếu mở file này bằng `SQLite Browser` thì chúng ta sẽ thấy rằng `value` của cookie đã bị mã hóa (có thể tham khảo thêm ở [đây](https://stackoverflow.com/questions/22532870/encrypted-cookies-in-chrome)).

Có một công cụ hỗ trợ chúng ta giải mã cookie đó là [Mimikatz](https://github.com/gentilkiwi/mimikatz).

Một số link tham khảo cách sử dụng Mimikatz để unprotect data:

- https://www.ired.team/offensive-security/credential-access-and-credential-dumping/reading-dpapi-encrypted-secrets-with-mimikatz-and-c++
- https://www.onlinehashcrack.com/how-to-procdump-mimikatz-credentials.php
- https://miloserdov.org/?p=4205

Mở mimikatz lên, sau đó chạy lần lượt các lệnh như sau:
- `sekurlsa::minidump D:\CTF\WannaGame3\Alice\lsass.dmp`
- `sekurlsa::logonPasswords`
- `dpapi::masterkey /in:D:\CTF\WannaGame3\Alice\AppData\Roaming\Microsoft\Protect\S-1-5-21-3734529546-3570587082-1750843553-1001\b9c69d2f-bc92-4f94-89f8-c0bc63f5816c`
- `dpapi::chrome /in:"D:\CTF\WannaGame3\Alice\AppData\Local\Microsoft\Edge\User Data\Default\Cookies" /unprotect`

Và đây là kết quả:
```
mimikatz # dpapi::chrome /in:"D:\CTF\WannaGame3\Alice\AppData\Local\Microsoft\Edge\User Data\Default\Cookies" /unprotect
> Encrypted Key found in local state file
> Encrypted Key seems to be protected by DPAPI
 * using CryptUnprotectData API
 * volatile cache: GUID:{b9820292-310b-4df7-8ff2-1a857a8f1ea5};KeyHash:ed634a59b7bb4cca37009449d3ccacec9f073b6f;Key:available
> AES Key is: d68479b16670c12e9b18aa1579c6e79d81c3368625274b8df49a76d8eb9b2434

...

Host  : cnsc.uit.edu.vn ( / )
Name  : _Flag
Dates : 29/7/2020 13:41:59 -> 1/12/2020 07:00:00
 * using BCrypt with AES-256-GCM
Cookie: WannaGame{this_challenge_is_created_by_danhph}

...

```
Secret: `this_challenge_is_created_by_danhph`

# Could you win this game?

Link tải challenge [game.zip](RE/game.zip)

Hàm mainLoop:
```C++
int __cdecl mainLoop(void (*a1)(void))
{
  int result; // eax
  int v2; // [esp+14h] [ebp-14h]
  signed int i; // [esp+18h] [ebp-10h]
  char v4; // [esp+1Fh] [ebp-9h]

  v2 = getcolor();
  if ( kbhit() == 0 )
  {
    a1();
  }
  else
  {
    v4 = getch();
    if ( v4 == -32 )
      v4 = getch();
    if ( v4 == 32 )
    {
      setcolor(0);
      outtextxy(100, 100, "Game Pause");
      setcolor(v2);
      v4 = getch();
      while ( v4 != 32 )
      {
        v4 = getch();
        delay(0);
      }
      setcolor(15);
      outtextxy(100, 100, "Game Pause");
      setcolor(v2);
      delay(0x3E8u);
    }
    changeDirecton(v4);
    mainLoop(a1);
  }
  result = iCountFood;
  if ( iCountFood > 107 )
  {
    result = nameFunction;
    if ( nameFunction == 2 )
    {
      outtextxy(460, 200, "You won!!");
      for ( i = 0; i <= 107; ++i )
      {
        food = 10 * (foodA[i] + 2);
        dword_49E6D4 = 10 * (foodB[i] + 2);
        drawFood();
      }
      delay(3000u);
      iCountFood = 0;
      result = setcolor(0);
    }
  }
  return result;
}
```

Khi đạt số điểm là 108, game sẽ in ra dòng chữ `You won!!`, đồng thời vẽ hết các tọa độ của `food` lên màn hình thông qua hàm `drawFood`.

```C++
int drawFood(void)
{
  int v0; // ST1C_4
  int v1; // ST18_4

  v0 = getcolor();
  v1 = rand() % 14 + 1;
  setcolor(v1);
  setfillstyle(1, v1);
  drawPoint(food, dword_49E6D4, 5);
  setcolor(v0);
  return setfillstyle(1, 15);
}
```
Trong phần mềm IDA Pro, chọn File -> Script command..., chọn `Scripting language` là `Python` và thực thi đoạn script sau:

```python
import json

foodA = 0x0048E040
foodB = 0x0048E200
arr = []
for i in range(108):
    food = 10 * (Dword(foodA + i * 4))
    x = 10 * (Dword(foodB + i * 4))
    arr.append([food, x])
print json.dumps(arr)
```

Output:
```python
[[90, 100], [130, 20], [90, 40], [210, 60], [220, 60], [130, 50], [270, 90], [60, 40], [220, 40], [110, 40], [220, 20], [130, 30], [20, 110], [90, 20], [20, 60], [80, 120], [170, 110], [190, 110], [250, 60], [60, 60], [40, 90], [50, 110], [180, 110], [90, 90], [110, 130], [200, 50], [210, 130], [120, 100], [210, 20], [40, 110], [90, 60], [60, 30], [290, 130], [70, 120], [110, 120], [180, 60], [40, 50], [190, 130], [290, 90], [150, 30], [210, 40], [240, 60], [170, 30], [260, 60], [110, 50], [130, 60], [170, 100], [120, 50], [90, 30], [250, 110], [80, 20], [70, 110], [150, 40], [270, 130], [160, 40], [20, 100], [170, 50], [60, 20], [20, 120], [150, 130], [150, 100], [270, 100], [30, 40], [200, 20], [200, 60], [290, 110], [80, 100], [130, 40], [270, 110], [250, 100], [110, 100], [30, 130], [90, 50], [220, 130], [180, 130], [200, 40], [180, 20], [150, 20], [30, 20], [170, 120], [40, 130], [20, 30], [70, 30], [190, 100], [60, 50], [150, 90], [200, 30], [300, 100], [120, 30], [110, 90], [250, 90], [150, 120], [90, 120], [180, 90], [110, 110], [230, 130], [250, 130], [150, 60], [140, 100], [40, 120], [130, 110], [40, 20], [30, 60], [90, 110], [30, 90], [150, 50], [150, 110], [90, 130]]
```
Lên trang https://www.w3schools.com/graphics/tryit.asp?filename=trycanvas_draw và dán code này vào 😛😛😛:

```html
<!DOCTYPE html>
<html>
<body>

<canvas id="myCanvas" width="320" height="160"
style="border:1px solid #c3c3c3;">
Your browser does not support the canvas element.
</canvas>

<script>
var arr = [[90, 100], [130, 20], [90, 40], [210, 60], [220, 60], [130, 50], [270, 90], [60, 40], [220, 40], [110, 40], [220, 20], [130, 30], [20, 110], [90, 20], [20, 60], [80, 120], [170, 110], [190, 110], [250, 60], [60, 60], [40, 90], [50, 110], [180, 110], [90, 90], [110, 130], [200, 50], [210, 130], [120, 100], [210, 20], [40, 110], [90, 60], [60, 30], [290, 130], [70, 120], [110, 120], [180, 60], [40, 50], [190, 130], [290, 90], [150, 30], [210, 40], [240, 60], [170, 30], [260, 60], [110, 50], [130, 60], [170, 100], [120, 50], [90, 30], [250, 110], [80, 20], [70, 110], [150, 40], [270, 130], [160, 40], [20, 100], [170, 50], [60, 20], [20, 120], [150, 130], [150, 100], [270, 100], [30, 40], [200, 20], [200, 60], [290, 110], [80, 100], [130, 40], [270, 110], [250, 100], [110, 100], [30, 130], [90, 50], [220, 130], [180, 130], [200, 40], [180, 20], [150, 20], [30, 20], [170, 120], [40, 130], [20, 30], [70, 30], [190, 100], [60, 50], [150, 90], [200, 30], [300, 100], [120, 30], [110, 90], [250, 90], [150, 120], [90, 120], [180, 90], [110, 110], [230, 130], [250, 130], [150, 60], [140, 100], [40, 120], [130, 110], [40, 20], [30, 60], [90, 110], [30, 90], [150, 50], [150, 110], [90, 130]];
var canvas = document.getElementById("myCanvas");
var ctx = canvas.getContext("2d");
ctx.fillStyle = "#000000";
for(var i = 0; i < arr.length; i++){
    var x = arr[i][0];
    var y = arr[i][1];
    ctx.fillRect(x, y, 10, 10);
}
</script>

</body>
</html>
```
Canvas thu được chứa secret: 

![Screenshot](/screenshots/snake-game.png?raw=true "Screenshot")

Secret: `sn4ke_g4me_!!?`

# AHIHI Descrypt
