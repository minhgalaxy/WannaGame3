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

# AHIHI Descrypt
