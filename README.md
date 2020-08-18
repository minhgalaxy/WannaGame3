# WannaGame Championship

- [RE - Simple reverse](#simple-reverse)
- [Cryptography - AES](#aes)
- [WEB - Source review](#source-review)
- [RE - Do I need to pay for professional versions?](#do-i-need-to-pay-for-professional-version)
- [MISC - Extract cookies from Google Chrome browser](#extract-cookies-from-google-chrome-browser)
- [RE - Could you win this game?](#could-you-win-this-game)
- [RE - AHIHI Descrypt](#ahihi-descrypt)

# Simple Reverse

[Link tải challenge](RE/HashProgram.exe)

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

Sử dụng tính năng debug của dnspy, đặt breakpoint ngay tại hàm so sánh 2 chuỗi

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

# Source review

# Do I need to pay for professional versions?

# Extract cookies from Google Chrome browser

# Could you win this game?

# AHIHI Descrypt
