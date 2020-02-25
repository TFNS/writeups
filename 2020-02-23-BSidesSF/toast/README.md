# Toast clicker (mobile/re)

There is the same code for all 3 challenges.
We get [android app](toast-clicker.apk) to analyze.

## Toast clicker 1 (79p, 23 solved)

In `MainActivity.java` we can see:

```java
int[] input = {67, 83, 68, 120, 62, 109, 95, 90, 92, 112, 85, 73, 99, 82, 53, 99, 101, 92, 80, 89, 81, 104};

//

public String printfirstFlag() {
    String output = BuildConfig.FLAVOR;
    int i = 0;
    while (true) {
        int[] iArr = this.input;
        if (i >= iArr.length) {
            return output;
        }
        int t = iArr[i] + i;
        StringBuilder sb = new StringBuilder();
        sb.append(output);
        sb.append(Character.toString((char) t));
        output = sb.toString();
        i++;
    }
}
```

We only need to run this code, or it's python equivalent:

```python
"".join([chr(x+i) for i,x in enumerate([67, 83, 68, 120, 62, 109, 95, 90, 92, 112, 85, 73, 99, 82, 53, 99, 101, 92, 80, 89, 81, 104])])
```
And we get `CTF{Bready_To_Crumble}`

## Toast clicker 2 (204p, 15 solved)

The second flag is slightly more complex:

```java
    public String printSecondFlag() {
        String output = BuildConfig.FLAVOR;
        String keyPart1 = BuildConfig.KEY_PART1;
        String keyPart2 = getString(C0275R.string.key_part2);
        StringBuilder sb = new StringBuilder();
        sb.append(keyPart1);
        sb.append(keyPart2);
        sb.append(keyStringFromJNI());
        try {
            return new helper(sb.toString()).decrypt(encryptedStringFromJNI());
        } catch (Exception e) {
            e.printStackTrace();
            return output;
        }
    }
```

We need 3 parts of the key.
First one is in `BuildConfig.java`:

```java
public static final String KEY_PART1 = "742375c48a7";
```

Second one we can get from `/resources/res/values/strings.xml`:

```xml
<string name="key_part2">0da605b16</string>
```

The last one comes from a native library in the project.
If you're not feeling like reversing a native lib, in this special case you don't really have to.
Since the value comes from just calling a function, you can create a new android NDK project, add this lib and simply call the function.
Here it's not necessary since the native lib just prints a static string:

```
        0012d4c0 34              ??         34h    4
        0012d4c1 00              ??         00h
        0012d4c2 00              ??         00h
        0012d4c3 00              ??         00h
        0012d4c4 39              ??         39h    9
        0012d4c5 00              ??         00h
        0012d4c6 00              ??         00h
        0012d4c7 00              ??         00h
        0012d4c8 63              ??         63h    c
        0012d4c9 00              ??         00h
        0012d4ca 00              ??         00h
        0012d4cb 00              ??         00h
        0012d4cc 39              ??         39h    9
        0012d4cd 00              ??         00h
        0012d4ce 00              ??         00h
        0012d4cf 00              ??         00h
        0012d4d0 62              ??         62h    b
        0012d4d1 00              ??         00h
        0012d4d2 00              ??         00h
        0012d4d3 00              ??         00h
        0012d4d4 37              ??         37h    7
        0012d4d5 00              ??         00h
        0012d4d6 00              ??         00h
        0012d4d7 00              ??         00h
        0012d4d8 31              ??         31h    1
        0012d4d9 00              ??         00h
        0012d4da 00              ??         00h
        0012d4db 00              ??         00h
        0012d4dc 31              ??         31h    1
        0012d4dd 00              ??         00h
        0012d4de 00              ??         00h
        0012d4df 00              ??         00h
        0012d4e0 38              ??         38h    8
        0012d4e1 00              ??         00h
        0012d4e2 00              ??         00h
        0012d4e3 00              ??         00h
        0012d4e4 65              ??         65h    e
        0012d4e5 00              ??         00h
        0012d4e6 00              ??         00h
        0012d4e7 00              ??         00h
        0012d4e8 36              ??         36h    6
        0012d4e9 00              ??         00h
        0012d4ea 00              ??         00h
        0012d4eb 00              ??         00h
        0012d4ec 31              ??         31h    1
        0012d4ed 00              ??         00h
        0012d4ee 00              ??         00h
        0012d4ef 00              ??         00h
```

The function there might look a bit daunting, but it simply prints out UTF string.

So we have all 3 parts of key -> `742375c48a70da605b1649c9b7118e61`.
Now the code takes another string the library, but again this is just hardcoded string:

```
                             s_MwDxTPEvfSLms0PVdgxjYwgpgN8Y8Xj3_0012d4f1     XREF[1]:     Java_com_ctf_toast_MainActivity_
        0012d4f1 4d  77  44       ds         "MwDxTPEvfSLms0PVdgxjYwgpgN8Y8Xj3Hrkw9pFkV6o="
                 78  54  50 
                 45  76  66 
```

So we just grab the string `MwDxTPEvfSLms0PVdgxjYwgpgN8Y8Xj3Hrkw9pFkV6o=`.

Now the flag is getting decrypted by some function from `helper.java` class.
Again, we could just run the original code, but we can also have a look there:

```java
public class helper {
    private Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
    private SecretKeySpec key = initKey();
    private String passphrase;

    public helper(String passphrase2) throws Exception {
        this.passphrase = passphrase2;
    }

    public SecretKeySpec initKey() throws Exception {
        return new SecretKeySpec(Arrays.copyOf(MessageDigest.getInstance("SHA-1").digest(this.passphrase.getBytes("UTF-8")), 16), "AES");
    }

    public String encrypt(String plaintext) throws Exception {
        byte[] plaintextBytes = plaintext.getBytes();
        this.cipher.init(1, this.key);
        return Base64.encodeToString(this.cipher.doFinal(plaintextBytes), 2);
    }

    public String decrypt(String ciphertext) throws Exception {
        byte[] ciphertextBytes = Base64.decode(ciphertext.getBytes(), 2);
        this.cipher.init(2, this.key);
        return new String(this.cipher.doFinal(ciphertextBytes), "UTF-8");
    }
}
```

It simply derives AES-ECB-128 key using `SHA-1` and decrypts the base64 decoded data.
We can do the same via:

```python
import hashlib

from Crypto.Cipher.AES import MODE_ECB
from Cryptodome.Cipher import AES


def main():
    key = '742375c48a70da605b1649c9b7118e61'
    ct = "MwDxTPEvfSLms0PVdgxjYwgpgN8Y8Xj3Hrkw9pFkV6o=".decode("base64")
    aes = AES.new(hashlib.sha1(key).digest()[:16], MODE_ECB)
    print(aes.decrypt(ct))


main()
```

And we get another flag `CTF{T00_Many_S3cr3t5}`

## Toast clicker 3 (96p, 21 solved)

The last part of the challenge comes from:

```java
    public void loadClass() {
        String methodToInvoke = "printThirdFlag";
        try {
            Class<?> loadedClass = new DexClassLoader(Uri.fromFile(new File(getExternalFilesDir(null), "bacon-final.dex")).toString(), null, null, ClassLoader.getSystemClassLoader().getParent()).loadClass("bacon.ToastDynamicFlag");
            Object obj = loadedClass.newInstance();
            String str = (String) loadedClass.getMethod(methodToInvoke, new Class[]{String.class, String.class}).invoke(obj, new Object[]{"ijiijiiijjjjjijijijiiijjijjjji", "jjjiiiiijjjijijijjijiijji"});
        } catch (ClassNotFoundException e) {
            e.printStackTrace();
        } catch (InstantiationException e2) {
            e2.printStackTrace();
        } catch (IllegalAccessException e3) {
            e3.printStackTrace();
        } catch (NoSuchMethodException e4) {
            e4.printStackTrace();
        } catch (IllegalArgumentException e5) {
            e5.printStackTrace();
        } catch (InvocationTargetException e6) {
            e6.printStackTrace();
        }
    }
```

It looks weird, but in reality this is simply loading a new class `bacon.ToastDynamicFlag` at runtime from `bacon-final.dex` and calls method `printThirdFlag` on object of this class with arguments `"ijiijiiijjjjjijijijiiijjijjjji", "jjjiiiiijjjijijijjijiijji"`.

This dex file comes from:

```java
    public void downloadFile() {
        File file = new File(getExternalFilesDir(null), "bacon-final.dex");
        DownloadManager downloadmanager = (DownloadManager) getSystemService("download");
        Request request = new Request(Uri.parse("https://storage.googleapis.com/bsides-sf-ctf-2020-attachments/bacon-final.dex"));
        request.setTitle("Dex File");
        request.setDescription("Downloading update");
        request.setNotificationVisibility(1);
        request.setVisibleInDownloadsUi(false);
        request.setDestinationUri(Uri.fromFile(file));
        request.setAllowedOverRoaming(false);
        request.setAllowedOverMetered(false);
        Log.d("File path", Uri.fromFile(file).toString());
        this.downloadID = downloadmanager.enqueue(request);
    }
```

We can just grab the [dex](bacon-final.dex) from the URL and decompile it just as we did with the apk.
There is only [one class](ToastDynamicFlag.java) there.

As mentioned, we only need to call the function there to get the flag, so we do just that, add a main method with:

```java
    public static void main(String[] args) {
        ToastDynamicFlag toastDynamicFlag = new ToastDynamicFlag();
        System.out.println(toastDynamicFlag.printThirdFlag("ijiijiiijjjjjijijijiiijjijjjji", "jjjiiiiijjjijijijjijiijji"));
    }
```

And run this to get `CTF{makingbaconpancakes}`
