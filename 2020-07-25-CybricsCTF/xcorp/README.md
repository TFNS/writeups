# XCorp (network, 50p, 159 solved)

In the task we get a [pcap](xcorp.pcap) to analyse.
Networ Miner recovers [executable](net10.exe) for us included in the pcap.

It's a simple .NET binary, with most important part of the code being:

```csharp
private void button1_Click(object sender, EventArgs e)
{
    byte[] bytes = Encoding.ASCII.GetBytes(this.textBox1.Text);
    if (bytes.Length == 0)
    {
        MessageBox.Show("Please, enter username!");
        return;
    }
    byte[] bytes2 = RC4.Encrypt(bytes, this.corp);
    if (Encoding.ASCII.GetString(bytes2) != "xcorporation")
    {
        MessageBox.Show("Incorrect!");
        return;
    }
    byte[] bytes3 = RC4.Encrypt(bytes, this.flag);
    this.label2.Text = Encoding.ASCII.GetString(bytes3);
}
```

First static buffer is:
```
[218, 201, 193, 75, 114, 18, 81, 42, 33, 53, 127, 239]
```

And second one:

```
[193, 211, 204, 75, 107, 30, 80, 48, 96, 111, 83, 244, 91, 214, 52, 0, 186, 157, 89, 127, 139, 164, 4, 105, 60, 22, 134, 43, 112, 69, 194]
```

RC4 is a stream cipher, so we could use the `xcorporation` plaintext and ciphertext to recover keystream, and decrypt prefix of the flag, but this is not very useful.
We actually need to find the valid username.
Grepping through the pcap we notice an interesting UTF string `u17ra_h4ck3r`, which turns out to be the valid RC4 passphrase:

```python
xcorp_ct = "".join(map(chr, [218, 201, 193, 75, 114, 18, 81, 42, 33, 53, 127, 239]))
flag_ct = "".join(map(chr, [193, 211, 204, 75, 107, 30, 80, 48, 96, 111, 83, 244, 91, 214, 52, 0, 186, 157, 89, 127, 139, 164, 4, 105, 60, 22, 134, 43, 112, 69, 194]))
keystream = xor_string(xcorp_ct, 'xcorporation')
print('flag prefix', xor_string(keystream, flag_ct))
rc4_key_bytes = rc4(map(ord, 'u17ra_h4ck3r'), 100)
keystream = "".join(map(chr, rc4_key_bytes))
print('flag', xor_string(keystream, flag_ct))
```

And we get: `cybrics{53CuR1tY_N07_0b5CuR17Y}`
