using System;
using System.Text;

// Token: 0x0200000D RID: 13
public static class GClass0
{
	// Token: 0x06000044 RID: 68 RVA: 0x000090AC File Offset: 0x000072AC
	public static bool checkFlag(string user_input)
	{
		uint num2;

		if (GClass1.checkFlagFormat(user_input, 41, true))
		{
			num2 = 26855954U;
		} else
		{
			GClass0.WriteLine("Invalid key format");
			num2 = 1370466160U;
		}
		for (; ; )
		{
			uint num;
			switch ((num = (num2 ^ 1725436766U)) % 5U)
			{
				case 1U:
					num2 = ((GClass0.xorStringBuilder(user_input, 74) ? 3365316463U : 2561374200U) ^ num * 2157556502U);
					continue;
				case 2U:
					return true;
				case 3U:
					{ 
						GClass0.WriteLine("Invalid key format");
						num2 = 1370466160U;
						break;
					}
				case 4U:
					continue;
			}
			break;
		}

		return false;
	}

	// Token: 0x06000045 RID: 69 RVA: 0x0000913C File Offset: 0x0000733C
	private static bool xorStringBuilder(string input, int int_0)
	{
		string secret = "3cD1Z84acsdf1caEBbfgMeAF0bObA";
		StringBuilder stringBuilder = GClass0.newStringBuilder();
		int num = 0;
		int num4 = 0;
		for (; ; )
		{
		IL_D0:
			uint num2 = 169177363U;
			for (; ; )
			{
				uint num3;
				switch ((num3 = (num2 ^ 200344158U)) % 6U)
				{
					case 0U:
						goto IL_D0;
					case 1U:
						num2 = (num3 * 1049313381U ^ 1849965166U);
						continue;
					case 2U:
						{
							num4 = (int)(GClass0.GetCharAtOffset(input, num) * '*');
							num2 = 708881281U;
							continue;
						}
					case 3U:
						num2 = ((num < GClass0.stringLength(input)) ? 1292729362U : 1878786418U);
						continue;
					case 5U:
						{
							int int_ = ((num4 >> 6) + (num4 >> 5) & 127) ^ (num4 + (int)GClass0.GetCharAtOffset(secret, num) & 127) ^ (int)GClass0.GetCharAtOffset(secret, GClass0.stringLength(input) - num - 1);
							stringBuilder = GClass0.stringBuilderAppend(stringBuilder, GClass0.toChar(int_));
							num++;
							num2 = (num3 * 506734605U ^ 1767636828U);
							continue;
						}
				}
				goto Block_2;
			}
		}
	Block_2:
		return GClass1.checkFlagFormat(GClass0.toString(stringBuilder), int_0, false);
	}

	// Token: 0x06000046 RID: 70 RVA: 0x00009230 File Offset: 0x00007430
	static void WriteLine(string string_0)
	{
		Console.WriteLine(string_0);
	}

	// Token: 0x06000047 RID: 71 RVA: 0x00009244 File Offset: 0x00007444
	static StringBuilder newStringBuilder()
	{
		return new StringBuilder();
	}

	// Token: 0x06000048 RID: 72 RVA: 0x00009258 File Offset: 0x00007458
	static char GetCharAtOffset(string string_0, int int_0)
	{
		return string_0[int_0];
	}

	// Token: 0x06000049 RID: 73 RVA: 0x0000926C File Offset: 0x0000746C
	static int stringLength(string string_0)
	{
		return string_0.Length;
	}

	// Token: 0x0600004A RID: 74 RVA: 0x00009280 File Offset: 0x00007480
	static char toChar(int int_0)
	{
		return Convert.ToChar(int_0);
	}

	// Token: 0x0600004B RID: 75 RVA: 0x00009294 File Offset: 0x00007494
	static StringBuilder stringBuilderAppend(StringBuilder stringBuilder_0, char char_0)
	{
		return stringBuilder_0.Append(char_0);
	}

	// Token: 0x0600004C RID: 76 RVA: 0x000092A8 File Offset: 0x000074A8
	static string toString(object object_0)
	{
		return object_0.ToString();
	}
}
