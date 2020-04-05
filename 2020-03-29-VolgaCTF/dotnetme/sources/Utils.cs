using System;

// Token: 0x0200000E RID: 14
public static class GClass1
{
	// Token: 0x0600004D RID: 77 RVA: 0x000092BC File Offset: 0x000074BC
	public static bool checkFlagFormat(string user_input, int hsh, bool checkFormat = true)
	{
		string[] input_parts = new string[1000];
		int num3 = 0;
		char c = '\0';


		if (checkFormat)
		{
			for (; ; )
			{
			IL_208:
				uint num = 1276780562U;
				for (; ; )
				{
					uint num2;
					switch ((num2 = (num ^ 1938848571U)) % 19U)
					{
						case 0U:
							{
								num = (GClass1.StringLength(input_parts[num3]) == 4) ? 161800768U : 267634710U;
								continue;
							}
						case 1U:
							{
								num = (num3 < input_parts.Length) ? 2066027667U : 372702057U;
								continue;
							}
						case 2U:
							return false;
						case 3U:
							{
								num3++;
								num = 22141646U;
								continue;
							}
						case 4U:
							num = (num2 * 1818674489U ^ 3927765253U);
							continue;
						case 6U:
							{
								num3 = 0;
								num = (num2 * 615570198U ^ 2476758416U);
								continue;
							}
						case 7U:
							goto IL_208;
						case 8U:
							{
								c = GClass1.GetCharAtOffset(user_input, num3);
								num = 487027905U;
								continue;
							}
						case 9U:
							{
								num = ((c < '\u007f') ? 3945937441U : 3956362675U) ^ num2 * 3337894887U;
								continue;
							}
						case 10U:
							{
								num = (((c < ' ') ? 2328726507U : 3166744977U) ^ num2 * 414064944U);
								continue;
							}
						case 11U:
							{
								num3++;
								num = 150263027U;
								continue;
							}
						case 12U:
							{
								input_parts = GClass1.StringSplit(user_input, new char[]
								{
							'-'
								});
								num3 = 0;
								num = 1642143901U;
								continue;
							}
						case 13U:
							return false;
						case 14U:
							num = (((GClass1.StringSplit(user_input, new char[]
							{
							'-'
							}).Length == 6) ? 683502988U : 1473095498U) ^ num2 * 1113113859U);
							continue;
						case 15U:
							num = (((GClass1.StringLength(user_input) != 29) ? 650567720U : 925404683U) ^ num2 * 2388823709U);
							continue;
						case 16U:
							num = (num2 * 1193093645U ^ 2466404860U);
							continue;
						case 17U:
							return false;
						case 18U:
							{
								num = (num3 >= GClass1.StringLength(user_input)) ? 1006143797U : 141482056U;
								continue;
							}
					}
					goto Block_9;
				}
			}
		Block_9:;
		}
		return GClass1.computeHash(user_input, hsh);
	}

	// Token: 0x0600004E RID: 78 RVA: 0x0001896C File Offset: 0x00013D6C
	public static bool computeHash(string input, int hsh)
	{
		int num = -1;
		char c = '\0';
		uint num3;
		int i = 0;
		int num5;

		for (; ; )
		{
		IL_B2:
			uint num2 = 3811407874U;
			for (; ; )
			{
				switch ((num3 = (num2 ^ 4060836142U)) % 8U)
				{
					case 0U:
						num2 = (i < GClass1.StringLength(input)) ? 3536600909U : 4041562728U;
						continue;
					case 1U:
						{
							if (num == -1)
							{
								num2 = (num3 * 1135592493U ^ 541386209U);
								continue;
							}
							num5 = c ^ num;
							goto IL_3B;
						}
					case 2U:
						{
							num5 = (int)c;
							goto IL_3B;
						}
					case 3U:
						{
							c = GClass1.GetCharAtOffset(input, i);
							num2 = 2698326959U;
							continue;
						}
					case 4U:
						num2 = (num3 * 3653827049U ^ 2748149295U);
						continue;
					case 5U:
						i = 0;
						num2 = (num3 * 1077189350U ^ 4038392112U);
						continue;
					case 7U:
						goto IL_B2;
				}
				goto Block_3;
			IL_3B:
				num = num5;
				i++;
				num2 = 3288268958U;
			}
		}
	Block_3:
		return num == hsh;
	}

	// Token: 0x0600004F RID: 79 RVA: 0x0000926C File Offset: 0x0000746C
	static int StringLength(string string_0)
	{
		return string_0.Length;
	}

	// Token: 0x06000050 RID: 80 RVA: 0x000095C0 File Offset: 0x000077C0
	static string[] StringSplit(string string_0, char[] char_0)
	{
		return string_0.Split(char_0);
	}

	// Token: 0x06000051 RID: 81 RVA: 0x00009258 File Offset: 0x00007458
	static char GetCharAtOffset(string string_0, int int_0)
	{
		return string_0[int_0];
	}
}
