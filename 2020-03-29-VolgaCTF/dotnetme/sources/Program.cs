using System;

// Token: 0x0200000D RID: 13
internal class Class5
{
	// Token: 0x06000044 RID: 68 RVA: 0x000090A0 File Offset: 0x000072A0
	private static void Main(string[] args)
	{
		string string_ = "";
		bool flag = false; ;
		for (; ; )
		{
		IL_124:
			uint num = 3852576474U;
			for (; ; )
			{
				uint num2;
				switch ((num2 = (num ^ 3668039872U)) % 12U)
				{
					case 0U:
						{
							string_ = Console.ReadLine();
							num = (num2 * 667074909U ^ 1832192635U);
							continue;
						}
					case 1U:
						num = (num2 * 873963387U ^ 3492954474U);
						continue;
					case 2U:
						Console.WriteLine("Hello There");
						num = (num2 * 392808653U ^ 210115494U);
						continue;
					case 3U:
						goto IL_124;
					case 4U:
					case 8U:
						num = 2230297123U;
						continue;
					case 5U:
						Console.WriteLine("Wrong!");
						num = 3893711220U;
						continue;
					case 6U:
						Console.WriteLine("Success!");
						num = (num2 * 2407774348U ^ 2373641761U);
						continue;
					case 7U:
						{
							flag = GClass0.checkFlag(string_);
							num = (num2 * 1384138710U ^ 1040842312U);
							continue;
						}
					case 10U:
						{
							num = (flag ? 3890892882U : 3125342133U) ^ num2 * 1182348344U;
							continue;
						}
					case 11U:
						Console.WriteLine("Please Type de correct key");
						num = (num2 * 647976485U ^ 2452960379U);
						continue;
				}
				return;
			}
		}
	}

	// Token: 0x06000046 RID: 70 RVA: 0x000091D8 File Offset: 0x000073D8
	static void WriteLine(string string_0)
	{
		Console.WriteLine(string_0);
	}

	// Token: 0x06000047 RID: 71 RVA: 0x000091EC File Offset: 0x000073EC
	static string smethod_1()
	{
		return Console.ReadLine();
	}

	// Token: 0x06000048 RID: 72 RVA: 0x00009200 File Offset: 0x00007400
	static bool smethod_2(string string_0)
	{
		return GClass0.checkFlag(string_0);
	}
}
