package bacon;

import java.util.HashMap;

public class ToastDynamicFlag {
    private HashMap<String, Character> bacon_dmap;
    private HashMap<Character, String> bacon_emap;
    private String flagPart3 = "jiijiiiijjiijjijijijiiijjjjjijjjjjjiiiii";

    public ToastDynamicFlag() {
        encode_map();
        decode_map();
    }

    public void encode_map() {
        this.bacon_emap = new HashMap<>();
        this.bacon_emap.put(Character.valueOf('a'), "iiijj");
        this.bacon_emap.put(Character.valueOf('b'), "jjjii");
        this.bacon_emap.put(Character.valueOf('c'), "jijij");
        this.bacon_emap.put(Character.valueOf('d'), "jjijj");
        this.bacon_emap.put(Character.valueOf('e'), "jjjjj");
        this.bacon_emap.put(Character.valueOf('f'), "ijjjj");
        this.bacon_emap.put(Character.valueOf('g'), "jjjji");
        this.bacon_emap.put(Character.valueOf('h'), "iijii");
        this.bacon_emap.put(Character.valueOf('i'), "ijiji");
        this.bacon_emap.put(Character.valueOf('j'), "iiiji");
        this.bacon_emap.put(Character.valueOf('k'), "jjjij");
        this.bacon_emap.put(Character.valueOf('l'), "jijji");
        this.bacon_emap.put(Character.valueOf('m'), "ijiij");
        this.bacon_emap.put(Character.valueOf('n'), "iijji");
        this.bacon_emap.put(Character.valueOf('o'), "ijjij");
        this.bacon_emap.put(Character.valueOf('p'), "jiiji");
        this.bacon_emap.put(Character.valueOf('q'), "ijijj");
        this.bacon_emap.put(Character.valueOf('r'), "jijii");
        this.bacon_emap.put(Character.valueOf('s'), "iiiii");
        this.bacon_emap.put(Character.valueOf('t'), "jjiij");
        this.bacon_emap.put(Character.valueOf('u'), "ijjji");
        this.bacon_emap.put(Character.valueOf('v'), "jiiij");
        this.bacon_emap.put(Character.valueOf('w'), "iiiij");
        this.bacon_emap.put(Character.valueOf('x'), "iijij");
        this.bacon_emap.put(Character.valueOf('y'), "jjiji");
        this.bacon_emap.put(Character.valueOf('z'), "jijjj");
    }

    public void decode_map() {
        this.bacon_dmap = new HashMap<>();
        this.bacon_dmap.put("iiijj", Character.valueOf('a'));
        this.bacon_dmap.put("jjjii", Character.valueOf('b'));
        this.bacon_dmap.put("jijij", Character.valueOf('c'));
        this.bacon_dmap.put("jjijj", Character.valueOf('d'));
        this.bacon_dmap.put("jjjjj", Character.valueOf('e'));
        this.bacon_dmap.put("ijjjj", Character.valueOf('f'));
        this.bacon_dmap.put("jjjji", Character.valueOf('g'));
        this.bacon_dmap.put("iijii", Character.valueOf('h'));
        this.bacon_dmap.put("ijiji", Character.valueOf('i'));
        this.bacon_dmap.put("iiiji", Character.valueOf('j'));
        this.bacon_dmap.put("jjjij", Character.valueOf('k'));
        this.bacon_dmap.put("jijji", Character.valueOf('l'));
        this.bacon_dmap.put("ijiij", Character.valueOf('m'));
        this.bacon_dmap.put("iijji", Character.valueOf('n'));
        this.bacon_dmap.put("ijjij", Character.valueOf('o'));
        this.bacon_dmap.put("jiiji", Character.valueOf('p'));
        this.bacon_dmap.put("ijijj", Character.valueOf('q'));
        this.bacon_dmap.put("jijii", Character.valueOf('r'));
        this.bacon_dmap.put("iiiii", Character.valueOf('s'));
        this.bacon_dmap.put("jjiij", Character.valueOf('t'));
        this.bacon_dmap.put("ijjji", Character.valueOf('u'));
        this.bacon_dmap.put("jiiij", Character.valueOf('v'));
        this.bacon_dmap.put("iiiij", Character.valueOf('w'));
        this.bacon_dmap.put("iijij", Character.valueOf('x'));
        this.bacon_dmap.put("jjiji", Character.valueOf('y'));
        this.bacon_dmap.put("jijjj", Character.valueOf('z'));
    }

    public String encode(String str) {
        StringBuilder sb = new StringBuilder();
        int i = 0;
        while (true) {
            int i2 = i;
            if (i2 >= str.length()) {
                return sb.toString();
            }
            sb.append((String) this.bacon_emap.get(Character.valueOf(str.charAt(i2))));
            i = i2 + 1;
        }
    }

    public String decode(String str) {
        int i = 0;
        StringBuilder sb = new StringBuilder();
        String str2 = "";
        int i2 = 0;
        while (true) {
            int i3 = i;
            if (i2 >= str.length() / 5) {
                return sb.toString();
            }
            sb.append(this.bacon_dmap.get(str.substring(i3, i3 + 5)));
            i = i3 + 5;
            i2++;
        }
    }

    public String printThirdFlag(String str, String str2) {
        String str3 = "";
        return "CTF{" + (decode(str) + decode(str2) + decode(this.flagPart3)) + "}";
    }
}
