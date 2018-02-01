/*
Software Security
First Homework
---------------------
Name : Shmuel 
Last Name : Uzan
ID : 302995089 
Campus : Beer Shave
---------------------
 */
package softwaresecurity;

import java.util.Arrays;

/**
 *
 * @author Sammy Guergachi <sguergachi at gmail.com>
 */
public class VigenereCipher {
    private final char A = 'A';
    private final char Z = 'Z';
    private final double VALUE = 0.066;
    private final int LENGTH_DISTANCE = 15;
    private final int LENGTH_LETTER = 26;
    private final double[] HISTOGRAM = { 8.167, 1.492, 2.782, 4.253, 12.702, 2.228,
			2.015, 6.094, 6.966, 0.153, 0.772, 4.025, 2.406, 6.749, 7.507,
			1.929, 0.095, 5.987, 6.327, 9.056, 2.758, 0.978, 2.360, 0.150,
			1.974, 0.074 };
    
    /**
     *Function takes a string and key and encrypts with Vigenere.
     * @param plaintext - String encryption.
     * @param key 
     * @return String - Ciphertext.
     */
    public String encrypt(String plaintext, final String key){

        StringBuilder ciphertext = new StringBuilder();
        String text = plaintext.toUpperCase();
        char ch ;
        for(int i=0, j=0; i < text.length() ; i++){
            ch = text.charAt(i);
            
            if(ch < A || ch > Z ) continue;
            
            ciphertext.append((char)((ch + key.charAt(j) - 2*A)%26 + A));
            j = ++j % key.length();
        }
        
        return ciphertext.toString();
    }
    
    /**
     *A function that receives a string and key and decrypt the encrypted string.
     * @param ciphertext - 
     * @param key
     * @return String decoded.
     */
    public String decrypt(String ciphertext, final String key){
        StringBuilder plaintext = new StringBuilder();
        String text = ciphertext.toUpperCase();
        char ch;
        
        for(int i=0, j=0; i < text.length() ; i++){
            ch = text.charAt(i);
            
            if(ch < A || ch > Z) continue;
            
            plaintext.append((char)((ch - key.charAt(j) + 26)%26 + A));
            j= ++j % key.length();
        }
        
        return plaintext.toString();
    }
    
    /**
     *A function calculates the frequency of characters
     * @param ciphertext - String search
     * @return int[]  - The number of impressions of each character.
    */
    private int[] frequency(String ciphpertext){
       int[] freq = new int[LENGTH_LETTER];
       int index = -1;
       int length = ciphpertext.length();
       char ch;
       Arrays.fill(freq, 0);
       
       for(int i=0 ; i<length;  i++){
           ch = ciphpertext.charAt(i);
                   
           if(ch < A || ch > Z) continue;
           
           index = (ch - A) % LENGTH_LETTER;
           
           freq[index]++;  
       }
       
       return freq;
    }
    
    /**
     * A function guessed by frequency of characters the length of the key
     * @param ciphertext - String
     * @return int - length of the key.
     */
    private int indexOfCoincidence(String ciphertext){
        
        double[] total = new double[LENGTH_DISTANCE];      
        double n,sum=0;
        
        Arrays.fill(total,0);

        for(int i=0 ; i < LENGTH_DISTANCE && ( ciphertext.length() - i) > 0 ; i++){
             String[] subString = subString(ciphertext, i+1);
             n = subString.length;
             sum = 0;
            
             for(int j=0 ;  j < n  ;j++){
                 double x = calculateIC(subString[j]);
                 sum = sum + x;
             }
             total[i] = sum/n;        
        }   
        
        int max =  maxIC(total ) ;
        return max+1;
    }
    
    /**
     * A function takes long string to substring her division by size.
     * @param cipher -String to substring
     * @param size - how many strings
     * @return String[] - substring.
     */
    private String[] subString(String cipher, int size){
        String[] subCipher = new String[size];
        StringBuilder text = new StringBuilder();
       
        for(int i=0; i < size; i++){
            for(int j=0; j < cipher.length() ; j++){
                if(j % size == i){
                    text.append(cipher.charAt(j));
                }
            }
            subCipher[i] = text.toString();
            text = new StringBuilder();
        }
        
        return subCipher;
    }
    
    /**
     * A function that accepts a string and calculates the Index Of Coincidence.
     * @param text 
     * @return int - sum of IC
     */
    private double calculateIC(String text){
        int i=0;      
        int N = text.length();
        double sum = 0;
        double total = 0;
        
        int[] frequency = frequency(text);
        int ch;
        
        for(i=0 ; i < frequency.length ; i++){
            ch = frequency[i];
            sum = sum + (ch*(ch- 1));
        }
        
        total = sum/((N*(N-1)));
        return total;
    }
    
    /**
     * Function searches for the number closest to 0.66 
     * @param array 
     * @return int - index of max value in array.
     */
    private int maxIC(double[] array){
        int length = array.length;
        if(length == 0 ) return 0; 
        
        double max1 = Double.MIN_VALUE, max2 = Double.MIN_VALUE;
        int index1 = -1, index2 = -1;
        
        for(int i=0 ; i<length ;i++){
            double temp = array[i]; 
            if(temp >= max1 && temp < VALUE  ){
                max1 = array[i];
                index1 = i;
            }
        }
        
        for(int i=0 ; i<length ;i++){
            double temp = array[i]; 
            if(temp >= max2 && temp > VALUE  ){
                max2 = array[i];
                index2 = i;
            }
        }
       
        double x = (VALUE-max1);
        double y = (max2-VALUE);
        
        if(x < 0 )
            x*=-1;
        else if(y < 0)
            y*=-1;
        
        if(x > y)
            return index2;
        return index1;
        
    }
    
    /**
     * Function searches for the greatest number in array.
     * @param array
     * @return int - index of max number.
     */
    private int maxValue(double[] array){
        int length = array.length;
        if(length == 0 ) return 0; 
        
        double max=0;
        int index = -1;
        
        
        for(int i=0 ; i<length ;i++){
            double temp = array[i]; 
            if(temp >= max){
                max = array[i];
                index = i;
            }
        }

        return index;
    }
    
    /**
     * Function that accepts encrypted string and calculates according Histogram of the key.
     * @param ciphertext 
     * @return String key
     */
    public String gussKey(String ciphertext){
        double[] tempResult = new double[LENGTH_LETTER];
        int index= 0;
        int lenghtKey = indexOfCoincidence(ciphertext);
        int[] total = new int[lenghtKey];
        String[] subString = subString(ciphertext, lenghtKey);
        StringBuilder key = new StringBuilder();
        
        for(String sb : subString){
            int[] fre = frequency(sb);
            
            Arrays.fill(tempResult, 0);
           
            total[index] = calculateRelativeFrequency(sb, fre);
            index++;
        }

        for(int sb : total)
            key.append((char)((int)(sb+A)));
        
        System.out.println("The key is : " + key);
        return key.toString();
    }
   
    /**
     * Function relative frequency of characters looking for the 
     * most appropriate adjustment key character.
     * 
     * @param sb - string column.
     * @param fre - frequency of characters.
     * @return index of char.
     */
    public int calculateRelativeFrequency(String sb, int[] fre){
        double[] tempResult = new double[LENGTH_LETTER];
        double[] total = new double[LENGTH_LETTER];
        double sum = 0;
        
        Arrays.fill(tempResult, 0);
        
        for(int j=0; j<LENGTH_LETTER ; j++){
            sum = 0;
            
            for(int i=0; i< fre.length ; i++){   
               
                double x = (double)fre[(i+j)%26]/(double)sb.length();
                tempResult[i] = HISTOGRAM[i]*x;
                sum+=tempResult[i];
             }
            
            total[j] = sum;
        }
        
         return maxValue(total);
    }
 
    /**
     * Function that accepts encrypted string and return a string decoded.
     * @param ciphertext 
     * @return String decoded.
     */
    public String decryptCipherText(String ciphertext){
        String ciphper = fixString(ciphertext);
        String gussKey = gussKey(ciphper);
        
        return decrypt(ciphper, gussKey);
    }
  
    /**
     * Function that accepts a string and deleted unnecessary character from.
     * @param text 
     * @return new String without unnecessary character.
     */
    private String fixString(String text) {
        StringBuilder sb = new StringBuilder();
        String temp = text.toUpperCase();
        char ch ;
        
        for(int i=0 ; i <temp.length() ; i++){
            ch = temp.charAt(i);
            
            if(ch < A || ch > Z) continue;
            
            sb.append(ch);
        }
        
        return sb.toString();
    }
    
    public static void main(String[] args) {
        System.out.println("Welcome to Program Vigenere :)");
        VigenereCipher vigenere = new VigenereCipher();
        String ciphertext = "HUGVUKSATTMUNDKUMKVVAYVLPOMCEDTBGKIIEYARTREEDRINKFSMEMQNGFEH\n" +
                            "UVMAMHRUCPVVHBWMOGYZXVJWOMKBMAIELJVRPOMCEDRBWKIUNZEEEFRRPKMA\n" +
                            "ZZYUDZRYRALVRZGNFLEKAKTVGNEJOAWBFLSEEBIAMSCIAKTVGNVRPKMAZHXD\n" +
                            "YXLNFIIIDJSEMPWJOHIIBZMKOMMZNAXVRZHGTWTZNBEGFFGYAHFRKKSFRJRY\n" +
                            "RALZSVRQGVXYIIKZHYIRHYMFMPRTTGCVKLQVMWIEBAARSDRGALFCEVOQXJID\n" +
                            "BZVNGKIRCCWRIHVRTZHLBUKVMWIEPYSLGCXVMZKYONXHIVRKHZJYHVVVABIE\n" +
                            "EFMNINLRWALVMJVEHDZRIIPLBOEUSJYTAAXFBJVEHDJIOHQLUVSBSNYEVLEJ\n" +
                            "EJJFNYVFWNSEKVAWOMXUXSSJTGIAHYIWOMXUXYEIEVRQKHHZAIXZTPHVNRLB\n" +
                            "FALVAIKREZRRMZPRGVVVNVQRELWJHZVRYVVVVZVZHYIRNYXUXZMCKZRFTKYE\n" +
                            "CZVGTPRIUNXYBUKFFZEPAWYIPGIPNYXRIIXUKPPCEYQRYPPCEYQRPPXYFVRG\n" +
                            "TZXZCOIEKVVJNZZRKMICTWISHYIJOOLNMUSNTJWGBSPKHZFRTAMEGJJZROIR\n" +
                            "ROMFMVSURZTRTAMEGOMFLVQVVDWVMVVVNOVRTAMEGZRGKHRTEVXZRJLRMWIE\n" +
                            "WVSISJQREHXVVDWVMVVVNOVRTAMEGZRGKHRTEVXZRJLRMWIEWVSITCMFBZMK\n" +
                            "AIHAHALZNBQBKLTIENIAMSCDYNSHENVVWNXEHUKVRCIFBAEKIIKGALREOGSA\n" +
                            "ZLVJIMWNBKMFRHEQTTXIUGCLHBVWOMKVOLRVSNMVFWPFRZFHMALVFVGGBZMN\n" +
                            "ANRNIWMEGVRQLVKVNOPLRVYTAHIETWTZNBEAWZSWADRGEFCFUXEZXAEGPDRT\n" +
                            "MHTGIIKNMTCTHVQOXYHFOMXUTAMJCVVPXDEJSPVRBOIRRYCBNOIIEDSCXUIU\n" +
                            "WDHRMOIUOJVQTYOEENWGALVVAIHAHALZNBQBKLHVEKMAMVXYEYEEDUIJSKIR\n" +
                            "KPRXLJRTBZXFOYXUXYINOIHRKPRXFZEEBUKUOPFGBUKURZEZBUKURZEZLUSD\n" +
                            "OMXNEZIMEMHNKLHKOYVRTTFVFJVRUBXKHZWVELRTEREFNUFIOFIATUHKHZWG\n" +
                            "BSPEENWTTCIEOOSXXUEEDOLRHUPPWJVQMOIIENTBDLRNANXUXDLZSKIEXKAF\n" +
                            "RYPRGVVVTCMFBDLZSKIEXKEEDVRRVOSDUMQHKLHSAXOGALAFRYPRGVVVMZVR\n" +
                            "EFXYINEAWUSKHDRTFVVVBVGXBUXFTCIPAHQSEMXHKUMEGVPYFFWFUGAVMOME\n" +
                            "MZFHKUMEGNSBGHKRIIMUXHVUAOECIPRXSJQRMOMEGGSHWLVKHVROXMSIENYE\n" +
                            "XSCJADHVLBVVLTXUTAMJSJQRMOMEGVXZRDMEDJAYTAXZCZPRMTIJEZXUXUAY\n" +
                            "AOXUXYIRTDWNGKXYINQLLAIIYZBCEVVVLZXZROIRROFRLAMCLVQBFLRKAIHG\n" +
                            "APWDYNXRKFIOPGSEXAMJTCIJBUHRNYRBMOMEGHSEXVTVNCIEXPJCUIKGALWY\n" +
                            "UOXRKDLVNRMGATEEYVJYBYXRNYJYNAXVRDRGALVVSOICILHRSOEGXSCIAQIA\n" +
                            "HMXYENEVGAPPDVCFHMCFRZRBMALVLZEFMVFVINEAVLQRDZLRGVXRMDRHMLWK\n" +
                            "OKTRWVVJTVCRWOISUOAVMOQZEISSEVVUOMPNWFTVRXLRWHFFVZQLVOEDBZVQ\n" +
                            "HVVGEMGUXKYGOIEONZXFFKEYEHWAUNXNUVZVMTGUTTFVRYSBKWIICCIQTUHJ\n" +
                            "AOEAWUSKHDRTFVVVTCIAMOMJEWSARIMIDWITNPPZNBQLLHHWAIGLBUXFSHMY\n" +
                            "BUKSYOLRZYEMEVRQLAIINYIPHYYDOAXUXJSLNOIATUGVIOABKLXYOPKUMOCT\n" +
                            "RZWGULWYOMRNGKWYAQIAMOSLINEVWHVKSPVRGVGIAQIAZOEJTGCTKPQRNYEA\n" +
                            "VPIETMEIXUARNYIEBUKWRJQGALRZGCXYRZLFRZXRESQVWCEGMOICOMHYRUED\n" +
                            "EDWBGALVNDKUMZTCUOSABHRJHJVRJBSKHOLRKHZVNIIIXYQFRZQHVOMDAMZR\n" +
                            "ESIUTCMFNUKRIIPLYVACTJLRTYHZSXSHKZIJOKPNBUPPTCSHZOMKSVRFPLVC\n" +
                            "IOXYXTIRNDRTEPXKLZVRELZRNXCOHYIWOMARVHREOOLREWEXRZIVGNXYAORB\n" +
                            "EPZZNBLHFHRSEDRTXCIIYZXJTZFCENWRWDMKHNIRBUKSIMHNUVZVHDWPAHQS\n" +
                            "EMHBHYFZRYSEULEJTPTBGALVSXYYIAYIEYFHLAESOQIUBZGYAHFRKKSFRRMG\n" +
                            "AZYTHIEZXHWEEQIEFVVVBPXGALVRVZRFBAXZNBPBGLPPOIXUTATCAXMQUBWK\n" +
                            "SKSXXVRCYOLNMVRVWJVQTZMWHDWFHBPZNOLNMVRVWJVQALHZDJYGIVYINJXU\n" +
                            "BUKWUMXUXYXYEILRNAXVRZHAHAEWEVXUXYXYEILRYSYKTZVRWAMCLDWPTYGV\n" +
                            "LTQBKLXYAIQHMAIIEYSGALVWRDIAWZLRVZJYHDRSEASEXVRKHZQBKYSNHZAV\n" +
                            "ESPVAQIZXHWDYCSCXZLRVZJYHDRSEASEXALVNOLRUPVUSVMQGLZVRHSEXZXR\n" +
                            "ROPRWHXKHZWGBSPEENWOKVOVNWCEXWPPSJECMSCJPJORGKSLBOPRLZWRIYMJ\n" +
                            "AHXZTPXGXYWZSDXFHUPPSOSPDHRUSOSEXJELGCXSKVQJOHIHGOEGPTQNLAII\n" +
                            "WCSZNUQVRXMSNSHZSVWGXYJFLGSJXKJRSOEAWMSCLJARWMEJTZVGBSPYINWB\n" +
                            "GNWFNZFHKKIEBJVRMPPCTCIQBYKVSJJUBZLFPZXUTAQVLVRPAVPPBPVQXUFF\n" +
                            "RZSSGLZVRIIIXYQFRZFHMALVRVZRGZXZLGFRZBMCIIKNESQPFVRPRPRKONQV\n" +
                            "EPRXSOVNBNLKIRLRXSIUAXYFAPSEEYWRTAMEFMSAMVJSIMHNGKFLSOEAWKSF\n" +
                            "ROLRGBTFNOLROLPMEOWVGRMEGDFRMVSBMTWREMXFLDRXBUKWAIGLNUXFFVRP\n" +
                            "RALZNFMAZDLRTOLVLVQZNJYFUPVUOACBKLAYAOXUBZKIIHYAZHMELTKUTZXC\n" +
                            "YBEHGAEEDJQVGVYJBDVQHMCFRZQRTUXZNXVBTRMEGIIIXYQFRZXUNZMJAOIA\n" +
                            "ZHKVDDRTNLWJIIKONARFSTPYTIPVESTEXZWZNBXBMOIWORPJAVWVFDIERLCV\n" +
                            "SISJUBVEEYMAMVQPBJWBFZGFRZXUBZEEDHSEXPWRTYMIBUMEGRMGATCYEVHN\n" +
                            "MLEJEMIPEPRZNBSAMOITUNLVHUWMEGZRMSMEIIKGAHXKHZPNFWPZGCXTEVEK\n" +
                            "EYSRKIYKWCSFXCICVZXIBVPVTGMABUKNIOLGALPRMKPVZOXXLJEGBUKFEMWU\n" +
                            "XZLRLGTEXZWRHIIIXYQFRZXUXUQVTCSHZOXKHZEVKNVVWYIALLVGEMJHFLHW\n" +
                            "RJQNGBRJEZRPXUWVRNAHGNFPSZVNIOMDWCSFXMSFTAEYEZXZNFPRWVRKHZXH\n" +
                            "YAIUFGSBKDVVTXLVVYMVDOLLZVHYAOLYXUXKHZIORALVSZEAZLPJHZLNMOWV\n" +
                            "NOXUXLVVSKMGXYIJPDXRTUHEEKIAMOIWRJQGAFQVMJVVXZSWLZRBKLULAAJB\n" +
                            "JBEWFOLVLRMEDIICXUXYEVRQYVVXEOXUBZPFSOPRGVVVQPSGAALVRVZRGUIM\n" +
                            "EMQBKLTIOKLRMZEZDDXUBUKFFZZVEWVFPCIGLAMCLDJOBYHFRYIIBSAYEOLR\n" +
                            "KAIDPOIELLRKOMAUXALVROIZILWKTJWFXKXYEZLRKLEJHJVRWLWFLVXRRLXR\n" +
                            "LGYAWHYETZHBGALZSYIFXYXCAIHRGJLRNOIQHUXYINLBFLFPHJVEHYLRUIXR\n" +
                            "WAICLHIGKBPPIDQCEVVVINXUXYIZSOLRKLFRLHMAZPPVAYXRESQVTZPYFLMZ\n" +
                            "MKPBKLULOOLGALVRVZRAXCIIMJVRIYSGHZXFTPHZTCMAZVJVVDPCKVTYEOWG\n" +
                            "BSPZFWMEWVVUEQMYUFXYAOLRTCIETCEGULRUSVFBOLYJBTXUTAKFDRIOHALR\n" +
                            "DJVRMLPCTCMFLVYCWDXULVVIORPNWLRZFRMGAPRKHZHVLAEETVMQXURZTNLN\n" +
                            "ESGCANTNLHMETZHZTPHVNRLBFALVAIKREZRRMZPRGVVVCGEFIHVRRZEAWYEU\n" +
                            "IVRGFHMUEIAUHTXYEVRTXSWEAHIYXUSIELYBMOXYEMEIXURVVZVZHYISEOLN\n" +
                            "MDSIDJYELPKEOATNKAMEGWMEWVVWIZRQBZLIIZORWBTJTVVGBUKXEOXUXLFR\n" +
                            "CFMAMVXYEOIZILWKAIHGALRZGCXFISYKOIMNGZLFRZPRTCIEOWPNVRTCUHIN\n" +
                            "LHXFKZRBYALRTGMRMOCJOPPUTALJPJORGSIRVZQLEVRVLDRRLZYEBMSXXUUL\n" +
                            "IOXUXIYJTVFBOLQPDJSEMHOVTCCOXHOWRJQBNAQPHZEEMHRUTVORMOCWOMQS\n" +
                            "KVQFFAQLWVSIQPSGAALVRVZRGUIMEMQBKLEEDOLRKHZVNIIIXYJCIOXVGNWK\n" +
                            "IGPVLZMKTDRTLAMCLDWFBAXZNBSAMOIGAGPVWIYJTJJCTSPRSEYFMHFFVZQL\n" +
                            "VOEDBZVQHVVRNYLVLLCVSCEIXHPCTCIFXLQZNBSSTKIDOIWGAHXZSYVRTTME\n" +
                            "GVRQMOICAHTYBNLKOZVUBTWKRZEZBUKKHMSJLALVSCEQHDSETCISEVSIAIHZ\n" +
                            "RZSLLAVBFVYKTCEGLOEUORXUTAPZENJYHHXZNBSAMOIWLJSELOECLWIYBMXV\n" +
                            "DIIIXYQFRZ";
        
        System.out.println("Encryption : \n"+ciphertext);
        System.out.println("The String is : \n"+vigenere.decryptCipherText(ciphertext));
    
    }
}
